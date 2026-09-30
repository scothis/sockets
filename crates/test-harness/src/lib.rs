//! Test harness for the gate, latch and trace components.
//!
//! A [`Harness`] instantiates a component (`target/components/*/*.wasm`) with real
//! upstream sockets from wasmtime-wasi, a scripted [`HostLatch`], and captured
//! `wasi:logging` output. Latch components from `target/components/` can be installed in
//! place of, or alongside, the host latch, they are composed into the component
//! before it is instantiated. Values for `wasi:config/store` are shared by every
//! component in the composition.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use wac_graph::{
    CompositionGraph, EncodeOptions,
    types::{Package, Types},
};
use wasmtime::component::{
    Accessor, Component, FutureConsumer, FutureReader, HasSelf, Lift, Linker, Lower, ResourceTable,
    Source, StreamConsumer, StreamReader, StreamResult,
};
use wasmtime::error::Context as _;
use wasmtime::{Config, Engine, Result, Store, StoreContextMut, bail, format_err};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::bindings::componentized::sockets::latch::{
    self, Decision, ErrorCode as LatchErrorCode, Operation, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};
use crate::bindings::exports::wasi::sockets::{ip_name_lookup, types};
use crate::bindings::wasi::config::store;
use crate::bindings::wasi::logging::logging;

pub mod bindings {
    wasmtime::component::bindgen!({
        path: "../../components/wit",
        inline: "
            package componentized:test-harness;

            world harness {
                import componentized:sockets/latch@0.1.0-dev;
                import wasi:config/store@0.2.0-rc.1;
                import wasi:logging/logging@0.1.0-draft;
                export wasi:sockets/types@0.3.0;
                export wasi:sockets/ip-name-lookup@0.3.0;
            }
        ",
        world: "componentized:test-harness/harness",
        exports: { default: async | store },
        with: {
            "wasi:sockets": wasmtime_wasi::p3::bindings::sockets,
            "wasi:clocks": wasmtime_wasi::p3::bindings::clocks,
        },
    });
}

pub use bindings::exports::wasi::sockets::types::{
    ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress,
};
pub use bindings::wasi::logging::logging::Level;

/// `127.0.0.1:{port}`
pub fn loopback(port: u16) -> IpSocketAddress {
    IpSocketAddress::Ipv4(Ipv4SocketAddress {
        port,
        address: (127, 0, 0, 1),
    })
}

/// Convert a wasi socket address to a std socket address.
pub fn socket_addr(address: IpSocketAddress) -> SocketAddr {
    match address {
        IpSocketAddress::Ipv4(ipv4) => {
            let (a, b, c, d) = ipv4.address;
            SocketAddr::from((Ipv4Addr::new(a, b, c, d), ipv4.port))
        }
        IpSocketAddress::Ipv6(ipv6) => {
            let (a, b, c, d, e, f, g, h) = ipv6.address;
            SocketAddr::from((Ipv6Addr::new(a, b, c, d, e, f, g, h), ipv6.port))
        }
    }
}

/// Convert a std socket address to a wasi socket address.
pub fn ip_socket_address(address: SocketAddr) -> IpSocketAddress {
    use bindings::exports::wasi::sockets::types::Ipv6SocketAddress;
    match address {
        SocketAddr::V4(v4) => {
            let [a, b, c, d] = v4.ip().octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: v4.port(),
                address: (a, b, c, d),
            })
        }
        SocketAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.ip().segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: v6.port(),
                address: (a, b, c, d, e, f, g, h),
                flow_info: v6.flowinfo(),
                scope_id: v6.scope_id(),
            })
        }
    }
}

/// Receive the items written to a guest stream on a channel.
pub fn collect<T: Lift + Send + Sync + 'static>(
    accessor: &Accessor<Ctx>,
    stream: StreamReader<T>,
) -> Result<mpsc::UnboundedReceiver<T>> {
    let (tx, rx) = mpsc::unbounded_channel();
    accessor.with(|store| stream.pipe(store, ChannelConsumer(tx)))?;
    Ok(rx)
}

/// Create a stream for the guest that yields the items, then closes.
pub fn stream<T: Lower + Lift + Unpin + Send + Sync + 'static>(
    accessor: &Accessor<Ctx>,
    items: Vec<T>,
) -> Result<StreamReader<T>> {
    accessor.with(|store| StreamReader::new(store, items))
}

/// Wait for the value of a guest future.
///
/// Only for futures the guest writes itself. A future the guest passes through from a wasmtime-wasi
/// host import is transferred host to host, which requires the same Rust type on both ends, and
/// the harness' exported types are generated separately from wasmtime-wasi's.
pub async fn resolve<T: Lift + Send + Sync + 'static>(
    accessor: &Accessor<Ctx>,
    future: FutureReader<T>,
) -> Result<T> {
    let (tx, rx) = oneshot::channel();
    accessor.with(|store| future.pipe(store, OneshotConsumer(Some(tx))))?;
    rx.await
        .map_err(|_| format_err!("future closed without a value"))
}

struct OneshotConsumer<T>(Option<oneshot::Sender<T>>);

impl<D, T: Lift + Send + Sync + 'static> FutureConsumer<D> for OneshotConsumer<T> {
    type Item = T;

    fn poll_consume(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        store: StoreContextMut<D>,
        mut source: Source<'_, T>,
        _finish: bool,
    ) -> Poll<Result<()>> {
        let mut item = None;
        source.read(store, &mut item)?;
        if let (Some(item), Some(tx)) = (item, self.get_mut().0.take()) {
            // the receiver is only dropped when the test stopped waiting
            let _ = tx.send(item);
        }
        Poll::Ready(Ok(()))
    }
}

struct ChannelConsumer<T>(mpsc::UnboundedSender<T>);

impl<D, T: Lift + Send + Sync + 'static> StreamConsumer<D> for ChannelConsumer<T> {
    type Item = T;

    fn poll_consume(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        store: StoreContextMut<D>,
        mut source: Source<'_, T>,
        _finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let mut item = None;
        source.read(store, &mut item)?;
        if let Some(item) = item {
            if self.0.send(item).is_err() {
                return Poll::Ready(Ok(StreamResult::Dropped));
            }
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

/// Root of the workspace, where the Makefile lives.
fn workspace_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Path containing the built component.
pub fn component_path(name: &str) -> PathBuf {
    workspace_dir().join(format!("target/components/{name}/{name}.wasm"))
}

/// Rebuild the named components in `target/components/` with make, unless they were already built by this
/// process.
fn ensure_built(names: &[&str]) -> Result<()> {
    static BUILT: Mutex<Option<HashSet<String>>> = Mutex::new(None);

    // hold the lock while building so concurrent tests don't run make over each other
    let mut built = BUILT.lock().unwrap_or_else(|err| err.into_inner());
    let built = built.get_or_insert_with(HashSet::new);
    let targets: Vec<String> = names
        .iter()
        .filter(|name| !built.contains(**name))
        .map(|name| format!("target/components/{name}/{name}.wasm"))
        .collect();
    if targets.is_empty() {
        return Ok(());
    }

    let output = Command::new("make")
        .arg("-C")
        .arg(workspace_dir())
        .args(&targets)
        .output()
        .context("failed to run make")?;
    if !output.status.success() {
        bail!(
            "failed to build {}:\n{}{}",
            targets.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    built.extend(names.iter().map(|name| name.to_string()));
    Ok(())
}

/// An operation the host latch was asked to authorize.
///
/// Resource handles are not retained, only the operation name and a debug
/// rendering of its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Operation name, e.g. `tcp-socket.bind`
    pub operation: String,
    /// Debug rendering of the operation arguments, excluding resources
    pub args: String,
}

/// A message logged by the test subject via `wasi:logging`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub level: Level,
    pub context: String,
    pub message: String,
}

impl LogEntry {
    /// A trace message logged by the test subject.
    pub fn trace(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::log(Level::Trace, context, message)
    }

    /// A warning message logged by the test subject.
    pub fn warn(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::log(Level::Warn, context, message)
    }

    /// An error message logged by the test subject.
    pub fn error(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::log(Level::Error, context, message)
    }

    /// A critical message logged by the test subject.
    pub fn critical(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::log(Level::Critical, context, message)
    }

    fn log(level: Level, context: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level,
            context: context.into(),
            message: message.into(),
        }
    }
}

type Policy = dyn FnMut(&Authorization) -> Result<Decision, LatchErrorCode> + Send;

/// Scripted latch implemented by the host.
///
/// It is the test subject's latch unless latch components are installed, see
/// [`Harness::latch`].
pub struct HostLatch {
    policy: Box<Policy>,
    fail_observe: bool,
}

impl HostLatch {
    /// Defer every operation.
    pub fn defer() -> Self {
        Self::new(|_| Ok(Decision::Deferred))
    }

    /// Deny the named operations with `access-denied`, defer the rest.
    pub fn deny(operations: &[&str]) -> Self {
        let operations: Vec<String> = operations.iter().map(|s| s.to_string()).collect();
        Self::new(move |auth| {
            if operations.contains(&auth.operation) {
                Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
            } else {
                Ok(Decision::Deferred)
            }
        })
    }

    /// Fail every authorization with a latch error.
    pub fn error(message: &str) -> Self {
        let message = message.to_string();
        Self::new(move |_| Err(LatchErrorCode::Other(Some(message.clone()))))
    }

    /// Fail every authorization with an invalid config error from the named latch.
    pub fn invalid_config(latch: &str) -> Self {
        let latch = latch.to_string();
        Self::new(move |_| Err(LatchErrorCode::InvalidConfig(latch.clone())))
    }

    /// Decide each operation with a custom policy.
    pub fn new(
        policy: impl FnMut(&Authorization) -> Result<Decision, LatchErrorCode> + Send + 'static,
    ) -> Self {
        Self {
            policy: Box::new(policy),
            fail_observe: false,
        }
    }

    /// Fail every `observe-decision` call.
    pub fn fail_observe(mut self) -> Self {
        self.fail_observe = true;
        self
    }
}

/// A decision the host latch was told about with `observe-decision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// Operation name, e.g. `tcp-socket.bind`
    pub operation: String,
    /// Whether the final decision denied the operation
    pub denied: bool,
}

/// Observations recorded while the test subject runs.
#[derive(Clone, Default)]
pub struct Recorder {
    authorizations: Arc<Mutex<Vec<Authorization>>>,
    observations: Arc<Mutex<Vec<Observation>>>,
    logs: Arc<Mutex<Vec<LogEntry>>>,
}

impl Recorder {
    /// Operations the host latch was asked to authorize, in order.
    pub fn authorizations(&self) -> Vec<Authorization> {
        self.authorizations.lock().unwrap().clone()
    }

    /// Names of the operations the host latch was asked to authorize, in order.
    pub fn operations(&self) -> Vec<String> {
        self.authorizations()
            .into_iter()
            .map(|a| a.operation)
            .collect()
    }

    /// Decisions the host latch observed, in order.
    pub fn observations(&self) -> Vec<Observation> {
        self.observations.lock().unwrap().clone()
    }

    /// Messages logged by the test subject, in order.
    pub fn logs(&self) -> Vec<LogEntry> {
        self.logs.lock().unwrap().clone()
    }
}

pub struct Ctx {
    wasi: WasiCtx,
    table: ResourceTable,
    latch: HostLatch,
    config: Vec<(String, String)>,
    recorder: Recorder,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl latch::Host for Ctx {
    fn authorize(&mut self, operation: Operation) -> Result<Decision, LatchErrorCode> {
        let authorization = describe(&operation);
        self.recorder
            .authorizations
            .lock()
            .unwrap()
            .push(authorization.clone());
        (self.latch.policy)(&authorization)
    }

    fn observe_decision(
        &mut self,
        decision: Decision,
        operation: Operation,
    ) -> Result<(), LatchErrorCode> {
        self.recorder
            .observations
            .lock()
            .unwrap()
            .push(Observation {
                operation: describe(&operation).operation,
                denied: matches!(decision, Decision::Denied(_)),
            });
        match self.latch.fail_observe {
            true => Err(LatchErrorCode::ObservationFailed("host".to_string())),
            false => Ok(()),
        }
    }
}

/// Define the host latch under a named import, e.g. `latch1` of a `latch-n` component.
fn add_named_latch_to_linker(linker: &mut Linker<Ctx>, name: &str) -> Result<()> {
    let mut instance = linker.instance(name)?;
    instance.func_wrap(
        "authorize",
        |mut store: StoreContextMut<'_, Ctx>, (operation,): (Operation,)| {
            Ok((latch::Host::authorize(store.data_mut(), operation),))
        },
    )?;
    instance.func_wrap(
        "observe-decision",
        |mut store: StoreContextMut<'_, Ctx>, (decision, operation): (Decision, Operation)| {
            Ok((latch::Host::observe_decision(
                store.data_mut(),
                decision,
                operation,
            ),))
        },
    )?;
    Ok(())
}

impl store::Host for Ctx {
    fn get(&mut self, key: String) -> Result<Option<String>, store::Error> {
        Ok(self
            .config
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone()))
    }

    fn get_all(&mut self) -> Result<Vec<(String, String)>, store::Error> {
        Ok(self.config.clone())
    }
}

impl logging::Host for Ctx {
    fn log(&mut self, level: Level, context: String, message: String) {
        self.recorder.logs.lock().unwrap().push(LogEntry {
            level,
            context,
            message,
        });
    }
}

fn describe(operation: &Operation) -> Authorization {
    let (operation, args) = match operation {
        Operation::IpNameLookup(op) => match op {
            latch::IpNameLookupOperation::ResolveAddresses(args) => {
                ("ip-name-lookup.resolve-addresses", format!("{args:?}"))
            }
            latch::IpNameLookupOperation::ResolveAddressesReturn(args) => (
                "ip-name-lookup.resolve-addresses.return",
                format!("{args:?}"),
            ),
        },
        Operation::TcpSocket(op) => match op {
            TcpSocketOperation::Create(args) => ("tcp-socket.create", format!("{args:?}")),
            TcpSocketOperation::Bind((_, args)) => ("tcp-socket.bind", format!("{args:?}")),
            TcpSocketOperation::Connect((_, args)) => ("tcp-socket.connect", format!("{args:?}")),
            TcpSocketOperation::Listen(_) => ("tcp-socket.listen", String::new()),
            TcpSocketOperation::ListenConnection(_) => {
                ("tcp-socket.listen.connection", String::new())
            }
            TcpSocketOperation::Send(_) => ("tcp-socket.send", String::new()),
            TcpSocketOperation::Receive(_) => ("tcp-socket.receive", String::new()),
        },
        Operation::UdpSocket(op) => match op {
            UdpSocketOperation::Create(args) => ("udp-socket.create", format!("{args:?}")),
            UdpSocketOperation::Bind((_, args)) => ("udp-socket.bind", format!("{args:?}")),
            UdpSocketOperation::Connect((_, args)) => ("udp-socket.connect", format!("{args:?}")),
            UdpSocketOperation::Send((_, args)) => ("udp-socket.send", format!("{args:?}")),
            UdpSocketOperation::Receive((_, args)) => ("udp-socket.receive", format!("{args:?}")),
        },
    };
    Authorization {
        operation: operation.to_string(),
        args,
    }
}

/// Builds a subject instance for a test.
pub struct Harness {
    subject: String,
    latches: Vec<String>,
    host_latch: Option<HostLatch>,
    config: Vec<(String, String)>,
}

impl Harness {
    /// Test the named component from `target/components/`, e.g. `gate`.
    pub fn new(component_name: &str) -> Self {
        Self {
            subject: component_name.to_string(),
            latches: vec![],
            host_latch: None,
            config: vec![],
        }
    }

    /// Install a latch component from `target/components/`.
    ///
    /// Without latch components the host latch is the test subject's latch. A single latch
    /// component replaces it, unless the latch imports a latch, then it wraps the host latch.
    /// Otherwise several latches, including the host latch when one is set with
    /// [`Harness::host_latch`], are aggregated with the `latch-n` component of the same size,
    /// in the order installed with the host latch last.
    pub fn latch(mut self, name: &str) -> Self {
        self.latches.push(name.to_string());
        self
    }

    /// Replace the default deferring host latch, it is aggregated with any latch components.
    pub fn host_latch(mut self, latch: HostLatch) -> Self {
        self.host_latch = Some(latch);
        self
    }

    /// Add a `wasi:config/store` value, visible to every component in the composition.
    ///
    /// Values are returned by `get-all` in the order they are added.
    pub fn config(mut self, key: &str, value: &str) -> Self {
        self.config.push((key.to_string(), value.to_string()));
        self
    }

    /// Compose and instantiate the test subject.
    pub async fn build(self) -> Result<TestSubject> {
        let mut config = Config::new();
        config.wasm_component_model_async(true);
        config.wasm_component_model_threading(true);
        config.wasm_component_model_implements(true);
        let engine = Engine::new(&config)?;

        let bytes = self.compose()?;
        let component = Component::new(&engine, &bytes)?;

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p3::add_to_linker(&mut linker)?;
        latch::add_to_linker::<_, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;
        for slot in 0..LATCH_N_MAX {
            add_named_latch_to_linker(&mut linker, &format!("latch{slot}"))?;
        }
        store::add_to_linker::<_, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;
        logging::add_to_linker::<_, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;

        let recorder = Recorder::default();
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            .inherit_network()
            .allow_tcp(true)
            .allow_udp(true)
            .allow_ip_name_lookup(true)
            .build();
        let mut store = Store::new(
            &engine,
            Ctx {
                wasi,
                table: ResourceTable::new(),
                latch: self.host_latch.unwrap_or_else(HostLatch::defer),
                config: self.config,
                recorder: recorder.clone(),
            },
        );
        let instance_pre = linker.instantiate_pre(&component)?;
        let instance = instance_pre
            .instantiate_async(&mut store)
            .await
            .with_context(|| format!("failed to instantiate {}", self.subject))?;
        let exports = Exports {
            name: self.subject,
            types: match types::GuestIndices::new(&instance_pre) {
                Ok(indices) => Some(indices.load(&mut store, &instance)?),
                Err(_) => None,
            },
            ip_name_lookup: match ip_name_lookup::GuestIndices::new(&instance_pre) {
                Ok(indices) => Some(indices.load(&mut store, &instance)?),
                Err(_) => None,
            },
        };

        Ok(TestSubject {
            store,
            exports,
            recorder,
        })
    }

    fn compose(&self) -> Result<Vec<u8>> {
        let mut names = vec![self.subject.as_str()];
        names.extend(self.latches.iter().map(String::as_str));
        ensure_built(&names)?;

        let read = |name: &str| {
            let path = component_path(name);
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))
        };

        let bytes = read(&self.subject)?;
        let latch = match self.latches.as_slice() {
            [] => return Ok(bytes),
            // a latch that wraps another latch wraps the host latch, its import is left for the host
            [latch] if self.host_latch.is_none() || imports_latch(&read(latch)?)? => read(latch)?,
            latches => {
                // the host latch takes the last slot of latch-n, left unsatisfied it is imported
                let slots = latches.len() + usize::from(self.host_latch.is_some());
                if slots > LATCH_N_MAX {
                    bail!("at most {LATCH_N_MAX} latches can be aggregated, got {slots}");
                }
                let latch_n = format!("latch-n{slots}");
                ensure_built(&[&latch_n])?;
                let latches = latches
                    .iter()
                    .map(|name| read(name))
                    .collect::<Result<Vec<_>>>()?;
                aggregate(read(&latch_n)?, latches)?
            }
        };
        plug(&self.subject, bytes, latch)
    }
}

/// The most latches a `latch-n` component aggregates.
const LATCH_N_MAX: usize = 5;

const LATCH_INTERFACE: &str = "componentized:sockets/latch@0.1.0-dev";

/// Whether the latch component imports a latch, which it wraps.
fn imports_latch(latch: &[u8]) -> Result<bool> {
    let mut types = Types::default();
    let package = Package::from_bytes("test:latch", None, latch.to_vec(), &mut types)
        .map_err(|err| format_err!("{err:#}"))?;
    Ok(types[package.ty()].imports.contains_key(LATCH_INTERFACE))
}

/// Satisfy the leading `latch{i}` imports of a `latch-n` component with the latches, any
/// remaining slot is left for the host.
fn aggregate(latch_n: Vec<u8>, latches: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    let mut graph = CompositionGraph::new();
    let latch_n = Package::from_bytes("test:latch-n", None, latch_n, graph.types_mut())
        .map_err(|err| format_err!("{err:#}"))?;
    let latch_n = graph.register_package(latch_n)?;
    let latch_n = graph.instantiate(latch_n);
    for (slot, latch) in latches.into_iter().enumerate() {
        let latch =
            Package::from_bytes(&format!("test:latch{slot}"), None, latch, graph.types_mut())
                .map_err(|err| format_err!("{err:#}"))?;
        let latch = graph.register_package(latch)?;
        let latch = graph.instantiate(latch);
        let export = graph.alias_instance_export(latch, LATCH_INTERFACE)?;
        graph.set_instantiation_argument(latch_n, &format!("latch{slot}"), export)?;
    }
    let export = graph.alias_instance_export(latch_n, LATCH_INTERFACE)?;
    graph.export(export, LATCH_INTERFACE)?;
    Ok(graph.encode(EncodeOptions::default())?)
}

/// Satisfy the socket's imports with the plug's exports.
fn plug(name: &str, socket: Vec<u8>, plug: Vec<u8>) -> Result<Vec<u8>> {
    let mut graph = CompositionGraph::new();
    let socket = Package::from_bytes("test:socket", None, socket, graph.types_mut())
        .map_err(|err| format_err!("{err:#}"))?;
    let socket = graph.register_package(socket)?;
    let plug = Package::from_bytes("test:plug", None, plug, graph.types_mut())
        .map_err(|err| format_err!("{err:#}"))?;
    let plug = graph.register_package(plug)?;
    if let Err(err) = wac_graph::plug(&mut graph, vec![plug], socket) {
        bail!("failed to plug latch into {name}: {err}");
    }
    Ok(graph.encode(EncodeOptions::default())?)
}

/// The test subject's exported interfaces.
///
/// A test subject component may export either or both interfaces, accessing an interface the component
/// does not export panics.
pub struct Exports {
    name: String,
    types: Option<types::Guest>,
    ip_name_lookup: Option<ip_name_lookup::Guest>,
}

impl Exports {
    /// The exported `wasi:sockets/types` interface.
    pub fn wasi_sockets_types(&self) -> &types::Guest {
        self.types
            .as_ref()
            .unwrap_or_else(|| panic!("{} does not export wasi:sockets/types", self.name))
    }

    /// The exported `wasi:sockets/ip-name-lookup` interface.
    pub fn wasi_sockets_ip_name_lookup(&self) -> &ip_name_lookup::Guest {
        self.ip_name_lookup
            .as_ref()
            .unwrap_or_else(|| panic!("{} does not export wasi:sockets/ip-name-lookup", self.name))
    }
}

/// An instantiated test subject.
pub struct TestSubject {
    store: Store<Ctx>,
    exports: Exports,
    recorder: Recorder,
}

impl TestSubject {
    /// Observations recorded by the host latch and logger.
    pub fn recorder(&self) -> Recorder {
        self.recorder.clone()
    }

    /// Run a test body against the test subject's exports.
    pub async fn run<R: Send + 'static>(
        &mut self,
        f: impl AsyncFnOnce(&Accessor<Ctx>, &Exports) -> Result<R> + Send,
    ) -> Result<R> {
        let exports = &self.exports;
        self.store
            .run_concurrent(async move |accessor| f(accessor, exports).await)
            .await?
    }
}
