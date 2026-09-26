//! Test harness for the gate components.
//!
//! A [`Harness`] instantiates a gate component (`lib/*.wasm`) with real
//! upstream sockets from wasmtime-wasi, a scripted [`HostLatch`], and captured
//! `wasi:logging` output. Latch components from `lib/` can be installed in
//! front of the host latch, they are composed into the gate before it is
//! instantiated.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use tokio::sync::mpsc;
use wac_graph::{types::Package, CompositionGraph, EncodeOptions};
use wasmtime::component::{
    Accessor, Component, HasSelf, Lift, Linker, ResourceTable, Source, StreamConsumer,
    StreamReader, StreamResult,
};
use wasmtime::error::Context as _;
use wasmtime::{bail, format_err, Config, Engine, Result, Store, StoreContextMut};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::bindings::componentized::sockets::latch::{
    self, Decision, ErrorCode as LatchErrorCode, Operation, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};
use crate::bindings::wasi::logging::logging;

pub mod bindings {
    wasmtime::component::bindgen!({
        path: "../../components/wit",
        inline: "
            package componentized:gate-tests;

            world gate {
                import componentized:sockets/latch@0.0.0-dev;
                import wasi:logging/logging@0.1.0-draft;
                export wasi:sockets/types@0.3.0;
                export wasi:sockets/ip-name-lookup@0.3.0;
            }
        ",
        world: "componentized:gate-tests/gate",
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

/// Directory containing the built components.
pub fn lib_dir() -> PathBuf {
    workspace_dir().join("lib")
}

/// Rebuild the named components in `lib/` with make, unless they were already built by this
/// process.
fn ensure_built(names: &[&str]) -> Result<()> {
    static BUILT: Mutex<Option<HashSet<String>>> = Mutex::new(None);

    // hold the lock while building so concurrent tests don't run make over each other
    let mut built = BUILT.lock().unwrap_or_else(|err| err.into_inner());
    let built = built.get_or_insert_with(HashSet::new);
    let targets: Vec<String> = names
        .iter()
        .filter(|name| !built.contains(**name))
        .map(|name| format!("lib/{name}.wasm"))
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

/// A message logged by the gate via `wasi:logging`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub level: Level,
    pub context: String,
    pub message: String,
}

impl LogEntry {
    /// A trace logged by the gate.
    pub fn trace(message: impl Into<String>) -> Self {
        Self::gate(Level::Trace, message)
    }

    /// A warning logged by the gate.
    pub fn warn(message: impl Into<String>) -> Self {
        Self::gate(Level::Warn, message)
    }

    /// An error logged by the gate.
    pub fn error(message: impl Into<String>) -> Self {
        Self::gate(Level::Error, message)
    }

    fn gate(level: Level, message: impl Into<String>) -> Self {
        Self {
            level,
            context: "componentized-gate".to_string(),
            message: message.into(),
        }
    }
}

type Policy = dyn FnMut(&Authorization) -> Result<Decision, LatchErrorCode> + Send;

/// Scripted latch implemented by the host.
///
/// It is the terminal latch, installed latch components that delegate to
/// their upstream latch will reach it.
pub struct HostLatch {
    policy: Box<Policy>,
}

impl HostLatch {
    /// Abstain from every operation.
    pub fn abstain() -> Self {
        Self::new(|_| Ok(Decision::Abstained))
    }

    /// Deny the named operations with `access-denied`, abstain from the rest.
    pub fn deny(operations: &[&str]) -> Self {
        let operations: Vec<String> = operations.iter().map(|s| s.to_string()).collect();
        Self::new(move |auth| {
            if operations.contains(&auth.operation) {
                Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
            } else {
                Ok(Decision::Abstained)
            }
        })
    }

    /// Fail every authorization with a latch error.
    pub fn error(message: &str) -> Self {
        let message = message.to_string();
        Self::new(move |_| Err(LatchErrorCode::Other(Some(message.clone()))))
    }

    /// Decide each operation with a custom policy.
    pub fn new(
        policy: impl FnMut(&Authorization) -> Result<Decision, LatchErrorCode> + Send + 'static,
    ) -> Self {
        Self {
            policy: Box::new(policy),
        }
    }
}

/// Observations recorded while the gate runs.
#[derive(Clone, Default)]
pub struct Recorder {
    authorizations: Arc<Mutex<Vec<Authorization>>>,
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

    /// Messages logged by the gate, in order.
    pub fn logs(&self) -> Vec<LogEntry> {
        self.logs.lock().unwrap().clone()
    }
}

pub struct Ctx {
    wasi: WasiCtx,
    table: ResourceTable,
    latch: HostLatch,
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

/// Builds a gate instance for a test.
pub struct Harness {
    gate: String,
    latches: Vec<String>,
    host_latch: HostLatch,
}

impl Harness {
    /// Test the named gate component from `lib/`, e.g. `gate`.
    pub fn new(gate: &str) -> Self {
        Self {
            gate: gate.to_string(),
            latches: vec![],
            host_latch: HostLatch::abstain(),
        }
    }

    /// Install a latch component from `lib/` in front of the host latch.
    ///
    /// Latches are chained in the order installed, the first latch is
    /// consulted by the gate directly. A latch that delegates to its upstream
    /// latch reaches the next installed latch, and finally the host latch.
    pub fn latch(mut self, name: &str) -> Self {
        self.latches.push(name.to_string());
        self
    }

    /// Replace the default abstaining host latch.
    pub fn host_latch(mut self, latch: HostLatch) -> Self {
        self.host_latch = latch;
        self
    }

    /// Compose and instantiate the gate.
    pub async fn build(self) -> Result<Gate> {
        let mut config = Config::new();
        config.wasm_component_model_async(true);
        config.wasm_component_model_threading(true);
        let engine = Engine::new(&config)?;

        let bytes = self.compose()?;
        let component = Component::new(&engine, &bytes)?;

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p3::add_to_linker(&mut linker)?;
        latch::add_to_linker::<_, HasSelf<Ctx>>(&mut linker, |ctx| ctx)?;
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
                latch: self.host_latch,
                recorder: recorder.clone(),
            },
        );
        let instance = bindings::Gate::instantiate_async(&mut store, &component, &linker)
            .await
            .with_context(|| format!("failed to instantiate {}", self.gate))?;

        Ok(Gate {
            store,
            instance,
            recorder,
        })
    }

    fn compose(&self) -> Result<Vec<u8>> {
        let mut names = vec![self.gate.as_str()];
        names.extend(self.latches.iter().map(String::as_str));
        ensure_built(&names)?;

        let read = |name: &str| {
            let path = lib_dir().join(format!("{name}.wasm"));
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))
        };

        let mut bytes = read(&self.gate)?;
        if self.latches.is_empty() {
            return Ok(bytes);
        }

        // plug the latches into each other from the host side outward, then into the gate
        let mut upstream: Option<Vec<u8>> = None;
        for name in self.latches.iter().rev() {
            let latch = read(name)?;
            upstream = Some(match upstream {
                Some(upstream) => plug(name, latch, upstream)?,
                None => latch,
            });
        }
        bytes = plug(&self.gate, bytes, upstream.unwrap())?;
        Ok(bytes)
    }
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

/// An instantiated gate.
pub struct Gate {
    store: Store<Ctx>,
    instance: bindings::Gate,
    recorder: Recorder,
}

impl Gate {
    /// Observations recorded by the host latch and logger.
    pub fn recorder(&self) -> Recorder {
        self.recorder.clone()
    }

    /// Run a test body against the gate's exports.
    pub async fn run<R: Send + 'static>(
        &mut self,
        f: impl AsyncFnOnce(&Accessor<Ctx>, &bindings::Gate) -> Result<R> + Send,
    ) -> Result<R> {
        let instance = &self.instance;
        self.store
            .run_concurrent(async move |accessor| f(accessor, instance).await)
            .await?
    }
}
