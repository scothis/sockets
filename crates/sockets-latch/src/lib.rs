//! Bindings and helpers for latch components, which implement the `sockets-latch` world.
//!
//! The bindings are generated once here and shared by every latch component. A latch implements
//! [`Latch`] and exports it with [`export!`]:
//!
//! ```ignore
//! struct MyLatch {}
//!
//! impl sockets_latch::Latch for MyLatch {
//!     // ...
//! }
//!
//! sockets_latch::export!(MyLatch with_types_in sockets_latch::bindings);
//! ```
//!
//! Imports a latch does not use, like `wasi:config/store` or the wrapped latch, are dropped from
//! the built component.

use core::cell::RefCell;
use core::fmt;
use core::ops::Deref;
use std::net::{IpAddr, SocketAddr};

use heck::ToKebabCase;

pub mod bindings {
    wit_bindgen::generate!({
        path: "../../components/wit",
        world: "latch",
        pub_export_macro: true,
        merge_structurally_equal_types: true,
        generate_all
    });
}

#[macro_export]
macro_rules! export {
    ($($t:tt)*) => {
        $crate::bindings::export!($($t)*);
    };
}

pub use bindings::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpNameLookupOperation, Operation, ResolveAddressesArgs,
    ResolveAddressesReturnsItem, SocketsErrorCode, TcpSocketBindArgs, TcpSocketConnectArgs,
    TcpSocketCreateArgs, TcpSocketOperation, UdpSocketBindArgs, UdpSocketConnectArgs,
    UdpSocketCreateArgs, UdpSocketOperation, UdpSocketReceiveReturns, UdpSocketSendArgs,
};
pub use bindings::wasi::sockets::types::{
    ErrorCode as WasiErrorCode, IpAddress, IpAddressFamily, IpSocketAddress,
};

/// The latch a wrapping latch delegates to, imported as `componentized:sockets/latch`.
pub mod wrapped {
    pub use crate::bindings::componentized::sockets::latch::{authorize, observe_decision};
}

/// Log a message from a latch with `wasi:logging`.
pub fn log(level: bindings::wasi::logging::logging::Level, message: &str) {
    bindings::wasi::logging::logging::log(level, "componentized-latch", message);
}

/// Log a critical message from a latch, formatted like `format!`.
#[macro_export]
macro_rules! critical {
    ($($arg:tt)*) => {
        $crate::log($crate::bindings::wasi::logging::logging::Level::Critical, &format!($($arg)*))
    };
}

/// Log an error from a latch, formatted like `format!`.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log($crate::bindings::wasi::logging::logging::Level::Error, &format!($($arg)*))
    };
}

/// Log a warning from a latch, formatted like `format!`.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log($crate::bindings::wasi::logging::logging::Level::Warn, &format!($($arg)*))
    };
}

/// Log a trace message from a latch, formatted like `format!`.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::log($crate::bindings::wasi::logging::logging::Level::Trace, &format!($($arg)*))
    };
}

/// Load the latch's config from `wasi:config/store` and parse it.
///
/// When the config cannot be read or parsed, the cause is logged and an `invalid-config` error
/// naming the latch is returned. Parse errors describe the offending entry, e.g.
/// `KEY=<key> VALUE=<value> ERROR=<error>`.
pub fn load_config<T>(
    latch_name: &str,
    parse: impl FnOnce(Vec<(String, String)>) -> Result<T, String>,
) -> Result<T, ErrorCode> {
    use bindings::wasi::config::store;

    store::get_all()
        .map_err(|err| match err {
            store::Error::Upstream(message) => format!("ERROR=upstream: {message}"),
            store::Error::Io(message) => format!("ERROR=io: {message}"),
        })
        .and_then(parse)
        .map_err(|message| {
            critical!("Invalid config LATCH={latch_name} {message}");
            ErrorCode::InvalidConfig(latch_name.to_string())
        })
}

/// State kept by a latch between calls, in a `static`.
///
/// Components are single threaded, and a component is not reentered while it is running, so the
/// state is never shared between threads.
pub struct Local<T>(RefCell<T>);

// components are single threaded, and a component is not reentered while it is running
unsafe impl<T> Sync for Local<T> {}

impl<T> Local<T> {
    pub const fn new(value: T) -> Local<T> {
        Local(RefCell::new(value))
    }
}

impl<T> Deref for Local<T> {
    type Target = RefCell<T>;

    fn deref(&self) -> &RefCell<T> {
        &self.0
    }
}

impl From<IpAddress> for IpAddr {
    fn from(address: IpAddress) -> IpAddr {
        match address {
            IpAddress::Ipv4((a, b, c, d)) => IpAddr::from([a, b, c, d]),
            IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => IpAddr::from([a, b, c, d, e, f, g, h]),
        }
    }
}

impl From<IpSocketAddress> for SocketAddr {
    fn from(address: IpSocketAddress) -> SocketAddr {
        match address {
            IpSocketAddress::Ipv4(ipv4) => {
                SocketAddr::new(IpAddress::Ipv4(ipv4.address).into(), ipv4.port)
            }
            IpSocketAddress::Ipv6(ipv6) => {
                SocketAddr::new(IpAddress::Ipv6(ipv6.address).into(), ipv6.port)
            }
        }
    }
}

/// The reason to deny an operation because of a socket error, e.g. an address that cannot be
/// determined.
pub fn socket_error_reason(err: WasiErrorCode) -> SocketsErrorCode {
    SocketsErrorCode::Other(Some(err.to_string().to_kebab_case()))
}

/// A denial reason, displayed the way gates log it, e.g. `access-denied`.
impl fmt::Display for SocketsErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketsErrorCode::AccessDenied => f.write_str("access-denied"),
            SocketsErrorCode::InvalidArgument => f.write_str("invalid-argument"),
            SocketsErrorCode::Other(Some(message)) => f.write_str(message),
            SocketsErrorCode::Other(None) => f.write_str("other"),
        }
    }
}

/// Displays a latch error the way gates log it, e.g. `invalid-config<latch-name>`.
///
/// The generated bindings already implement `Display` for [`ErrorCode`], with its debug form.
pub struct DisplayError<'a>(pub &'a ErrorCode);

impl fmt::Display for DisplayError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ErrorCode::InvalidConfig(latch) => write!(f, "invalid-config<{latch}>"),
            ErrorCode::ObservationFailed(latch) => write!(f, "observation-failed<{latch}>"),
            ErrorCode::Other(Some(message)) => f.write_str(message),
            ErrorCode::Other(None) => f.write_str("other"),
        }
    }
}

/// An address family, displayed the way gates log it, e.g. `IPv4`.
impl fmt::Display for IpAddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddressFamily::Ipv4 => f.write_str("IPv4"),
            IpAddressFamily::Ipv6 => f.write_str("IPv6"),
        }
    }
}

/// An address, displayed like [`IpAddr`], e.g. `10.1.2.3` or `2001:db8::1`.
impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        IpAddr::from(*self).fmt(f)
    }
}

/// A socket address, displayed like [`SocketAddr`], e.g. `10.1.2.3:443` or `[2001:db8::1]:443`.
impl fmt::Display for IpSocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        SocketAddr::from(*self).fmt(f)
    }
}

/// A socket address that may not be known, e.g. the remote address of a socket that is not
/// connected.
struct OptionalAddress(Option<IpSocketAddress>);

impl fmt::Display for OptionalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(address) => address.fmt(f),
            None => f.write_str("none"),
        }
    }
}

/// An operation, displayed the way gates log it, e.g.
/// `OPERATION=wasi:sockets/types#tcp-socket.connect REMOTE-ADDRESS=10.1.2.3:443`.
impl fmt::Display for Operation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::IpNameLookup(operation) => match operation {
                IpNameLookupOperation::ResolveAddresses(args) => write!(
                    f,
                    "OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={}",
                    args.name
                ),
                IpNameLookupOperation::ResolveAddressesReturn(item) => write!(
                    f,
                    "OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses IP-ADDRESS={}",
                    item.ip_address
                ),
            },
            Operation::TcpSocket(operation) => match operation {
                TcpSocketOperation::Create(args) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY={}",
                    args.address_family
                ),
                TcpSocketOperation::Bind((_, args)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS={}",
                    args.local_address
                ),
                TcpSocketOperation::Connect((_, args)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.connect REMOTE-ADDRESS={}",
                    args.remote_address
                ),
                TcpSocketOperation::Listen((socket,)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.listen LOCAL-ADDRESS={}",
                    OptionalAddress(socket.get_local_address().ok())
                ),
                TcpSocketOperation::ListenConnection((socket,)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.listen REMOTE-ADDRESS={}",
                    OptionalAddress(socket.get_remote_address().ok())
                ),
                TcpSocketOperation::Send((socket,)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.send REMOTE-ADDRESS={}",
                    OptionalAddress(socket.get_remote_address().ok())
                ),
                TcpSocketOperation::Receive((socket,)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#tcp-socket.receive REMOTE-ADDRESS={}",
                    OptionalAddress(socket.get_remote_address().ok())
                ),
            },
            Operation::UdpSocket(operation) => match operation {
                UdpSocketOperation::Create(args) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY={}",
                    args.address_family
                ),
                UdpSocketOperation::Bind((_, args)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#udp-socket.bind LOCAL-ADDRESS={}",
                    args.local_address
                ),
                UdpSocketOperation::Connect((_, args)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#udp-socket.connect REMOTE-ADDRESS={}",
                    args.remote_address
                ),
                UdpSocketOperation::Send((socket, args)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#udp-socket.send DATA-LENGTH={} REMOTE-ADDRESS={}",
                    args.data_length,
                    OptionalAddress(
                        args.remote_address
                            .or_else(|| socket.get_remote_address().ok())
                    )
                ),
                UdpSocketOperation::Receive((_, args)) => write!(
                    f,
                    "OPERATION=wasi:sockets/types#udp-socket.receive DATA-LENGTH={} REMOTE-ADDRESS={}",
                    args.data_length, args.remote_address
                ),
            },
        }
    }
}
