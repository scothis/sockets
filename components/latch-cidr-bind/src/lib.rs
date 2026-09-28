use std::cell::RefCell;
use std::net::IpAddr;

use latch_cidr::{Action, Ranges, Reason};

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};
use crate::wasi::logging::logging::{Level, log};
use crate::wasi::sockets::types::IpSocketAddress;

macro_rules! critical {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Critical, "componentized-latch", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Critical, "componentized-latch", &format!($dst));
    };
}

macro_rules! warn {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Warn, "componentized-latch", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Warn, "componentized-latch", &format!($dst));
    };
}

const LATCH_NAME: &str = "latch-cidr-bind";

struct CidrBindLatch {}

/// Load the ranges from config, logging why when the config is invalid.
fn load() -> Result<Ranges, ErrorCode> {
    wasi::config::store::get_all()
        .map_err(|err| match err {
            wasi::config::store::Error::Upstream(message) => format!("ERROR=upstream: {message}"),
            wasi::config::store::Error::Io(message) => format!("ERROR=io: {message}"),
        })
        .and_then(Ranges::parse)
        .inspect(|ranges| {
            // accepted, but likely mistakes
            for warning in ranges.warnings() {
                warn!("Config issue LATCH={LATCH_NAME} {warning}");
            }
        })
        .map_err(|message| {
            critical!("Invalid config LATCH={LATCH_NAME} {message}");
            ErrorCode::InvalidConfig(LATCH_NAME.to_string())
        })
}

/// Decide whether a socket may be bound to the local address and port.
fn authorize(local_address: IpSocketAddress) -> Result<Decision, ErrorCode> {
    // config is loaded once, an invalid config fails every authorization
    let mut ranges = STATE.ranges.borrow_mut();
    let ranges = match ranges.get_or_insert_with(load) {
        Ok(ranges) => ranges,
        Err(err) => return Err(err.clone()),
    };
    Ok(
        match ranges.action(ip_addr(local_address), port(local_address)) {
            Action::Deny => Decision::Denied(sockets_error_code(ranges.reason())),
            Action::Abstain => Decision::Abstained,
        },
    )
}

struct State {
    /// `None` until the config is loaded.
    ranges: RefCell<Option<Result<Ranges, ErrorCode>>>,
}

// components are single threaded, and a component is not reentered while it is running
unsafe impl Sync for State {}

static STATE: State = State {
    ranges: RefCell::new(None),
};

fn sockets_error_code(reason: &Reason) -> SocketsErrorCode {
    match reason {
        Reason::AccessDenied => SocketsErrorCode::AccessDenied,
        Reason::InvalidArgument => SocketsErrorCode::InvalidArgument,
        Reason::Other(message) => SocketsErrorCode::Other(message.clone()),
    }
}

fn port(address: IpSocketAddress) -> u16 {
    match address {
        IpSocketAddress::Ipv4(ipv4) => ipv4.port,
        IpSocketAddress::Ipv6(ipv6) => ipv6.port,
    }
}

fn ip_addr(address: IpSocketAddress) -> IpAddr {
    match address {
        IpSocketAddress::Ipv4(ipv4) => {
            let (a, b, c, d) = ipv4.address;
            IpAddr::from([a, b, c, d])
        }
        IpSocketAddress::Ipv6(ipv6) => {
            let (a, b, c, d, e, f, g, h) = ipv6.address;
            IpAddr::from([a, b, c, d, e, f, g, h])
        }
    }
}

impl Latch for CidrBindLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            // only explicit binds are checked, an implicit bind by listen, connect or send has no
            // operation of its own
            Operation::TcpSocket(TcpSocketOperation::Bind((_, tcp_socket_bind_args))) => {
                authorize(tcp_socket_bind_args.local_address)
            }
            Operation::UdpSocket(UdpSocketOperation::Bind((_, udp_socket_bind_args))) => {
                authorize(udp_socket_bind_args.local_address)
            }
            _ => Ok(Decision::Abstained),
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(CidrBindLatch);
