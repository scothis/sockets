use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};

use heck::ToKebabCase;
use latch_cidr::{Action, Peers, Ranges, Reason};

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};
use crate::wasi::logging::logging::{log, Level};
use crate::wasi::sockets::types::{ErrorCode as SocketErrorCode, IpSocketAddress};

macro_rules! critical {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Critical, "componentized-latch", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Critical, "componentized-latch", &format!($dst));
    };
}

const LATCH_NAME: &str = "latch-cidr-egress";

struct CidrEgressLatch {}

/// Load the ranges from config, logging why when the config is invalid.
fn load() -> Result<Ranges, ErrorCode> {
    wasi::config::store::get_all()
        .map_err(|err| match err {
            wasi::config::store::Error::Upstream(message) => format!("ERROR=upstream: {message}"),
            wasi::config::store::Error::Io(message) => format!("ERROR=io: {message}"),
        })
        .and_then(Ranges::parse)
        .map_err(|message| {
            critical!("Invalid config LATCH={LATCH_NAME} {message}");
            ErrorCode::InvalidConfig(LATCH_NAME.to_string())
        })
}

/// Decide whether traffic may originate to the remote address. Return traffic to an established
/// peer is abstained without consulting the ranges.
fn authorize(
    remote_address: Result<IpSocketAddress, SocketErrorCode>,
    established: bool,
) -> Result<Decision, ErrorCode> {
    // config is loaded once, an invalid config fails every authorization
    let mut ranges = STATE.ranges.borrow_mut();
    let ranges = match ranges.get_or_insert_with(load) {
        Ok(ranges) => ranges,
        Err(err) => return Err(err.clone()),
    };
    if established {
        return Ok(Decision::Abstained);
    }
    match remote_address {
        Ok(remote_address) => Ok(match ranges.action(ip_addr(remote_address)) {
            Action::Deny => Decision::Denied(sockets_error_code(ranges.reason())),
            Action::Abstain => Decision::Abstained,
        }),
        Err(err) => Ok(Decision::Denied(SocketsErrorCode::Other(Some(
            err.to_string().to_kebab_case(),
        )))),
    }
}

struct State {
    /// `None` until the config is loaded.
    ranges: RefCell<Option<Result<Ranges, ErrorCode>>>,
    /// Peers udp sockets have received datagrams from, sending back to them is return traffic.
    udp_peers: RefCell<Peers>,
}

// components are single threaded, and a component is not reentered while it is running
unsafe impl Sync for State {}

static STATE: State = State {
    ranges: RefCell::new(None),
    udp_peers: RefCell::new(Peers::new()),
};

fn sockets_error_code(reason: &Reason) -> SocketsErrorCode {
    match reason {
        Reason::AccessDenied => SocketsErrorCode::AccessDenied,
        Reason::InvalidArgument => SocketsErrorCode::InvalidArgument,
        Reason::Other(message) => SocketsErrorCode::Other(message.clone()),
    }
}

fn socket_addr(address: IpSocketAddress) -> SocketAddr {
    let port = match address {
        IpSocketAddress::Ipv4(ipv4) => ipv4.port,
        IpSocketAddress::Ipv6(ipv6) => ipv6.port,
    };
    SocketAddr::new(ip_addr(address), port)
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

impl Latch for CidrEgressLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            // tcp traffic originates with connect, sends on accepted connections are return traffic
            Operation::TcpSocket(TcpSocketOperation::Connect((_, tcp_socket_connect_args))) => {
                authorize(Ok(tcp_socket_connect_args.remote_address), false)
            }
            Operation::UdpSocket(UdpSocketOperation::Send((udp_socket, udp_socket_send_args))) => {
                // a connected socket sends to its remote address
                let remote_address = match udp_socket_send_args.remote_address {
                    Some(remote_address) => Ok(remote_address),
                    None => udp_socket.get_remote_address(),
                };
                let established = match (&remote_address, udp_socket.get_local_address()) {
                    (Ok(remote_address), Ok(local_address)) => STATE.udp_peers.borrow().contains(
                        Some(socket_addr(local_address)),
                        socket_addr(*remote_address),
                    ),
                    _ => false,
                };
                authorize(remote_address, established)
            }
            _ => Ok(Decision::Abstained),
        }
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // only a datagram the final decision allows reaches the guest, a denial from any latch
        // means there is nothing to reply to
        if let (
            Decision::Abstained,
            Operation::UdpSocket(UdpSocketOperation::Receive((
                udp_socket,
                udp_socket_receive_returns,
            ))),
        ) = (final_decision, operation)
        {
            // a socket that received a datagram is bound
            if let Ok(local_address) = udp_socket.get_local_address() {
                STATE.udp_peers.borrow_mut().record(
                    Some(socket_addr(local_address)),
                    socket_addr(udp_socket_receive_returns.remote_address),
                );
            }
        }
        Ok(())
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(CidrEgressLatch);
