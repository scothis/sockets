use std::net::SocketAddr;

use latch_cidr::{Peers, Ranges};
use sockets_latch::{
    Decision, ErrorCode, IpSocketAddress, Latch, Local, Operation, TcpSocketOperation,
    UdpSocketOperation, WasiErrorCode, socket_error_reason,
};

const LATCH_NAME: &str = "latch-cidr-egress";

struct CidrEgressLatch {}

/// Load the ranges from config, logging why when the config is invalid, and warnings for likely
/// mistakes.
fn load() -> Result<Ranges, ErrorCode> {
    sockets_latch::load_config(LATCH_NAME, Ranges::parse).inspect(|ranges| {
        for warning in ranges.warnings() {
            sockets_latch::warn!("Config issue LATCH={LATCH_NAME} {warning}");
        }
    })
}

/// The ranges, loaded once, an invalid config fails every authorization.
fn with_ranges(f: impl FnOnce(&Ranges) -> Decision) -> Result<Decision, ErrorCode> {
    match STATE.borrow_mut().ranges.get_or_insert_with(load) {
        Ok(ranges) => Ok(f(ranges)),
        Err(err) => Err(err.clone()),
    }
}

/// Decide whether traffic may originate to the remote address. Return traffic to an established
/// peer is deferred without consulting the ranges.
fn authorize(
    remote_address: Result<IpSocketAddress, WasiErrorCode>,
    established: bool,
) -> Result<Decision, ErrorCode> {
    with_ranges(|ranges| {
        if established {
            return Decision::Deferred;
        }
        match remote_address.map(SocketAddr::from) {
            // outbound traffic matches the remote port it is sent to
            Ok(remote_address) => ranges.decision(remote_address.ip(), remote_address.port()),
            Err(err) => Decision::Denied(socket_error_reason(err)),
        }
    })
}

struct State {
    /// `None` until the config is loaded.
    ranges: Option<Result<Ranges, ErrorCode>>,
    /// Peers udp sockets have received datagrams from, sending back to them is return traffic.
    udp_peers: Peers,
}

static STATE: Local<State> = Local::new(State {
    ranges: None,
    udp_peers: Peers::new(),
});

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
                    (Ok(remote_address), Ok(local_address)) => STATE.borrow().udp_peers.contains(
                        Some(SocketAddr::from(local_address)),
                        SocketAddr::from(*remote_address),
                    ),
                    _ => false,
                };
                authorize(remote_address, established)
            }
            _ => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // only a datagram the final decision allows reaches the guest, a denial from any latch
        // means there is nothing to reply to
        if let (
            Decision::Deferred,
            Operation::UdpSocket(UdpSocketOperation::Receive((
                udp_socket,
                udp_socket_receive_returns,
            ))),
        ) = (final_decision, operation)
        {
            // a socket that received a datagram is bound
            if let Ok(local_address) = udp_socket.get_local_address() {
                STATE.borrow_mut().udp_peers.record(
                    Some(SocketAddr::from(local_address)),
                    SocketAddr::from(udp_socket_receive_returns.remote_address),
                );
            }
        }
        Ok(())
    }
}

sockets_latch::export!(CidrEgressLatch with_types_in sockets_latch::bindings);
