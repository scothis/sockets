use std::net::SocketAddr;

use latch_cidr::{Peers, Ranges};
use sockets_latch::{
    Decision, ErrorCode, IpSocketAddress, Latch, Local, Operation, TcpSocketOperation,
    UdpSocketOperation, WasiErrorCode, socket_error_reason,
};

const LATCH_NAME: &str = "latch-cidr-ingress";

struct CidrIngressLatch {}

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

/// Decide whether traffic originating from the remote address may reach the guest's local
/// address. Return traffic from an established peer is deferred without consulting the ranges.
fn authorize(
    remote_address: Result<IpSocketAddress, WasiErrorCode>,
    local_address: Result<IpSocketAddress, WasiErrorCode>,
    established: bool,
) -> Result<Decision, ErrorCode> {
    with_ranges(|ranges| {
        if established {
            return Decision::Deferred;
        }
        // inbound traffic matches the guest's local port it is sent to, the remote port is
        // usually an ephemeral port chosen by the peer
        match remote_address.and_then(|remote_address| Ok((remote_address, local_address?))) {
            Ok((remote_address, local_address)) => ranges.decision(
                SocketAddr::from(remote_address).ip(),
                SocketAddr::from(local_address).port(),
            ),
            Err(err) => Decision::Denied(socket_error_reason(err)),
        }
    })
}

struct State {
    /// `None` until the config is loaded.
    ranges: Option<Result<Ranges, ErrorCode>>,
    /// Peers udp sockets have sent datagrams to or connected to, datagrams from them are return
    /// traffic.
    udp_peers: Peers,
}

static STATE: Local<State> = Local::new(State {
    ranges: None,
    udp_peers: Peers::new(),
});

/// Record the peer as established for the socket. A socket sending or connecting before it is
/// bound has no local address yet, the peer is then recorded for any local address.
fn record_udp_peer(
    local_address: Result<IpSocketAddress, WasiErrorCode>,
    remote_address: IpSocketAddress,
) {
    STATE.borrow_mut().udp_peers.record(
        local_address.ok().map(SocketAddr::from),
        SocketAddr::from(remote_address),
    );
}

impl Latch for CidrIngressLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            // tcp traffic originates from a peer when it connects to a listening socket, receiving
            // on a connection the guest opened is return traffic
            Operation::TcpSocket(TcpSocketOperation::ListenConnection((tcp_socket,))) => authorize(
                tcp_socket.get_remote_address(),
                tcp_socket.get_local_address(),
                false,
            ),
            Operation::UdpSocket(UdpSocketOperation::Receive((
                udp_socket,
                udp_socket_receive_returns,
            ))) => {
                let remote_address = udp_socket_receive_returns.remote_address;
                let established = STATE.borrow().udp_peers.contains(
                    udp_socket.get_local_address().ok().map(SocketAddr::from),
                    SocketAddr::from(remote_address),
                );
                authorize(
                    Ok(remote_address),
                    udp_socket.get_local_address(),
                    established,
                )
            }
            _ => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // only a send or connect the final decision allows reaches the peer, a denial from any
        // latch means datagrams from the peer are not return traffic
        let Decision::Deferred = final_decision else {
            return Ok(());
        };
        match operation {
            Operation::UdpSocket(UdpSocketOperation::Send((udp_socket, udp_socket_send_args))) => {
                // a connected socket sends to its remote address
                let remote_address = match udp_socket_send_args.remote_address {
                    Some(remote_address) => Ok(remote_address),
                    None => udp_socket.get_remote_address(),
                };
                if let Ok(remote_address) = remote_address {
                    record_udp_peer(udp_socket.get_local_address(), remote_address);
                }
            }
            Operation::UdpSocket(UdpSocketOperation::Connect((
                udp_socket,
                udp_socket_connect_args,
            ))) => {
                record_udp_peer(
                    udp_socket.get_local_address(),
                    udp_socket_connect_args.remote_address,
                );
            }
            _ => {}
        }
        Ok(())
    }
}

sockets_latch::export!(CidrIngressLatch with_types_in sockets_latch::bindings);
