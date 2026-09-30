use std::net::SocketAddr;

use latch_cidr::Ranges;
use sockets_latch::{
    Decision, ErrorCode, IpSocketAddress, Latch, Local, Operation, TcpSocketOperation,
    UdpSocketOperation,
};

const LATCH_NAME: &str = "latch-cidr-bind";

struct CidrBindLatch {}

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

/// Decide whether a socket may be bound to the local address and port.
fn authorize(local_address: IpSocketAddress) -> Result<Decision, ErrorCode> {
    let local_address = SocketAddr::from(local_address);
    with_ranges(|ranges| ranges.decision(local_address.ip(), local_address.port()))
}

struct State {
    /// `None` until the config is loaded.
    ranges: Option<Result<Ranges, ErrorCode>>,
}

static STATE: Local<State> = Local::new(State { ranges: None });

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
            _ => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

sockets_latch::export!(CidrBindLatch with_types_in sockets_latch::bindings);
