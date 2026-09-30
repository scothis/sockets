use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use sockets_latch::{
    Decision, ErrorCode, IpAddress, IpNameLookupOperation, IpSocketAddress, Latch, Local,
    Operation, ResolveAddressesReturnsItem, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};

/// Addresses returned from lookups the final decision allowed.
static KNOWN_ADDRESSES: Local<BTreeSet<IpAddr>> = Local::new(BTreeSet::new());

fn is_known_address(socket_address: IpSocketAddress) -> bool {
    KNOWN_ADDRESSES
        .borrow()
        .contains(&SocketAddr::from(socket_address).ip())
}

fn add_known_address(ip_address: IpAddress) {
    KNOWN_ADDRESSES
        .borrow_mut()
        .insert(IpAddr::from(ip_address));
}

struct DenyConnectUnlessLookUpAddressLatch {}

fn known_address(remote_address: IpSocketAddress) -> Result<Decision, ErrorCode> {
    match is_known_address(remote_address) {
        true => Ok(Decision::Deferred),
        false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
    }
}

impl Latch for DenyConnectUnlessLookUpAddressLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                    known_address(tcp_socket_connect_args.remote_address)
                }
                _ => Ok(Decision::Deferred),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                    known_address(udp_socket_connect_args.remote_address)
                }
                UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                    match udp_socket_send_args.remote_address {
                        Some(remote_address) => known_address(remote_address),
                        None => Ok(Decision::Deferred),
                    }
                }
                _ => Ok(Decision::Deferred),
            },
            _ => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // an address is known once the final decision allows it to be returned to the guest
        if let (
            Decision::Deferred,
            Operation::IpNameLookup(IpNameLookupOperation::ResolveAddressesReturn(
                ResolveAddressesReturnsItem { ip_address },
            )),
        ) = (final_decision, operation)
        {
            add_known_address(ip_address)
        }
        Ok(())
    }
}

sockets_latch::export!(DenyConnectUnlessLookUpAddressLatch with_types_in sockets_latch::bindings);
