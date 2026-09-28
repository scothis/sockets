use std::{
    cell::RefCell,
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpAddress, IpNameLookupOperation, IpSocketAddress,
    Operation, ResolveAddressesReturnsItem, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};

struct State {
    known_addresses: RefCell<BTreeSet<IpAddr>>,
}

// components are single threaded
unsafe impl Sync for State {}

impl State {
    fn is_known_address(socket_address: IpSocketAddress) -> bool {
        let ip_address = match socket_address {
            IpSocketAddress::Ipv4(ipv4_socket_address) => {
                IpAddress::Ipv4(ipv4_socket_address.address)
            }
            IpSocketAddress::Ipv6(ipv6_socket_address) => {
                IpAddress::Ipv6(ipv6_socket_address.address)
            }
        };
        STATE
            .known_addresses
            .borrow()
            .contains(&ip_addr(ip_address))
    }

    fn add_known_address(ip_address: IpAddress) {
        STATE
            .known_addresses
            .borrow_mut()
            .insert(ip_addr(ip_address));
    }
}

static STATE: State = State {
    known_addresses: RefCell::new(BTreeSet::new()),
};

fn ip_addr(ip_address: IpAddress) -> IpAddr {
    match ip_address {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

struct DenyConnectUnlessLookUpAddressLatch {}

fn known_address(remote_address: IpSocketAddress) -> Result<Decision, ErrorCode> {
    match State::is_known_address(remote_address) {
        true => Ok(Decision::Abstained),
        false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
    }
}

impl Latch for DenyConnectUnlessLookUpAddressLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(_) => Ok(Decision::Abstained),
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Bind(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                    known_address(tcp_socket_connect_args.remote_address)
                }
                TcpSocketOperation::Listen(_) => Ok(Decision::Abstained),
                TcpSocketOperation::ListenConnection(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Send(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Receive(_) => Ok(Decision::Abstained),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(_) => Ok(Decision::Abstained),
                UdpSocketOperation::Bind(_) => Ok(Decision::Abstained),
                UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                    known_address(udp_socket_connect_args.remote_address)
                }
                UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                    match udp_socket_send_args.remote_address {
                        Some(remote_address) => known_address(remote_address),
                        None => Ok(Decision::Abstained),
                    }
                }
                UdpSocketOperation::Receive(_) => Ok(Decision::Abstained),
            },
        }
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // an address is known once the final decision allows it to be returned to the guest
        if let (
            Decision::Abstained,
            Operation::IpNameLookup(IpNameLookupOperation::ResolveAddressesReturn(
                ResolveAddressesReturnsItem { ip_address },
            )),
        ) = (final_decision, operation)
        {
            State::add_known_address(ip_address)
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

export!(DenyConnectUnlessLookUpAddressLatch);
