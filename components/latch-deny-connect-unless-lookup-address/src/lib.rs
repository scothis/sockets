use std::{
    cell::RefCell,
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpAddress, IpSocketAddress, Operation, SocketsErrorCode,
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

impl Latch for DenyConnectUnlessLookUpAddressLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        let operation = operation.into();
        let decision = match latch::authorize(&operation)? {
            latch::Decision::Denied(error_code) => Ok(Decision::Denied(error_code.into())),
            latch::Decision::Abstained => match &operation {
                latch::Operation::IpNameLookup(_) => Ok(Decision::Abstained),
                latch::Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                    latch::TcpSocketOperation::Create(_) => Ok(Decision::Abstained),
                    latch::TcpSocketOperation::Bind(_) => Ok(Decision::Abstained),
                    latch::TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                        match State::is_known_address(tcp_socket_connect_args.remote_address) {
                            true => Ok(Decision::Abstained),
                            false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                        }
                    }
                    latch::TcpSocketOperation::Listen(_) => Ok(Decision::Abstained),
                    latch::TcpSocketOperation::ListenConnection(_) => Ok(Decision::Abstained),
                    latch::TcpSocketOperation::Send(_) => Ok(Decision::Abstained),
                    latch::TcpSocketOperation::Receive(_) => Ok(Decision::Abstained),
                },
                latch::Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                    latch::UdpSocketOperation::Create(_) => Ok(Decision::Abstained),
                    latch::UdpSocketOperation::Bind(_) => Ok(Decision::Abstained),
                    latch::UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                        match State::is_known_address(udp_socket_connect_args.remote_address) {
                            true => Ok(Decision::Abstained),
                            false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                        }
                    }
                    latch::UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                        match udp_socket_send_args.remote_address {
                            Some(remote_address) => match State::is_known_address(remote_address) {
                                true => Ok(Decision::Abstained),
                                false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                            },
                            None => Ok(Decision::Abstained),
                        }
                    }
                    latch::UdpSocketOperation::Receive(_) => Ok(Decision::Abstained),
                },
            },
        };

        if !matches!(decision, Ok(Decision::Denied(_))) {
            if let latch::Operation::IpNameLookup(
                latch::IpNameLookupOperation::ResolveAddressesReturn(
                    latch::ResolveAddressesReturnsItem { ip_address },
                ),
            ) = operation
            {
                State::add_known_address(ip_address)
            }
        }

        decision
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DenyConnectUnlessLookUpAddressLatch);
