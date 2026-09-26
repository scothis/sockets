#![cfg_attr(not(test), no_main)]

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpAddress, IpSocketAddress, Operation, SocketsErrorCode,
};

struct State {
    granted_addresses: Mutex<HashSet<IpAddress>>,
}

impl State {
    fn is_granted_socket_address(socket_address: IpSocketAddress) -> bool {
        let ip_address = match socket_address {
            IpSocketAddress::Ipv4(ipv4_socket_address) => {
                IpAddress::Ipv4(ipv4_socket_address.address)
            }
            IpSocketAddress::Ipv6(ipv6_socket_address) => {
                IpAddress::Ipv6(ipv6_socket_address.address)
            }
        };
        Self::get()
            .granted_addresses
            .lock()
            .unwrap()
            .contains(&ip_address)
    }

    fn grant_ip_address(ip_address: IpAddress) {
        Self::get()
            .granted_addresses
            .lock()
            .unwrap()
            .insert(ip_address);
    }

    fn get() -> &'static Self {
        STATE.get_or_init(|| Self {
            granted_addresses: Mutex::new(HashSet::new()),
        })
    }
}

static STATE: OnceLock<State> = OnceLock::new();

struct ConnectToLookedUpAddressLatch {}

impl Latch for ConnectToLookedUpAddressLatch {
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
                        match State::is_granted_socket_address(
                            tcp_socket_connect_args.remote_address,
                        ) {
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
                        match State::is_granted_socket_address(
                            udp_socket_connect_args.remote_address,
                        ) {
                            true => Ok(Decision::Abstained),
                            false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                        }
                    }
                    latch::UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                        match udp_socket_send_args.remote_address {
                            Some(remote_address) => {
                                match State::is_granted_socket_address(remote_address) {
                                    true => Ok(Decision::Abstained),
                                    false => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                                }
                            }
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
                State::grant_ip_address(ip_address)
            }
        }

        decision
    }
}

impl PartialEq for IpAddress {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ipv4(l0), Self::Ipv4(r0)) => l0 == r0,
            (Self::Ipv6(l0), Self::Ipv6(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for IpAddress {}

impl Hash for IpAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            IpAddress::Ipv4(ipv4) => {
                4.hash(state);
                ipv4.hash(state);
            }
            IpAddress::Ipv6(ipv6) => {
                6.hash(state);
                ipv6.hash(state);
            }
        }
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(ConnectToLookedUpAddressLatch);
