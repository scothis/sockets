#![no_main]

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpAddress, IpSocketAddress, Operation,
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
    fn authorize(operation: Operation) -> Option<Decision> {
        let operation = operation.into();
        let decision = match latch::authorize(&operation) {
            Some(latch::Decision::Granted) => Some(Decision::Granted),
            Some(latch::Decision::Denied(error_code)) => Some(Decision::Denied(error_code.into())),
            None => match &operation {
                latch::Operation::IpNameLookup(_) => None,
                latch::Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                    latch::TcpSocketOperation::Create(_) => None,
                    latch::TcpSocketOperation::Bind(_) => None,
                    latch::TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                        match State::is_granted_socket_address(
                            tcp_socket_connect_args.remote_address,
                        ) {
                            true => None,
                            false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                        }
                    }
                    latch::TcpSocketOperation::Listen(_) => None,
                    latch::TcpSocketOperation::ListenConnection(_) => None,
                    latch::TcpSocketOperation::Send(_) => None,
                    latch::TcpSocketOperation::Receive(_) => None,
                },
                latch::Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                    latch::UdpSocketOperation::Create(_) => None,
                    latch::UdpSocketOperation::Bind(_) => None,
                    latch::UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                        match State::is_granted_socket_address(
                            udp_socket_connect_args.remote_address,
                        ) {
                            true => None,
                            false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                        }
                    }
                    latch::UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                        match udp_socket_send_args.remote_address {
                            Some(remote_address) => {
                                match State::is_granted_socket_address(remote_address) {
                                    true => None,
                                    false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                                }
                            }
                            None => None,
                        }
                    }
                    latch::UdpSocketOperation::Receive(_) => None,
                },
            },
        };

        if !matches!(decision, Some(Decision::Denied(_))) {
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
    path: "../../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(ConnectToLookedUpAddressLatch);
