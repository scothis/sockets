#![no_main]

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpAddress, IpNameLookupOperation, IpSocketAddress,
    Operation, ResolveAddressesArgs, ResolveAddressesReturnsItem, TcpSocketBindArgs,
    TcpSocketConnectArgs, TcpSocketCreateArgs, TcpSocketOperation, UdpSocketBindArgs,
    UdpSocketConnectArgs, UdpSocketCreateArgs, UdpSocketOperation, UdpSocketReceiveReturns,
    UdpSocketSendArgs,
};

struct State {
    permitted_addresses: Mutex<HashSet<IpAddress>>,
}

impl State {
    fn is_permitted_socket_address(socket_address: IpSocketAddress) -> bool {
        let ip_address = match socket_address {
            IpSocketAddress::Ipv4(ipv4_socket_address) => {
                IpAddress::Ipv4(ipv4_socket_address.address)
            }
            IpSocketAddress::Ipv6(ipv6_socket_address) => {
                IpAddress::Ipv6(ipv6_socket_address.address)
            }
        };
        Self::get()
            .permitted_addresses
            .lock()
            .unwrap()
            .contains(&ip_address)
    }

    fn permit_ip_address(ip_address: IpAddress) {
        Self::get()
            .permitted_addresses
            .lock()
            .unwrap()
            .insert(ip_address);
    }

    fn get() -> &'static Self {
        STATE.get_or_init(|| Self {
            permitted_addresses: Mutex::new(HashSet::new()),
        })
    }
}

static STATE: OnceLock<State> = OnceLock::new();

struct ConnectToLookedUpAddressLatch {}

impl Latch for ConnectToLookedUpAddressLatch {
    fn authorize(operation: Operation) -> Option<Decision> {
        let operation = operation.into();
        let decision = match latch::authorize(&operation) {
            Some(latch::Decision::Permitted) => Some(Decision::Permitted),
            Some(latch::Decision::Denied(error_code)) => Some(Decision::Denied(error_code.into())),
            None => match &operation {
                latch::Operation::IpNameLookup(_) => None,
                latch::Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                    latch::TcpSocketOperation::Create(_) => None,
                    latch::TcpSocketOperation::Bind(_) => None,
                    latch::TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                        match State::is_permitted_socket_address(
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
                        match State::is_permitted_socket_address(
                            udp_socket_connect_args.remote_address,
                        ) {
                            true => None,
                            false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                        }
                    }
                    latch::UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                        match udp_socket_send_args.remote_address {
                            Some(remote_address) => {
                                match State::is_permitted_socket_address(remote_address) {
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
                State::permit_ip_address(ip_address)
            }
        }

        decision
    }
}

impl<'a> From<Operation<'a>> for latch::Operation<'a> {
    fn from(operation: Operation<'a>) -> Self {
        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => {
                latch::Operation::IpNameLookup(ip_name_lookup_operation.into())
            }
            Operation::TcpSocket(tcp_socket_operation) => {
                latch::Operation::TcpSocket(tcp_socket_operation.into())
            }
            Operation::UdpSocket(udp_socket_operation) => {
                latch::Operation::UdpSocket(udp_socket_operation.into())
            }
        }
    }
}

impl From<IpNameLookupOperation> for latch::IpNameLookupOperation {
    fn from(operation: IpNameLookupOperation) -> Self {
        match operation {
            IpNameLookupOperation::ResolveAddresses(resolve_addresses_args) => {
                latch::IpNameLookupOperation::ResolveAddresses(resolve_addresses_args.into())
            }
            IpNameLookupOperation::ResolveAddressesReturn(resolve_addresses_returns_item) => {
                latch::IpNameLookupOperation::ResolveAddressesReturn(
                    resolve_addresses_returns_item.into(),
                )
            }
        }
    }
}

impl<'a> From<TcpSocketOperation<'a>> for latch::TcpSocketOperation<'a> {
    fn from(operation: TcpSocketOperation<'a>) -> Self {
        match operation {
            TcpSocketOperation::Create(tcp_socket_create_args) => {
                latch::TcpSocketOperation::Create(tcp_socket_create_args.into())
            }
            TcpSocketOperation::Bind((tcp_socket, tcp_socker_bind_args)) => {
                latch::TcpSocketOperation::Bind((tcp_socket, tcp_socker_bind_args.into()))
            }
            TcpSocketOperation::Connect((tcp_socket, tcp_stocket_connect_args)) => {
                latch::TcpSocketOperation::Connect((tcp_socket, tcp_stocket_connect_args.into()))
            }
            TcpSocketOperation::Listen((tcp_socket,)) => {
                latch::TcpSocketOperation::Listen((tcp_socket,))
            }
            TcpSocketOperation::ListenConnection((tcp_socket,)) => {
                latch::TcpSocketOperation::ListenConnection((tcp_socket,))
            }
            TcpSocketOperation::Send((tcp_socket,)) => {
                latch::TcpSocketOperation::Send((tcp_socket,))
            }
            TcpSocketOperation::Receive((tcp_socket,)) => {
                latch::TcpSocketOperation::Receive((tcp_socket,))
            }
        }
    }
}

impl<'a> From<UdpSocketOperation<'a>> for latch::UdpSocketOperation<'a> {
    fn from(operation: UdpSocketOperation<'a>) -> Self {
        match operation {
            UdpSocketOperation::Create(udp_socket_create_args) => {
                latch::UdpSocketOperation::Create(udp_socket_create_args.into())
            }
            UdpSocketOperation::Bind((udp_socket, udp_socket_bind_args)) => {
                latch::UdpSocketOperation::Bind((udp_socket, udp_socket_bind_args.into()))
            }
            UdpSocketOperation::Connect((udp_socket, udp_socket_connect_args)) => {
                latch::UdpSocketOperation::Connect((udp_socket, udp_socket_connect_args.into()))
            }
            UdpSocketOperation::Send((udp_socket, udp_socket_send_args)) => {
                latch::UdpSocketOperation::Send((udp_socket, udp_socket_send_args.into()))
            }
            UdpSocketOperation::Receive((udp_socket, udp_socket_receive_args)) => {
                latch::UdpSocketOperation::Receive((udp_socket, udp_socket_receive_args.into()))
            }
        }
    }
}

impl From<ResolveAddressesArgs> for latch::ResolveAddressesArgs {
    fn from(args: ResolveAddressesArgs) -> Self {
        Self { name: args.name }
    }
}

impl From<ResolveAddressesReturnsItem> for latch::ResolveAddressesReturnsItem {
    fn from(returns: ResolveAddressesReturnsItem) -> Self {
        Self {
            ip_address: returns.ip_address,
        }
    }
}

impl From<TcpSocketCreateArgs> for latch::TcpSocketCreateArgs {
    fn from(args: TcpSocketCreateArgs) -> Self {
        Self {
            address_family: args.address_family,
        }
    }
}

impl From<TcpSocketBindArgs> for latch::TcpSocketBindArgs {
    fn from(args: TcpSocketBindArgs) -> Self {
        Self {
            local_address: args.local_address,
        }
    }
}

impl From<TcpSocketConnectArgs> for latch::TcpSocketConnectArgs {
    fn from(args: TcpSocketConnectArgs) -> Self {
        Self {
            remote_address: args.remote_address,
        }
    }
}

impl From<UdpSocketCreateArgs> for latch::UdpSocketCreateArgs {
    fn from(args: UdpSocketCreateArgs) -> Self {
        Self {
            address_family: args.address_family,
        }
    }
}

impl From<UdpSocketBindArgs> for latch::UdpSocketBindArgs {
    fn from(args: UdpSocketBindArgs) -> Self {
        Self {
            local_address: args.local_address,
        }
    }
}

impl From<UdpSocketConnectArgs> for latch::UdpSocketConnectArgs {
    fn from(args: UdpSocketConnectArgs) -> Self {
        Self {
            remote_address: args.remote_address,
        }
    }
}

impl From<UdpSocketReceiveReturns> for latch::UdpSocketReceiveReturns {
    fn from(returns: UdpSocketReceiveReturns) -> Self {
        Self {
            data_length: returns.data_length,
            remote_address: returns.remote_address,
        }
    }
}

impl From<UdpSocketSendArgs> for latch::UdpSocketSendArgs {
    fn from(args: UdpSocketSendArgs) -> Self {
        Self {
            data_length: args.data_length,
            remote_address: args.remote_address,
        }
    }
}

impl From<latch::ErrorCode> for ErrorCode {
    fn from(error_code: latch::ErrorCode) -> Self {
        match error_code {
            latch::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
            latch::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
            latch::ErrorCode::Other(error) => ErrorCode::Other(error),
        }
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
    generate_all
});

export!(ConnectToLookedUpAddressLatch);
