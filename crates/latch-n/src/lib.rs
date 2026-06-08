#![no_main]

use crate::bindings::{
    componentized::sockets::latch,
    exports::componentized::sockets::latch::{
        Decision, ErrorCode, IpNameLookupOperation, Operation, ResolveAddressesArgs,
        ResolveAddressesReturnsItem, TcpSocketBindArgs, TcpSocketConnectArgs, TcpSocketCreateArgs,
        TcpSocketOperation, UdpSocketBindArgs, UdpSocketConnectArgs, UdpSocketCreateArgs,
        UdpSocketOperation, UdpSocketReceiveReturns, UdpSocketSendArgs,
    },
};

pub fn authorize(
    operation: Operation,
    authorizers: Vec<fn(&latch::Operation<'_>) -> Option<latch::Decision>>,
) -> Option<Decision> {
    let operation = operation.into();
    for authorize in authorizers {
        match authorize(&operation) {
            None => {}
            Some(latch::Decision::Permitted) => return Some(Decision::Permitted),
            Some(latch::Decision::Denied(error_code)) => {
                return Some(Decision::Denied(error_code.into()))
            }
        }
    }
    None
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

pub mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "sockets-latch-n",
        pub_export_macro: true,
        generate_all
    });
}

#[macro_export]
macro_rules! export {
    ($($t:tt)*) => {
        $crate::bindings::export!($($t)*);
    };
}
