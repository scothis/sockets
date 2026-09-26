#![cfg_attr(not(test), no_main)]

use heck::ToKebabCase;

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpNameLookupOperation, Operation, SocketsErrorCode,
    TcpSocketOperation, UdpSocketOperation,
};
use crate::wasi::sockets::types::{IpAddress, IpAddressFamily, IpSocketAddress};

struct DenyIPv6Latch {}

impl Latch for DenyIPv6Latch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(_) => Ok(Decision::Abstained),
                IpNameLookupOperation::ResolveAddressesReturn(resolve_addresses_returns_item) => {
                    match resolve_addresses_returns_item.ip_address {
                        IpAddress::Ipv4(_) => Ok(Decision::Abstained),
                        IpAddress::Ipv6(_) => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                    }
                }
            },
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(tcp_socket_create_args) => {
                    match tcp_socket_create_args.address_family {
                        IpAddressFamily::Ipv4 => Ok(Decision::Abstained),
                        IpAddressFamily::Ipv6 => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                TcpSocketOperation::Bind((_, tcp_socket_bind_args)) => {
                    match tcp_socket_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Abstained),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                    match tcp_socket_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Abstained),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                TcpSocketOperation::Listen(_) => Ok(Decision::Abstained),
                TcpSocketOperation::ListenConnection((tcp_socket,)) => {
                    match tcp_socket.get_remote_address() {
                        Ok(IpSocketAddress::Ipv4(_)) => Ok(Decision::Abstained),
                        Ok(IpSocketAddress::Ipv6(_)) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        Err(error_code) => Ok(Decision::Denied(SocketsErrorCode::Other(Some(
                            error_code.to_string().to_kebab_case(),
                        )))),
                    }
                }
                TcpSocketOperation::Send(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Receive(_) => Ok(Decision::Abstained),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(udp_socket_create_args) => {
                    match udp_socket_create_args.address_family {
                        IpAddressFamily::Ipv4 => Ok(Decision::Abstained),
                        IpAddressFamily::Ipv6 => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                UdpSocketOperation::Bind((_, udp_socket_bind_args)) => {
                    match udp_socket_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Abstained),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                    match udp_socket_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Abstained),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                    match udp_socket_send_args.remote_address {
                        Some(IpSocketAddress::Ipv4(_)) => Ok(Decision::Abstained),
                        Some(IpSocketAddress::Ipv6(_)) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        None => Ok(Decision::Abstained),
                    }
                }
                UdpSocketOperation::Receive((_, udp_socket_receive_args)) => {
                    match udp_socket_receive_args.remote_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Abstained),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
            },
        }
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DenyIPv6Latch);
