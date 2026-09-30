use sockets_latch::{
    Decision, ErrorCode, IpAddress, IpAddressFamily, IpNameLookupOperation, IpSocketAddress, Latch,
    Operation, SocketsErrorCode, TcpSocketOperation, UdpSocketOperation, socket_error_reason,
};

struct DenyIPv6Latch {}

impl Latch for DenyIPv6Latch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(_) => Ok(Decision::Deferred),
                IpNameLookupOperation::ResolveAddressesReturn(resolve_addresses_returns_item) => {
                    match resolve_addresses_returns_item.ip_address {
                        IpAddress::Ipv4(_) => Ok(Decision::Deferred),
                        IpAddress::Ipv6(_) => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                    }
                }
            },
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(tcp_socket_create_args) => {
                    match tcp_socket_create_args.address_family {
                        IpAddressFamily::Ipv4 => Ok(Decision::Deferred),
                        IpAddressFamily::Ipv6 => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                TcpSocketOperation::Bind((_, tcp_socket_bind_args)) => {
                    match tcp_socket_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Deferred),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                    match tcp_socket_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Deferred),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                TcpSocketOperation::Listen(_) => Ok(Decision::Deferred),
                TcpSocketOperation::ListenConnection((tcp_socket,)) => {
                    match tcp_socket.get_remote_address() {
                        Ok(IpSocketAddress::Ipv4(_)) => Ok(Decision::Deferred),
                        Ok(IpSocketAddress::Ipv6(_)) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        Err(error_code) => Ok(Decision::Denied(socket_error_reason(error_code))),
                    }
                }
                TcpSocketOperation::Send(_) => Ok(Decision::Deferred),
                TcpSocketOperation::Receive(_) => Ok(Decision::Deferred),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(udp_socket_create_args) => {
                    match udp_socket_create_args.address_family {
                        IpAddressFamily::Ipv4 => Ok(Decision::Deferred),
                        IpAddressFamily::Ipv6 => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                UdpSocketOperation::Bind((_, udp_socket_bind_args)) => {
                    match udp_socket_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Deferred),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                    match udp_socket_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Deferred),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
                UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                    match udp_socket_send_args.remote_address {
                        Some(IpSocketAddress::Ipv4(_)) => Ok(Decision::Deferred),
                        Some(IpSocketAddress::Ipv6(_)) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        None => Ok(Decision::Deferred),
                    }
                }
                UdpSocketOperation::Receive((_, udp_socket_receive_args)) => {
                    match udp_socket_receive_args.remote_address {
                        IpSocketAddress::Ipv4(_) => Ok(Decision::Deferred),
                        IpSocketAddress::Ipv6(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                    }
                }
            },
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

sockets_latch::export!(DenyIPv6Latch with_types_in sockets_latch::bindings);
