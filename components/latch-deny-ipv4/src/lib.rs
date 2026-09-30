use sockets_latch::{
    Decision, ErrorCode, IpAddress, IpAddressFamily, IpNameLookupOperation, IpSocketAddress, Latch,
    Operation, SocketsErrorCode, TcpSocketOperation, UdpSocketOperation, socket_error_reason,
};

struct DenyIPv4Latch {}

impl Latch for DenyIPv4Latch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(_) => Ok(Decision::Deferred),
                IpNameLookupOperation::ResolveAddressesReturn(resolve_addresses_returns_item) => {
                    match resolve_addresses_returns_item.ip_address {
                        IpAddress::Ipv4(_) => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
                        IpAddress::Ipv6(_) => Ok(Decision::Deferred),
                    }
                }
            },
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(tcp_socket_create_args) => {
                    match tcp_socket_create_args.address_family {
                        IpAddressFamily::Ipv4 => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpAddressFamily::Ipv6 => Ok(Decision::Deferred),
                    }
                }
                TcpSocketOperation::Bind((_, tcp_socket_bind_args)) => {
                    match tcp_socket_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpSocketAddress::Ipv6(_) => Ok(Decision::Deferred),
                    }
                }
                TcpSocketOperation::Connect((_, tcp_socket_connect_args)) => {
                    match tcp_socket_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpSocketAddress::Ipv6(_) => Ok(Decision::Deferred),
                    }
                }
                TcpSocketOperation::Listen(_) => Ok(Decision::Deferred),
                TcpSocketOperation::ListenConnection((tcp_socket,)) => {
                    match tcp_socket.get_remote_address() {
                        Ok(IpSocketAddress::Ipv4(_)) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        Ok(IpSocketAddress::Ipv6(_)) => Ok(Decision::Deferred),
                        Err(error_code) => Ok(Decision::Denied(socket_error_reason(error_code))),
                    }
                }
                TcpSocketOperation::Send(_) => Ok(Decision::Deferred),
                TcpSocketOperation::Receive(_) => Ok(Decision::Deferred),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(udp_socket_create_args) => {
                    match udp_socket_create_args.address_family {
                        IpAddressFamily::Ipv4 => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpAddressFamily::Ipv6 => Ok(Decision::Deferred),
                    }
                }
                UdpSocketOperation::Bind((_, udp_socket_bind_args)) => {
                    match udp_socket_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpSocketAddress::Ipv6(_) => Ok(Decision::Deferred),
                    }
                }
                UdpSocketOperation::Connect((_, udp_socket_connect_args)) => {
                    match udp_socket_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpSocketAddress::Ipv6(_) => Ok(Decision::Deferred),
                    }
                }
                UdpSocketOperation::Send((_, udp_socket_send_args)) => {
                    match udp_socket_send_args.remote_address {
                        Some(IpSocketAddress::Ipv4(_)) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        Some(IpSocketAddress::Ipv6(_)) => Ok(Decision::Deferred),
                        None => Ok(Decision::Deferred),
                    }
                }
                UdpSocketOperation::Receive((_, udp_socket_receive_args)) => {
                    match udp_socket_receive_args.remote_address {
                        IpSocketAddress::Ipv4(_) => {
                            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                        }
                        IpSocketAddress::Ipv6(_) => Ok(Decision::Deferred),
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

sockets_latch::export!(DenyIPv4Latch with_types_in sockets_latch::bindings);
