#![no_main]

use crate::{
    exports::componentized::sockets::latch::{
        Decision, Guest as Latch, IncomingDatagramOperation, IpAddressFamily,
        IpNameLookupOperation, IpSocketAddress, Operation, OutgoingDatagramOperation,
        ResolveAddressStreamOperation, TcpCreateSocketOperation, TcpSocketOperation,
        UdpCreateSocketOperation, UdpSocketOperation,
    },
    wasi::sockets::network::ErrorCode,
};

struct DenyIPv6Latch {}

impl Latch for DenyIPv6Latch {
    fn authorize(operation: Operation) -> Option<Decision> {
        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(_) => None,
            },
            Operation::ResolveAddressStream((_, _, resolve_address_stream_operation)) => {
                match resolve_address_stream_operation {
                    ResolveAddressStreamOperation::ResolveNextAddressEntry(
                        resolve_next_address_entry_args,
                    ) => match resolve_next_address_entry_args.ip_address {
                        wasi::sockets::network::IpAddress::Ipv4(_) => None,
                        wasi::sockets::network::IpAddress::Ipv6(_) => {
                            Some(Decision::Denied(ErrorCode::NotSupported))
                        }
                    },
                }
            }
            Operation::TcpCreateSocket(tcp_create_socket_operation) => {
                match tcp_create_socket_operation {
                    TcpCreateSocketOperation::CreateTcpSocket(create_tcp_socket_args) => {
                        match create_tcp_socket_args.address_family {
                            IpAddressFamily::Ipv4 => None,
                            IpAddressFamily::Ipv6 => {
                                Some(Decision::Denied(ErrorCode::NotSupported))
                            }
                        }
                    }
                }
            }
            Operation::TcpSocket((_, tcp_socket_operation)) => match tcp_socket_operation {
                TcpSocketOperation::StartBind(start_bind_args) => {
                    match start_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => None,
                        IpSocketAddress::Ipv6(_) => Some(Decision::Denied(ErrorCode::NotSupported)),
                    }
                }
                TcpSocketOperation::StartConnect(start_connect_args) => {
                    match start_connect_args.remote_address {
                        IpSocketAddress::Ipv4(_) => None,
                        IpSocketAddress::Ipv6(_) => Some(Decision::Denied(ErrorCode::NotSupported)),
                    }
                }
            },
            Operation::UdpCreateSocket(udp_create_socket_operation) => {
                match udp_create_socket_operation {
                    UdpCreateSocketOperation::CreateUdpSocket(create_udp_socket_args) => {
                        match create_udp_socket_args.address_family {
                            IpAddressFamily::Ipv4 => None,
                            IpAddressFamily::Ipv6 => {
                                Some(Decision::Denied(ErrorCode::NotSupported))
                            }
                        }
                    }
                }
            }
            Operation::UdpSocket((_, udp_socket_operation)) => match udp_socket_operation {
                UdpSocketOperation::StartBind(start_bind_args) => {
                    match start_bind_args.local_address {
                        IpSocketAddress::Ipv4(_) => None,
                        IpSocketAddress::Ipv6(_) => Some(Decision::Denied(ErrorCode::NotSupported)),
                    }
                }
                UdpSocketOperation::Stream(stream_args) => match stream_args.remote_address {
                    Some(IpSocketAddress::Ipv4(_)) => None,
                    Some(IpSocketAddress::Ipv6(_)) => {
                        Some(Decision::Denied(ErrorCode::NotSupported))
                    }
                    None => None,
                },
            },
            Operation::UdpStreamIncomingDatagram(incoming_datagram_operation) => {
                match incoming_datagram_operation {
                    IncomingDatagramOperation::ReceiveIncomingDatagram(
                        receive_incoming_datagram_args,
                    ) => match receive_incoming_datagram_args.remote_address {
                        IpSocketAddress::Ipv4(_) => None,
                        IpSocketAddress::Ipv6(_) => Some(Decision::Denied(ErrorCode::NotSupported)),
                    },
                }
            }
            Operation::UdpStreamOutgoingDatagram(outgoing_datagram_operation) => {
                match outgoing_datagram_operation {
                    OutgoingDatagramOperation::SendOutgoingDatagram(
                        send_outgoing_datagram_args,
                    ) => match send_outgoing_datagram_args.remote_address {
                        Some(IpSocketAddress::Ipv4(_)) => None,
                        Some(IpSocketAddress::Ipv6(_)) => {
                            Some(Decision::Denied(ErrorCode::NotSupported))
                        }
                        None => todo!(),
                    },
                }
            }
        }
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    generate_all
});

export!(DenyIPv6Latch);
