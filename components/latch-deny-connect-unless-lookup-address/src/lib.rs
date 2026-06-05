#![no_main]

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    CreateTcpSocketArgs, CreateUdpSocketArgs, Decision, ErrorCode, Guest as Latch,
    IncomingDatagramOperation, IpNameLookupOperation, Operation, OutgoingDatagramOperation,
    ReceiveIncomingDatagramArgs, ResolveAddressStreamOperation, ResolveAddressesArgs,
    ResolveNextAddressEntryArgs, SendOutgoingDatagramArgs, StartBindArgs, StartConnectArgs,
    StreamArgs, TcpCreateSocketOperation, TcpSocketOperation, UdpCreateSocketOperation,
    UdpSocketOperation,
};
use crate::wasi::sockets::network::{IpAddress, IpSocketAddress};

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
        let operation = operation_map(operation);
        let decision = match latch::authorize(&operation) {
            Some(latch::Decision::Permitted) => Some(Decision::Permitted),
            Some(latch::Decision::Denied(error_code)) => Some(Decision::Denied(error_code)),
            None => match &operation {
                latch::Operation::IpNameLookup(_) => None,
                latch::Operation::ResolveAddressStream(_) => None,
                latch::Operation::TcpCreateSocket(_) => None,
                latch::Operation::TcpSocket((_, tcp_socket_operation)) => {
                    match tcp_socket_operation {
                        latch::TcpSocketOperation::StartBind(_) => None,
                        latch::TcpSocketOperation::StartConnect(start_connect_args) => {
                            match State::is_permitted_socket_address(
                                start_connect_args.remote_address,
                            ) {
                                true => None,
                                false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                            }
                        }
                    }
                }
                latch::Operation::UdpCreateSocket(_) => None,
                latch::Operation::UdpSocket((_, udp_socket_operation)) => {
                    match udp_socket_operation {
                        latch::UdpSocketOperation::StartBind(_) => None,
                        latch::UdpSocketOperation::Stream(stream_args) => {
                            match stream_args.remote_address {
                                Some(remote_address) => {
                                    match State::is_permitted_socket_address(remote_address) {
                                        true => None,
                                        false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                                    }
                                }
                                None => None,
                            }
                        }
                    }
                }
                latch::Operation::UdpStreamIncomingDatagram(_) => None,
                latch::Operation::UdpStreamOutgoingDatagram(outgoing_datagram_operation) => {
                    match outgoing_datagram_operation {
                        latch::OutgoingDatagramOperation::SendOutgoingDatagram(
                            send_outgoing_datagram_args,
                        ) => match send_outgoing_datagram_args.remote_address {
                            Some(remote_address) => {
                                match State::is_permitted_socket_address(remote_address) {
                                    true => None,
                                    false => Some(Decision::Denied(ErrorCode::AccessDenied)),
                                }
                            }
                            None => None,
                        },
                    }
                }
            },
        };

        if !matches!(decision, Some(Decision::Denied(_))) {
            if let latch::Operation::ResolveAddressStream((
                _,
                _,
                latch::ResolveAddressStreamOperation::ResolveNextAddressEntry(
                    latch::ResolveNextAddressEntryArgs { ip_address },
                ),
            )) = operation
            {
                State::permit_ip_address(ip_address)
            }
        }

        decision
    }
}

fn operation_map(operation: Operation) -> latch::Operation {
    match operation {
        Operation::IpNameLookup(ip_name_lookup_operation) => {
            latch::Operation::IpNameLookup(ip_name_lookup_operation_map(ip_name_lookup_operation))
        }
        Operation::ResolveAddressStream((
            resolve_address_stream,
            name,
            resolve_address_stream_operation,
        )) => latch::Operation::ResolveAddressStream((
            resolve_address_stream,
            name,
            resolve_address_stream_operation_map(resolve_address_stream_operation),
        )),
        Operation::TcpCreateSocket(tcp_create_socket_operation) => {
            latch::Operation::TcpCreateSocket(tcp_create_socket_operation_map(
                tcp_create_socket_operation,
            ))
        }
        Operation::TcpSocket((tcp_socket, tcp_socket_operation)) => latch::Operation::TcpSocket((
            tcp_socket,
            tcp_socket_operation_map(tcp_socket_operation),
        )),
        Operation::UdpCreateSocket(udp_create_socket_operation) => {
            latch::Operation::UdpCreateSocket(udp_create_socket_operation_map(
                udp_create_socket_operation,
            ))
        }
        Operation::UdpSocket((udp_socket, udp_socket_operation)) => latch::Operation::UdpSocket((
            udp_socket,
            udp_socket_operation_map(udp_socket_operation),
        )),
        Operation::UdpStreamIncomingDatagram(incoming_datagram_operation) => {
            latch::Operation::UdpStreamIncomingDatagram(incoming_datagram_operation_map(
                incoming_datagram_operation,
            ))
        }
        Operation::UdpStreamOutgoingDatagram(outgoing_datagram_operation) => {
            latch::Operation::UdpStreamOutgoingDatagram(outgoing_datagram_operation_map(
                outgoing_datagram_operation,
            ))
        }
    }
}

fn ip_name_lookup_operation_map(
    ip_name_lookup_operation: IpNameLookupOperation,
) -> latch::IpNameLookupOperation {
    match ip_name_lookup_operation {
        IpNameLookupOperation::ResolveAddresses(resolve_addresses_args) => {
            latch::IpNameLookupOperation::ResolveAddresses(resolve_addresses_args_map(
                resolve_addresses_args,
            ))
        }
    }
}

fn resolve_addresses_args_map(args: ResolveAddressesArgs) -> latch::ResolveAddressesArgs {
    latch::ResolveAddressesArgs {
        network: args.network,
        name: args.name,
    }
}

fn resolve_address_stream_operation_map(
    resolve_address_stream_operation: ResolveAddressStreamOperation,
) -> latch::ResolveAddressStreamOperation {
    match resolve_address_stream_operation {
        ResolveAddressStreamOperation::ResolveNextAddressEntry(resolve_next_address_entry_args) => {
            latch::ResolveAddressStreamOperation::ResolveNextAddressEntry(
                resolve_next_address_entry_args_map(resolve_next_address_entry_args),
            )
        }
    }
}

fn resolve_next_address_entry_args_map(
    args: ResolveNextAddressEntryArgs,
) -> latch::ResolveNextAddressEntryArgs {
    latch::ResolveNextAddressEntryArgs {
        ip_address: args.ip_address,
    }
}

fn tcp_create_socket_operation_map(
    tcp_create_socket_operation: TcpCreateSocketOperation,
) -> latch::TcpCreateSocketOperation {
    match tcp_create_socket_operation {
        TcpCreateSocketOperation::CreateTcpSocket(create_tcp_socket_args) => {
            latch::TcpCreateSocketOperation::CreateTcpSocket(create_tcp_socket_args_map(
                create_tcp_socket_args,
            ))
        }
    }
}

fn create_tcp_socket_args_map(args: CreateTcpSocketArgs) -> latch::CreateTcpSocketArgs {
    latch::CreateTcpSocketArgs {
        address_family: args.address_family,
    }
}

fn tcp_socket_operation_map(tcp_socket_operation: TcpSocketOperation) -> latch::TcpSocketOperation {
    match tcp_socket_operation {
        TcpSocketOperation::StartBind(start_bind_args) => {
            latch::TcpSocketOperation::StartBind(start_bind_args_map(start_bind_args))
        }
        TcpSocketOperation::StartConnect(start_connect_args) => {
            latch::TcpSocketOperation::StartConnect(start_connect_args_map(start_connect_args))
        }
    }
}

fn start_bind_args_map(args: StartBindArgs) -> latch::StartBindArgs {
    latch::StartBindArgs {
        network: args.network,
        local_address: args.local_address,
    }
}

fn start_connect_args_map(args: StartConnectArgs) -> latch::StartConnectArgs {
    latch::StartConnectArgs {
        network: args.network,
        remote_address: args.remote_address,
    }
}

fn udp_create_socket_operation_map(
    udp_create_socket_operation: UdpCreateSocketOperation,
) -> latch::UdpCreateSocketOperation {
    match udp_create_socket_operation {
        UdpCreateSocketOperation::CreateUdpSocket(create_udp_socket_args) => {
            latch::UdpCreateSocketOperation::CreateUdpSocket(create_udp_socket_args_map(
                create_udp_socket_args,
            ))
        }
    }
}

fn create_udp_socket_args_map(args: CreateUdpSocketArgs) -> latch::CreateUdpSocketArgs {
    latch::CreateUdpSocketArgs {
        address_family: args.address_family,
    }
}

fn udp_socket_operation_map(udp_socket_operation: UdpSocketOperation) -> latch::UdpSocketOperation {
    match udp_socket_operation {
        UdpSocketOperation::StartBind(start_bind_args) => {
            latch::UdpSocketOperation::StartBind(start_bind_args_map(start_bind_args))
        }
        UdpSocketOperation::Stream(stream_args) => {
            latch::UdpSocketOperation::Stream(stream_args_map(stream_args))
        }
    }
}

fn stream_args_map(args: StreamArgs) -> latch::StreamArgs {
    latch::StreamArgs {
        remote_address: args.remote_address,
    }
}

fn incoming_datagram_operation_map(
    incoming_datagram_operation: IncomingDatagramOperation,
) -> latch::IncomingDatagramOperation {
    match incoming_datagram_operation {
        IncomingDatagramOperation::ReceiveIncomingDatagram(receive_incoming_datagram_args) => {
            latch::IncomingDatagramOperation::ReceiveIncomingDatagram(
                receive_incoming_datagram_args_map(receive_incoming_datagram_args),
            )
        }
    }
}

fn receive_incoming_datagram_args_map(
    args: ReceiveIncomingDatagramArgs,
) -> latch::ReceiveIncomingDatagramArgs {
    latch::ReceiveIncomingDatagramArgs {
        remote_address: args.remote_address,
        data_length: args.data_length,
    }
}

fn outgoing_datagram_operation_map(
    outgoing_datagram_operation: OutgoingDatagramOperation,
) -> latch::OutgoingDatagramOperation {
    match outgoing_datagram_operation {
        OutgoingDatagramOperation::SendOutgoingDatagram(send_outgoing_datagram_args) => {
            latch::OutgoingDatagramOperation::SendOutgoingDatagram(send_outgoing_datagram_args_map(
                send_outgoing_datagram_args,
            ))
        }
    }
}

fn send_outgoing_datagram_args_map(
    args: SendOutgoingDatagramArgs,
) -> latch::SendOutgoingDatagramArgs {
    latch::SendOutgoingDatagramArgs {
        remote_address: args.remote_address,
        data_length: args.data_length,
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
