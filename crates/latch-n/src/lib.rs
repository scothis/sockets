#![no_main]

use crate::bindings::{
    componentized::sockets::latch,
    exports::componentized::sockets::latch::{
        CreateTcpSocketArgs, CreateUdpSocketArgs, Decision, IncomingDatagramOperation,
        IpNameLookupOperation, Operation, OutgoingDatagramOperation, ReceiveIncomingDatagramArgs,
        ResolveAddressStreamOperation, ResolveAddressesArgs, ResolveNextAddressEntryArgs,
        SendOutgoingDatagramArgs, StartBindArgs, StartConnectArgs, StreamArgs,
        TcpCreateSocketOperation, TcpSocketOperation, UdpCreateSocketOperation, UdpSocketOperation,
    },
};

pub fn authorize(
    operation: Operation,
    authorizers: Vec<fn(&latch::Operation<'_>) -> Option<latch::Decision>>,
) -> Option<Decision> {
    let operation = operation_map(operation);
    for authorize in authorizers {
        match authorize(&operation) {
            None => {}
            Some(latch::Decision::Permitted) => return Some(Decision::Permitted),
            Some(latch::Decision::Denied(error_code)) => return Some(Decision::Denied(error_code)),
        }
    }
    None
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
