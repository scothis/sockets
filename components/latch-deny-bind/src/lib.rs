#![no_main]

use crate::{
    exports::componentized::sockets::latch::{
        Decision, Guest as Latch, Operation, TcpSocketOperation, UdpSocketOperation,
    },
    wasi::sockets::network::ErrorCode,
};

struct DenyConnectLatch {}

impl Latch for DenyConnectLatch {
    fn authorize(operation: Operation) -> Option<Decision> {
        match operation {
            Operation::IpNameLookup(_) => None,
            Operation::ResolveAddressStream(_) => None,
            Operation::TcpCreateSocket(_) => None,
            Operation::TcpSocket((_, tcp_socket_operation)) => match tcp_socket_operation {
                TcpSocketOperation::StartBind(_) => Some(Decision::Denied(ErrorCode::NotSupported)),
                TcpSocketOperation::StartConnect(_) => None,
            },
            Operation::UdpCreateSocket(_) => None,
            Operation::UdpSocket((_, udp_socket_operation)) => match udp_socket_operation {
                UdpSocketOperation::StartBind(_) => Some(Decision::Denied(ErrorCode::NotSupported)),
                UdpSocketOperation::Stream(stream_args) => match stream_args.remote_address {
                    Some(_) => None,
                    None => Some(Decision::Denied(ErrorCode::NotSupported)),
                },
            },
            Operation::UdpStreamIncomingDatagram(_) => None,
            Operation::UdpStreamOutgoingDatagram(_) => None,
        }
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    generate_all
});

export!(DenyConnectLatch);
