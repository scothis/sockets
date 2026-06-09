#![no_main]

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, TcpSocketOperation, UdpSocketOperation,
};

struct DenyConnectLatch {}

impl Latch for DenyConnectLatch {
    fn authorize(operation: Operation) -> Option<Decision> {
        match operation {
            Operation::IpNameLookup(_) => None,
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(_) => None,
                TcpSocketOperation::Bind(_) => None,
                TcpSocketOperation::Connect(_) => Some(Decision::Denied(ErrorCode::AccessDenied)),
                TcpSocketOperation::Listen(_) => todo!(),
                TcpSocketOperation::ListenConnection(_) => todo!(),
                TcpSocketOperation::Send(_) => todo!(),
                TcpSocketOperation::Receive(_) => todo!(),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(_) => None,
                UdpSocketOperation::Bind(_) => None,
                UdpSocketOperation::Connect(_) => Some(Decision::Denied(ErrorCode::AccessDenied)),
                UdpSocketOperation::Send(_) => None,
                UdpSocketOperation::Receive(_) => None,
            },
        }
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DenyConnectLatch);
