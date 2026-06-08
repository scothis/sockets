#![no_main]

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, TcpSocketOperation, UdpSocketOperation,
};

struct DenyBindLatch {}

impl Latch for DenyBindLatch {
    fn authorize(operation: Operation) -> Option<Decision> {
        match operation {
            Operation::IpNameLookup(_) => None,
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(_) => todo!(),
                TcpSocketOperation::Bind(_) => Some(Decision::Denied(ErrorCode::AccessDenied)),
                TcpSocketOperation::Connect(_) => None,
                TcpSocketOperation::Listen(_) => todo!(),
                TcpSocketOperation::ListenConnection(_) => todo!(),
                TcpSocketOperation::Send(_) => todo!(),
                TcpSocketOperation::Receive(_) => todo!(),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(_) => None,
                UdpSocketOperation::Bind(_) => Some(Decision::Denied(ErrorCode::AccessDenied)),
                UdpSocketOperation::Connect(_) => None,
                UdpSocketOperation::Send(_) => None,
                UdpSocketOperation::Receive(_) => None,
            },
        }
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    generate_all
});

export!(DenyBindLatch);
