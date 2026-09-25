#![no_main]

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, SocketsErrorCode, TcpSocketOperation,
    UdpSocketOperation,
};

struct DenyConnectLatch {}

impl Latch for DenyConnectLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(_) => Ok(Decision::Abstained),
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Create(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Bind(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Connect(_) => {
                    Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                }
                TcpSocketOperation::Listen(_) => Ok(Decision::Abstained),
                TcpSocketOperation::ListenConnection(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Send(_) => Ok(Decision::Abstained),
                TcpSocketOperation::Receive(_) => Ok(Decision::Abstained),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Create(_) => Ok(Decision::Abstained),
                UdpSocketOperation::Bind(_) => Ok(Decision::Abstained),
                UdpSocketOperation::Connect(_) => {
                    Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                }
                UdpSocketOperation::Send(_) => Ok(Decision::Abstained),
                UdpSocketOperation::Receive(_) => Ok(Decision::Abstained),
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

export!(DenyConnectLatch);
