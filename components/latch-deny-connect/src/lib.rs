use sockets_latch::{
    Decision, ErrorCode, Latch, Operation, SocketsErrorCode, TcpSocketOperation, UdpSocketOperation,
};

struct DenyConnectLatch {}

impl Latch for DenyConnectLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::TcpSocket(tcp_socket_operation) => match tcp_socket_operation {
                TcpSocketOperation::Connect(_) => {
                    Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                }
                _ => Ok(Decision::Abstained),
            },
            Operation::UdpSocket(udp_socket_operation) => match udp_socket_operation {
                UdpSocketOperation::Connect(_) => {
                    Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
                }
                _ => Ok(Decision::Abstained),
            },
            _ => Ok(Decision::Abstained),
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

sockets_latch::export!(DenyConnectLatch with_types_in sockets_latch::bindings);
