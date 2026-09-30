use sockets_latch::{Decision, ErrorCode, Latch, Operation, SocketsErrorCode};

struct DenyUdpLatch {}

impl Latch for DenyUdpLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::UdpSocket(_) => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
            _ => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

sockets_latch::export!(DenyUdpLatch with_types_in sockets_latch::bindings);
