use sockets_latch::{Decision, ErrorCode, Latch, Operation, SocketsErrorCode};

struct DenyAllLatch {}

impl Latch for DenyAllLatch {
    fn authorize(_: Operation) -> Result<Decision, ErrorCode> {
        Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

sockets_latch::export!(DenyAllLatch with_types_in sockets_latch::bindings);
