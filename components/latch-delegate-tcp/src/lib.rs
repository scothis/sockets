use sockets_latch::wrapped as latch;
use sockets_latch::{Decision, ErrorCode, Latch, Operation};

struct DelegateTcpLatch {}

/// Only tcp socket operations reach the wrapped latch.
fn is_delegated(operation: &Operation) -> bool {
    matches!(operation, Operation::TcpSocket(_))
}

impl Latch for DelegateTcpLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match is_delegated(&operation) {
            true => latch::authorize(&operation),
            false => Ok(Decision::Deferred),
        }
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // the wrapped latch only observes the operations it was asked to authorize
        match is_delegated(&operation) {
            true => latch::observe_decision(&final_decision, &operation),
            false => Ok(()),
        }
    }
}

sockets_latch::export!(DelegateTcpLatch with_types_in sockets_latch::bindings);
