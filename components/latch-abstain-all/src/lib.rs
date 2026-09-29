use sockets_latch::{Decision, ErrorCode, Latch, Operation};

struct AbstainAllLatch {}

impl Latch for AbstainAllLatch {
    fn authorize(_: Operation) -> Result<Decision, ErrorCode> {
        Ok(Decision::Abstained)
    }

    fn observe_decision(_final_decision: Decision, _operation: Operation) -> Result<(), ErrorCode> {
        // no side effects
        Ok(())
    }
}

sockets_latch::export!(AbstainAllLatch with_types_in sockets_latch::bindings);
