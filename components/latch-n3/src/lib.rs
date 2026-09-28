use latch_n::bindings::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation,
};
use latch_n::bindings::{latch0, latch1, latch2};

struct LatchN3 {}

impl Latch for LatchN3 {
    #[allow(async_fn_in_trait)]
    fn authorize(operation: Operation<'_>) -> Result<Decision, ErrorCode> {
        let authorizers = vec![latch0::authorize, latch1::authorize, latch2::authorize];
        latch_n::authorize(operation, authorizers)
    }

    fn observe_decision(
        final_decision: Decision,
        operation: Operation<'_>,
    ) -> Result<(), ErrorCode> {
        let observers = vec![
            latch0::observe_decision,
            latch1::observe_decision,
            latch2::observe_decision,
        ];
        latch_n::observe_decision(final_decision, operation, observers)
    }
}

latch_n::export!(LatchN3 with_types_in latch_n::bindings);
