#![no_main]

use latch_n::bindings::componentized::sockets::latch as latch0;
use latch_n::bindings::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation,
};
use latch_n::bindings::latch1;

struct LatchN2 {}

impl Latch for LatchN2 {
    #[allow(async_fn_in_trait)]
    fn authorize(operation: Operation<'_>) -> Result<Decision, ErrorCode> {
        let authorizers = vec![latch0::authorize, latch1::authorize];
        latch_n::authorize(operation, authorizers)
    }
}

latch_n::export!(LatchN2 with_types_in latch_n::bindings);
