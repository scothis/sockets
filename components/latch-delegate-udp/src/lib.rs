use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation,
};

struct DelegateUdpLatch {}

/// Only udp socket operations reach the wrapped latch.
fn is_delegated(operation: &Operation) -> bool {
    matches!(operation, Operation::UdpSocket(_))
}

impl Latch for DelegateUdpLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match is_delegated(&operation) {
            true => latch::authorize(&operation),
            false => Ok(Decision::Abstained),
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

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DelegateUdpLatch);
