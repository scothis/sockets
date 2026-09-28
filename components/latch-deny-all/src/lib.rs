use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, SocketsErrorCode,
};

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

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DenyAllLatch);
