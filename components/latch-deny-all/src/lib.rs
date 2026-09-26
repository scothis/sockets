#![cfg_attr(not(test), no_main)]

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, SocketsErrorCode,
};

struct DenyAllLatch {}

impl Latch for DenyAllLatch {
    fn authorize(_: Operation) -> Result<Decision, ErrorCode> {
        Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DenyAllLatch);
