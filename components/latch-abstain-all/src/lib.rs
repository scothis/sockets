#![no_main]

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation,
};

struct AbstainAllLatch {}

impl Latch for AbstainAllLatch {
    fn authorize(_: Operation) -> Result<Decision, ErrorCode> {
        Ok(Decision::Abstained)
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(AbstainAllLatch);
