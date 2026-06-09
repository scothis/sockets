#![no_main]

use crate::exports::componentized::sockets::latch::{Decision, Guest as Latch, Operation};

struct PermitAllLatch {}

impl Latch for PermitAllLatch {
    fn authorize(_: Operation) -> Option<Decision> {
        Some(Decision::Permitted)
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(PermitAllLatch);
