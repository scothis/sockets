#![no_main]

use crate::exports::componentized::sockets::latch::{Decision, Guest as Latch, Operation};

struct AbstainAllLatch {}

impl Latch for AbstainAllLatch {
    fn authorize(_: Operation) -> Option<Decision> {
        None
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    generate_all
});

export!(AbstainAllLatch);
