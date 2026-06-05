#![no_main]

use crate::{
    exports::componentized::sockets::latch::{Decision, Guest as Latch, Operation},
    wasi::sockets::network::ErrorCode,
};

struct DenyAllLatch {}

impl Latch for DenyAllLatch {
    fn authorize(_: Operation) -> Option<Decision> {
        Some(Decision::Denied(ErrorCode::NotSupported))
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    generate_all
});

export!(DenyAllLatch);
