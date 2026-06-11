#![no_main]

use crate::bindings::{
    componentized::sockets::latch,
    exports::componentized::sockets::latch::{Decision, Operation},
};

pub fn authorize(
    operation: Operation,
    authorizers: Vec<fn(&latch::Operation<'_>) -> Option<latch::Decision>>,
) -> Option<Decision> {
    let operation = operation.into();
    for authorize in authorizers {
        match authorize(&operation) {
            None => {}
            Some(latch::Decision::Granted) => return Some(Decision::Granted),
            Some(latch::Decision::Denied(error_code)) => {
                return Some(Decision::Denied(error_code.into()))
            }
        }
    }
    None
}

pub mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "sockets-latch-n",
        pub_export_macro: true,
        merge_structurally_equal_types: true,
        generate_all
    });
}

#[macro_export]
macro_rules! export {
    ($($t:tt)*) => {
        $crate::bindings::export!($($t)*);
    };
}
