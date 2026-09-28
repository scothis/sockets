use crate::bindings::exports::componentized::sockets::latch::{Decision, ErrorCode, Operation};

pub fn authorize(
    operation: Operation,
    authorizers: Vec<fn(&Operation<'_>) -> Result<Decision, ErrorCode>>,
) -> Result<Decision, ErrorCode> {
    for authorize in authorizers {
        match authorize(&operation)? {
            Decision::Abstained => {}
            Decision::Denied(error_code) => return Ok(Decision::Denied(error_code)),
        }
    }
    Ok(Decision::Abstained)
}

/// Pass the final decision to every nested latch, including latches that were not asked to
/// authorize the operation because an earlier latch denied it.
///
/// Every observer is called even if an earlier one fails, the result is the first error.
pub fn observe_decision(
    final_decision: Decision,
    operation: Operation,
    observers: Vec<fn(&Decision, &Operation<'_>) -> Result<(), ErrorCode>>,
) -> Result<(), ErrorCode> {
    let mut result = Ok(());
    for observe in observers {
        if let Err(err) = observe(&final_decision, &operation) {
            if result.is_ok() {
                result = Err(err);
            }
        }
    }
    result
}

pub mod bindings {
    wit_bindgen::generate!({
        path: "../../components/wit",
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
