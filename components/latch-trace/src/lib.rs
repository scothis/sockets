use core::fmt;

use sockets_latch::{Decision, DisplayError, ErrorCode, Latch, Operation, wrapped as latch};

struct TraceLatch {}

impl Latch for TraceLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        // the wrapped latch decides, its decision is logged and returned unchanged
        let result = latch::authorize(&operation);
        match &result {
            Ok(decision) => {
                sockets_latch::trace!("Authorization {} {operation}", DisplayDecision(decision));
            }
            Err(err) => {
                sockets_latch::trace!("Authorization ERROR={} {operation}", DisplayError(err));
            }
        }
        result
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        latch::observe_decision(&final_decision, &operation)
    }
}

/// Displays a decision, e.g. `DECISION=denied REASON=access-denied`.
struct DisplayDecision<'a>(&'a Decision);

impl fmt::Display for DisplayDecision<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Decision::Deferred => f.write_str("DECISION=deferred"),
            Decision::Denied(reason) => write!(f, "DECISION=denied REASON={reason}"),
        }
    }
}

sockets_latch::export!(TraceLatch with_types_in sockets_latch::bindings);
