use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, Operation, SocketsErrorCode,
};

struct DenyUdpLatch {}

impl Latch for DenyUdpLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        match operation {
            Operation::IpNameLookup(_) => Ok(Decision::Abstained),
            Operation::TcpSocket(_) => Ok(Decision::Abstained),
            Operation::UdpSocket(_) => Ok(Decision::Denied(SocketsErrorCode::AccessDenied)),
        }
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

export!(DenyUdpLatch);
