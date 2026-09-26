#![cfg_attr(not(test), no_main)]

use path_matchers::{glob, PathMatcher};
use std::path::Path;

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpNameLookupOperation, Operation, SocketsErrorCode,
};

struct GlobIpNameLookupLatch {}

struct Patterns {
    initialized: bool,
    denies: Option<Vec<Box<dyn PathMatcher>>>,
    grants: Option<Vec<Box<dyn PathMatcher>>>,
    deny_reason: Option<SocketsErrorCode>,
    default: Decision,
}

impl Patterns {
    fn initialize() {
        if unsafe { STATE.initialized } {
            return;
        }

        let mut denies: Vec<Box<dyn PathMatcher>> = vec![];
        let mut grants: Vec<Box<dyn PathMatcher>> = vec![];
        let mut reason = SocketsErrorCode::AccessDenied;
        let mut default = Decision::Abstained;

        for (key, value) in wasi::config::store::get_all().expect("config must be available") {
            if key.starts_with("deny") {
                let value = value.replace(".", "/").to_lowercase();
                denies.push(Box::new(
                    glob(&value).expect("config value must parse as a glob"),
                ));
            } else if key.starts_with("grant") {
                let value = value.replace(".", "/").to_lowercase();
                grants.push(Box::new(
                    glob(&value).expect("config value must parse as a glob"),
                ));
            } else if key == "reason" {
                reason = get_error_code(value).unwrap_or(SocketsErrorCode::AccessDenied);
                if let Decision::Abstained = default {
                    default = Decision::Denied(reason.clone())
                }
            } else if key == "default" {
                default = match value.as_str() {
                    "deny" => Decision::Denied(reason.clone()),
                    "abstain" => Decision::Abstained,
                    _ => panic!("unknown default value: {value}, expected 'deny' or 'abstain'"),
                }
            }
        }

        unsafe {
            STATE.denies = Some(denies);
            STATE.grants = Some(grants);
            STATE.deny_reason = Some(reason);
            STATE.default = default;
            STATE.initialized = true;
        };
    }

    #[allow(static_mut_refs)]
    fn authorize(name: String) -> Result<Decision, ErrorCode> {
        let decision = unsafe { STATE.authorize_name(name) };
        if matches!(decision, Ok(Decision::Denied(_))) {
            return decision;
        }
        unsafe { Ok(STATE.default.clone()) }
    }

    fn authorize_name(&self, name: String) -> Result<Decision, ErrorCode> {
        let name = name.replace(".", "/").to_lowercase();
        let name = Path::new(&name);

        for deny in self.denies.as_ref().unwrap() {
            if deny.matches(name) {
                return Ok(Decision::Denied(self.deny_reason.clone().unwrap()));
            }
        }
        Ok(Decision::Abstained)
    }
}

static mut STATE: Patterns = Patterns {
    initialized: false,
    denies: None,
    grants: None,
    deny_reason: None,
    default: Decision::Abstained,
};

impl Latch for GlobIpNameLookupLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        Patterns::initialize();

        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(resolve_addresses_args) => {
                    Patterns::authorize(resolve_addresses_args.name)
                }
                IpNameLookupOperation::ResolveAddressesReturn(_) => Ok(Decision::Abstained),
            },
            _ => Ok(Decision::Abstained),
        }
    }
}

fn get_error_code(value: String) -> Option<SocketsErrorCode> {
    match value.as_str() {
        "" => None,
        "access-denied" => Some(SocketsErrorCode::AccessDenied),
        "invalid-argument" => Some(SocketsErrorCode::InvalidArgument),
        "other" => Some(SocketsErrorCode::Other(None)),
        _ => Some(SocketsErrorCode::Other(Some(value))),
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(GlobIpNameLookupLatch);
