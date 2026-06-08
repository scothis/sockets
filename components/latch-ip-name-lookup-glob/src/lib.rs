#![no_main]

use path_matchers::{glob, PathMatcher};
use std::path::Path;

use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpNameLookupOperation, Operation,
};

struct GlobIpNameLookupLatch {}

struct Patterns {
    initialized: bool,
    denies: Option<Vec<Box<dyn PathMatcher>>>,
    permits: Option<Vec<Box<dyn PathMatcher>>>,
    deny_reason: Option<ErrorCode>,
    default: Option<Decision>,
}

impl Patterns {
    fn initialize() {
        if unsafe { STATE.initialized } {
            return;
        }

        let mut denies: Vec<Box<dyn PathMatcher>> = vec![];
        let mut permits: Vec<Box<dyn PathMatcher>> = vec![];
        let mut reason = ErrorCode::AccessDenied;
        let mut default = None;

        for (key, value) in wasi::config::store::get_all().expect("config must be available") {
            if key.starts_with("deny") {
                let value = value.replace(".", "/").to_lowercase();
                denies.push(Box::new(
                    glob(&value).expect("config value must parse as a glob"),
                ));
            } else if key.starts_with("permit") {
                let value = value.replace(".", "/").to_lowercase();
                permits.push(Box::new(
                    glob(&value).expect("config value must parse as a glob"),
                ));
            } else if key == "reason" {
                reason = get_error_code(value).unwrap_or(ErrorCode::AccessDenied);
                if let Some(Decision::Denied(_)) = default {
                    default = Some(Decision::Denied(reason.clone()))
                }
            } else if key == "default" {
                default = match value.as_str() {
                    "deny" => Some(Decision::Denied(reason.clone())),
                    "permit" => Some(Decision::Permitted),
                    _ => None,
                }
            }
        }

        unsafe {
            STATE.denies = Some(denies);
            STATE.permits = Some(permits);
            STATE.deny_reason = Some(reason);
            STATE.default = default;
            STATE.initialized = true;
        };
    }

    #[allow(static_mut_refs)]
    fn authorize(name: String) -> Option<Decision> {
        let decision = unsafe { STATE.authorize_name(name) };
        if decision.is_some() {
            return decision;
        }
        unsafe { STATE.default.clone() }
    }

    fn authorize_name(&self, name: String) -> Option<Decision> {
        let name = name.replace(".", "/").to_lowercase();
        let name = Path::new(&name);

        for deny in self.denies.as_ref().unwrap() {
            if deny.matches(name) {
                return Some(Decision::Denied(self.deny_reason.clone().unwrap()));
            }
        }
        for permit in self.permits.as_ref().unwrap() {
            if permit.matches(name) {
                return Some(Decision::Permitted);
            }
        }
        None
    }
}

static mut STATE: Patterns = Patterns {
    initialized: false,
    denies: None,
    permits: None,
    deny_reason: None,
    default: None,
};

impl Latch for GlobIpNameLookupLatch {
    fn authorize(operation: Operation) -> Option<Decision> {
        Patterns::initialize();

        match operation {
            Operation::IpNameLookup(ip_name_lookup_operation) => match ip_name_lookup_operation {
                IpNameLookupOperation::ResolveAddresses(resolve_addresses_args) => {
                    Patterns::authorize(resolve_addresses_args.name)
                }
                IpNameLookupOperation::ResolveAddressesReturn(_) => None,
            },
            _ => None,
        }
    }
}

fn get_error_code(value: String) -> Option<ErrorCode> {
    match value.as_str() {
        "" => None,
        "access-denied" => Some(ErrorCode::AccessDenied),
        "invalid-argument" => Some(ErrorCode::InvalidArgument),
        "other" => Some(ErrorCode::Other(None)),
        _ => Some(ErrorCode::Other(Some(value))),
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "sockets-latch",
    generate_all
});

export!(GlobIpNameLookupLatch);
