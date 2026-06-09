#![no_main]

use std::fmt::Display;

use crate::componentized::sockets::latch::{
    self, authorize, Decision::Denied, IpNameLookupOperation, Operation, ResolveAddressesArgs,
    ResolveAddressesReturnsItem,
};
use crate::exports::wasi::sockets::ip_name_lookup::{ErrorCode, Guest};
use crate::wasi::logging::logging::{log, Level};
use crate::wasi::sockets::{ip_name_lookup, types};

macro_rules! warn {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Warn, "componentized-gate", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Warn, "componentized-gate", &format!($dst));
    };
}

macro_rules! trace {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Trace, "componentized-gate", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Trace, "componentized-gate", &format!($dst));
    };
}

#[derive(Debug, Clone)]
struct GatedIpNameLookup {}

impl Guest for GatedIpNameLookup {
    #[doc = "/ Resolve an internet host name to a list of IP addresses."]
    #[doc = "/"]
    #[doc = "/ Unicode domain names are automatically converted to ASCII using IDNA"]
    #[doc = "/ encoding. If the input is an IP address string, the address is parsed"]
    #[doc = "/ and returned as-is without making any external requests."]
    #[doc = "/"]
    #[doc = "/ See the wasi-socket proposal README.md for a comparison with getaddrinfo."]
    #[doc = "/"]
    #[doc = "/ The results are returned in connection order preference."]
    #[doc = "/"]
    #[doc = "/ This function never succeeds with 0 results. It either fails or succeeds"]
    #[doc = "/ with at least one address. Additionally, this function never returns"]
    #[doc = "/ IPv4-mapped IPv6 addresses."]
    #[doc = "/"]
    #[doc = "/ # References:"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getaddrinfo.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man3/getaddrinfo.3.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=getaddrinfo&sektion=3>"]
    #[allow(async_fn_in_trait)]
    async fn resolve_addresses(name: String) -> Result<Vec<types::IpAddress>, ErrorCode> {
        match authorize(&Operation::IpNameLookup(
            IpNameLookupOperation::ResolveAddresses(ResolveAddressesArgs { name: name.clone() }),
        )) {
            Some(Denied(code)) => {
                warn!("Denied REASON={code} OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={name}");
                Err(code.into())
            }
            _ => ip_name_lookup::resolve_addresses(name.clone())
                .await
                .map(|addresses| 
                    addresses
                        .into_iter()
                        .filter(|ip_address| match authorize(
                            &Operation::IpNameLookup(IpNameLookupOperation::ResolveAddressesReturn(ResolveAddressesReturnsItem { ip_address: *ip_address }))
                        ) {
                            Some(Denied(code)) => {
                                trace!("Denied REASON={code} OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={name}");
                                false
                            }
                            _ => true,
                        })
                        .collect()
                ),
        }
    }
}

impl From<latch::ErrorCode> for ErrorCode {
    fn from(value: latch::ErrorCode) -> Self {
        match value {
            latch::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
            latch::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
            latch::ErrorCode::Other(error) => ErrorCode::Other(error),
        }
    }
}

impl Display for latch::ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}",
            match self {
                latch::ErrorCode::AccessDenied => "access-denied".to_string(),
                latch::ErrorCode::InvalidArgument => "invalid-argument".to_string(),
                latch::ErrorCode::Other(None) => "other".to_string(),
                latch::ErrorCode::Other(Some(error_code)) => format!("other<{error_code}>"),
            }
        ))
    }
}



wit_bindgen::generate!({
    path: "../../wit",
    world: "gated-ip-name-lookup",
    merge_structurally_equal_types: true,
    generate_all
});

export!(GatedIpNameLookup);
