#![no_main]

use crate::componentized::sockets::latch::{
    self, authorize, Decision::Denied, IpNameLookupOperation, Operation, ResolveAddressesArgs,
    ResolveAddressesReturnsItem,
};
use crate::exports::wasi::sockets::ip_name_lookup::{ErrorCode, Guest, IpAddress};
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
                let reason = error_code_display(code.clone());
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={name}");
                Err(latch_error_code_map(code))
            }
            _ => ip_name_lookup::resolve_addresses(name.clone())
                .await
                .map_err(ip_name_lookup_error_code_map)
                .map(|addresses| 
                    addresses
                        .iter()
                        .filter(|ip_address| match authorize(
                            &Operation::IpNameLookup(IpNameLookupOperation::ResolveAddressesReturn(ResolveAddressesReturnsItem { ip_address: **ip_address }))
                        ) {
                            Some(Denied(code)) => {
                                let reason = error_code_display(code);
                                trace!("Denied REASON={reason} OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={name}");
                                false
                            }
                            _ => true,
                        })
                        .map(|ip_address| ip_address_map(*ip_address))
                        .collect()
                ),
        }
    }
}

fn ip_address_map(ip_address: types::IpAddress) -> IpAddress {
    match ip_address {
        types::IpAddress::Ipv4(v4) => IpAddress::Ipv4(v4),
        types::IpAddress::Ipv6(v6) => IpAddress::Ipv6(v6),
    }
}

fn latch_error_code_map(error_code: latch::ErrorCode) -> ErrorCode {
    match error_code {
        latch::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
        latch::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        latch::ErrorCode::Other(error) => ErrorCode::Other(error),
    }
}

fn ip_name_lookup_error_code_map(error_code: ip_name_lookup::ErrorCode) -> ErrorCode {
    match error_code {
        ip_name_lookup::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
        ip_name_lookup::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        ip_name_lookup::ErrorCode::NameUnresolvable => ErrorCode::NameUnresolvable,
        ip_name_lookup::ErrorCode::TemporaryResolverFailure => ErrorCode::TemporaryResolverFailure,
        ip_name_lookup::ErrorCode::PermanentResolverFailure => ErrorCode::PermanentResolverFailure,
        ip_name_lookup::ErrorCode::Other(error) => ErrorCode::Other(error.clone()),
    }
}

fn error_code_display(error_code: latch::ErrorCode) -> String {
    match error_code {
        latch::ErrorCode::AccessDenied => format!("access-denied"),
        latch::ErrorCode::InvalidArgument => format!("invalid-argument"),
        latch::ErrorCode::Other(error) => match error {
            Some(error) => format!("other<{error}>"),
            None => format!("other"),
        },
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "gated-ip-name-lookup",
    generate_all
});

export!(GatedIpNameLookup);
