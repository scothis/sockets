use crate::{
    exports::wasi::sockets::ip_name_lookup::{ErrorCode, Guest},
    wasi::{
        logging::logging::{Level, log},
        sockets::{ip_name_lookup, types},
    },
};

macro_rules! trace {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Trace, "componentized-trace", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Trace, "componentized-trace", &format!($dst));
    };
}

#[derive(Debug, Clone)]
struct TracedIpNameLookup {}

impl Guest for TracedIpNameLookup {
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
        trace!("OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={name}");
        ip_name_lookup::resolve_addresses(name).await
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "traced-ip-name-lookup",
    merge_structurally_equal_types: true,
    generate_all
});

export!(TracedIpNameLookup);
