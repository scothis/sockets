#![no_main]

use std::rc::Rc;

use heck::ToKebabCase;

use crate::componentized::sockets::latch::{
    authorize, Decision::Denied, IpNameLookupOperation, Operation, ResolveAddressStreamOperation,
    ResolveAddressesArgs, ResolveNextAddressEntryArgs,
};
use crate::exports::wasi::sockets::ip_name_lookup::{
    ErrorCode, Guest, GuestResolveAddressStream, Network, ResolveAddressStream,
};
use crate::wasi::io::poll::Pollable;
use crate::wasi::logging::logging::{log, Level};
use crate::wasi::sockets::network::IpAddress;
use crate::wasi::sockets::{ip_name_lookup, network};

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
    type ResolveAddressStream = GatedResolveAddressStream;

    #[doc = " Resolve an internet host name to a list of IP addresses."]
    #[doc = ""]
    #[doc = " Unicode domain names are automatically converted to ASCII using IDNA encoding."]
    #[doc = " If the input is an IP address string, the address is parsed and returned"]
    #[doc = " as-is without making any external requests."]
    #[doc = ""]
    #[doc = " See the wasi-socket proposal README.md for a comparison with getaddrinfo."]
    #[doc = ""]
    #[doc = " This function never blocks. It either immediately fails or immediately"]
    #[doc = " returns successfully with a `resolve-address-stream` that can be used"]
    #[doc = " to (asynchronously) fetch the results."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`: `name` is a syntactically invalid domain name or IP address."]
    #[doc = ""]
    #[doc = " # References:"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getaddrinfo.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man3/getaddrinfo.3.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=getaddrinfo&sektion=3>"]
    #[allow(async_fn_in_trait)]
    fn resolve_addresses(
        network: &Network,
        name: String,
    ) -> Result<ResolveAddressStream, ErrorCode> {
        match authorize(&Operation::IpNameLookup(
            IpNameLookupOperation::ResolveAddresses(ResolveAddressesArgs {
                network,
                name: name.clone(),
            }),
        )) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NETWORK={network:?} NAME={name}");
                Err(error_code_map(code))
            }
            _ => ip_name_lookup::resolve_addresses(network, &name)
                .map(|ras| resolve_address_stream_map(ras, name))
                .map_err(error_code_map),
        }
    }
}

#[derive(Debug, Clone)]
struct GatedResolveAddressStream {
    ras: Rc<ip_name_lookup::ResolveAddressStream>,
    name: String,
}

impl GatedResolveAddressStream {
    fn new(ras: ip_name_lookup::ResolveAddressStream, name: String) -> Self {
        Self {
            ras: Rc::new(ras),
            name,
        }
    }
}

impl GuestResolveAddressStream for GatedResolveAddressStream {
    #[doc = " Returns the next address from the resolver."]
    #[doc = ""]
    #[doc = " This function should be called multiple times. On each call, it will"]
    #[doc = " return the next address in connection order preference. If all"]
    #[doc = " addresses have been exhausted, this function returns `none`."]
    #[doc = ""]
    #[doc = " This function never returns IPv4-mapped IPv6 addresses."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `name-unresolvable`:          Name does not exist or has no suitable associated IP addresses. (EAI_NONAME, EAI_NODATA, EAI_ADDRFAMILY)"]
    #[doc = " - `temporary-resolver-failure`: A temporary failure in name resolution occurred. (EAI_AGAIN)"]
    #[doc = " - `permanent-resolver-failure`: A permanent failure in name resolution occurred. (EAI_FAIL)"]
    #[doc = " - `would-block`:                A result is not available yet. (EWOULDBLOCK, EAGAIN)"]
    #[allow(async_fn_in_trait)]
    fn resolve_next_address(&self) -> Result<Option<IpAddress>, ErrorCode> {
        match self.ras.resolve_next_address() {
            Ok(Some(ip_address)) => {
                match authorize(&Operation::ResolveAddressStream((
                    &self.ras,
                    self.name.clone(),
                    ResolveAddressStreamOperation::ResolveNextAddressEntry(
                        ResolveNextAddressEntryArgs { ip_address },
                    ),
                ))) {
                    Some(Denied(code)) => {
                        let reason = error_code_display(code);
                        trace!("Denied REASON={reason} OPERATION=wasi:sockets/ip-name-lookup#resolve-address-stream.resolve-next-address-entry STREAM={self:?} IP-ADDRESS={ip_address:?}");
                        // continue reading the next entry transparently
                        self.resolve_next_address()
                    }
                    _ => Ok(Some(ip_address_map(ip_address))),
                }
            }
            Ok(None) => Ok(None),
            Err(code) => Err(error_code_map(code)),
        }
    }

    #[doc = " Create a `pollable` which will resolve once the stream is ready for I/O."]
    #[doc = ""]
    #[doc = " Note: this function is here for WASI 0.2 only."]
    #[doc = " It\'s planned to be removed when `future` is natively supported in Preview3."]
    #[allow(async_fn_in_trait)]
    fn subscribe(&self) -> Pollable {
        self.ras.subscribe()
    }
}

fn resolve_address_stream_map(
    resolve_address_stream: ip_name_lookup::ResolveAddressStream,
    name: String,
) -> ResolveAddressStream {
    ResolveAddressStream::new(GatedResolveAddressStream::new(resolve_address_stream, name))
}

fn ip_address_map(ip_address: network::IpAddress) -> IpAddress {
    match ip_address {
        network::IpAddress::Ipv4(v4) => IpAddress::Ipv4(v4),
        network::IpAddress::Ipv6(v6) => IpAddress::Ipv6(v6),
    }
}

fn error_code_map(error_code: network::ErrorCode) -> ErrorCode {
    match error_code {
        network::ErrorCode::Unknown => ErrorCode::Unknown,
        network::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
        network::ErrorCode::NotSupported => ErrorCode::NotSupported,
        network::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        network::ErrorCode::OutOfMemory => ErrorCode::OutOfMemory,
        network::ErrorCode::Timeout => ErrorCode::Timeout,
        network::ErrorCode::ConcurrencyConflict => ErrorCode::ConcurrencyConflict,
        network::ErrorCode::NotInProgress => ErrorCode::NotInProgress,
        network::ErrorCode::WouldBlock => ErrorCode::WouldBlock,
        network::ErrorCode::InvalidState => ErrorCode::InvalidState,
        network::ErrorCode::NewSocketLimit => ErrorCode::NewSocketLimit,
        network::ErrorCode::AddressNotBindable => ErrorCode::AddressNotBindable,
        network::ErrorCode::AddressInUse => ErrorCode::AddressInUse,
        network::ErrorCode::RemoteUnreachable => ErrorCode::RemoteUnreachable,
        network::ErrorCode::ConnectionRefused => ErrorCode::ConnectionRefused,
        network::ErrorCode::ConnectionReset => ErrorCode::ConnectionReset,
        network::ErrorCode::ConnectionAborted => ErrorCode::ConnectionAborted,
        network::ErrorCode::DatagramTooLarge => ErrorCode::DatagramTooLarge,
        network::ErrorCode::NameUnresolvable => ErrorCode::NameUnresolvable,
        network::ErrorCode::TemporaryResolverFailure => ErrorCode::TemporaryResolverFailure,
        network::ErrorCode::PermanentResolverFailure => ErrorCode::PermanentResolverFailure,
    }
}

fn error_code_display(error_code: network::ErrorCode) -> String {
    error_code
        .to_string()
        .splitn(2, ' ')
        .next()
        .unwrap_or("")
        .to_kebab_case()
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "ip-name-lookup",
    generate_all
});

export!(GatedIpNameLookup);
