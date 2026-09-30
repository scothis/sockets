use core::{fmt, net};

use crate::{
    componentized::sockets::latch::{
        self,
        Decision::{self, Deferred, Denied},
        ErrorCode as LatchErrorCode, IpNameLookupOperation, Operation, ResolveAddressesArgs,
        ResolveAddressesReturnsItem, SocketsErrorCode,
    },
    exports::wasi::sockets::ip_name_lookup::{ErrorCode, Guest},
    wasi::{
        logging::logging::{Level, log},
        sockets::{ip_name_lookup, types},
    },
};
macro_rules! error {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Error, "componentized-gate", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Error, "componentized-gate", &format!($dst));
    };
}

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

/// Authorize the operation with the latch, then report the decision back to the latch. Latches
/// act on the final decision in `observe-decision`, never while authorizing. Failing to observe
/// the decision fails the operation, the same as a latch error.
fn authorize(operation: &Operation) -> Result<Decision, LatchErrorCode> {
    let decision = latch::authorize(operation)?;
    latch::observe_decision(&decision, operation)?;
    Ok(decision)
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
        let call_summary =
            || format!("OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={name}");
        match authorize(&Operation::IpNameLookup(
            IpNameLookupOperation::ResolveAddresses(ResolveAddressesArgs { name: name.clone() }),
        )) {
            Ok(Denied(reason)) => {
                warn!("Denied REASON={reason} {}", call_summary());
                Err(reason)?
            }
            Ok(Deferred) => {
                ip_name_lookup::resolve_addresses(name.clone())
                    .await
                    .map(|addresses| {
                        addresses
                            .into_iter()
                            .filter(|ip_address| {
                                match authorize(&Operation::IpNameLookup(
                                    IpNameLookupOperation::ResolveAddressesReturn(
                                        ResolveAddressesReturnsItem {
                                            ip_address: *ip_address,
                                        },
                                    ),
                                )) {
                                    Ok(Denied(reason)) => {
                                        trace!("Denied REASON={reason} {}", call_summary());
                                        false
                                    }
                                    _ => true,
                                }
                            })
                            .collect()
                    })
            }
            Err(code) => {
                error!(
                    "Latch error CODE={code} {summary}",
                    code = DisplayLatchError(&code),
                    summary = call_summary()
                );
                Err(code)?
            }
        }
    }
}

impl fmt::Display for SocketsErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => f.write_str("access-denied"),
            Self::InvalidArgument => f.write_str("invalid-argument"),
            Self::Other(Some(message)) => f.write_str(message),
            Self::Other(None) => f.write_str("other"),
        }
    }
}

struct DisplayLatchError<'a>(&'a LatchErrorCode);
impl fmt::Display for DisplayLatchError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self(LatchErrorCode::InvalidConfig(latch)) => {
                write!(f, "invalid-config<{latch}>")
            }
            Self(LatchErrorCode::ObservationFailed(latch)) => {
                write!(f, "observation-failed<{latch}>")
            }
            Self(LatchErrorCode::Other(Some(message))) => f.write_str(message),
            Self(LatchErrorCode::Other(None)) => f.write_str("other"),
        }
    }
}

impl fmt::Display for types::IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address: net::IpAddr = (*self).into();
        f.write_fmt(format_args!("{address}"))
    }
}

impl Into<net::IpAddr> for types::IpAddress {
    fn into(self) -> net::IpAddr {
        match self {
            Self::Ipv4(v4) => net::IpAddr::V4(net::Ipv4Addr::new(v4.0, v4.1, v4.2, v4.3)),
            Self::Ipv6(v6) => net::IpAddr::V6(net::Ipv6Addr::new(
                v6.0, v6.1, v6.2, v6.3, v6.4, v6.5, v6.6, v6.7,
            )),
        }
    }
}

impl From<SocketsErrorCode> for ErrorCode {
    fn from(value: SocketsErrorCode) -> Self {
        match value {
            SocketsErrorCode::AccessDenied => Self::AccessDenied,
            SocketsErrorCode::InvalidArgument => Self::InvalidArgument,
            SocketsErrorCode::Other(message) => Self::Other(message),
        }
    }
}

impl From<LatchErrorCode> for ErrorCode {
    fn from(value: LatchErrorCode) -> Self {
        match value {
            LatchErrorCode::InvalidConfig(latch) => {
                Self::Other(Some(format!("latch-error: invalid-config<{latch}>")))
            }
            LatchErrorCode::ObservationFailed(latch) => {
                Self::Other(Some(format!("latch-error: observation-failed<{latch}>")))
            }
            LatchErrorCode::Other(Some(message)) => {
                Self::Other(Some(format!("latch-error: {message}")))
            }
            LatchErrorCode::Other(None) => Self::Other(Some("latch-error".to_string())),
        }
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "gated-ip-name-lookup",
    merge_structurally_equal_types: true,
    generate_all
});

export!(GatedIpNameLookup);
