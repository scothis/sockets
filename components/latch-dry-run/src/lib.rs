use std::net::{IpAddr, SocketAddr};

use crate::componentized::sockets::latch;
use crate::exports::componentized::sockets::latch::{
    Decision, ErrorCode, Guest as Latch, IpNameLookupOperation, Operation, SocketsErrorCode,
    TcpSocketOperation, UdpSocketOperation,
};
use crate::wasi::logging::logging::{Level, log};
use crate::wasi::sockets::types::{IpAddress, IpAddressFamily, IpSocketAddress};

macro_rules! error {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Error, "componentized-latch", &format!($dst, $($arg)*));
    };
}

macro_rules! warn {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Warn, "componentized-latch", &format!($dst, $($arg)*));
    };
}

struct DryRunLatch {}

impl Latch for DryRunLatch {
    fn authorize(operation: Operation) -> Result<Decision, ErrorCode> {
        // the wrapped latch decides, its denials and errors are logged but never enforced
        match latch::authorize(&operation) {
            Ok(Decision::Abstained) => {}
            Ok(Decision::Denied(reason)) => {
                warn!(
                    "Dry run, would deny REASON={} {}",
                    display_reason(&reason),
                    describe(&operation)
                );
            }
            Err(err) => {
                error!(
                    "Dry run, latch error CODE={} {}",
                    display_error(&err),
                    describe(&operation)
                );
            }
        }
        Ok(Decision::Abstained)
    }

    fn observe_decision(final_decision: Decision, operation: Operation) -> Result<(), ErrorCode> {
        // the wrapped latch observes what actually happens, the operation was not denied by this
        // latch, so stateful latches act as if their denials were not enforced
        if let Err(err) = latch::observe_decision(&final_decision, &operation) {
            error!(
                "Dry run, latch error CODE={} {}",
                display_error(&err),
                describe(&operation)
            );
        }
        Ok(())
    }
}

/// Describe an operation the same way the gates do in their logs.
fn describe(operation: &Operation) -> String {
    match operation {
        Operation::IpNameLookup(operation) => match operation {
            IpNameLookupOperation::ResolveAddresses(args) => format!(
                "OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME={}",
                args.name
            ),
            IpNameLookupOperation::ResolveAddressesReturn(item) => format!(
                "OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses IP-ADDRESS={}",
                ip_addr(item.ip_address)
            ),
        },
        Operation::TcpSocket(operation) => match operation {
            TcpSocketOperation::Create(args) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY={}",
                display_family(args.address_family)
            ),
            TcpSocketOperation::Bind((_, args)) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS={}",
                socket_addr(args.local_address)
            ),
            TcpSocketOperation::Connect((_, args)) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.connect REMOTE-ADDRESS={}",
                socket_addr(args.remote_address)
            ),
            TcpSocketOperation::Listen((socket,)) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.listen LOCAL-ADDRESS={}",
                display_option(socket.get_local_address().ok())
            ),
            TcpSocketOperation::ListenConnection((socket,)) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.listen REMOTE-ADDRESS={}",
                display_option(socket.get_remote_address().ok())
            ),
            TcpSocketOperation::Send((socket,)) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.send REMOTE-ADDRESS={}",
                display_option(socket.get_remote_address().ok())
            ),
            TcpSocketOperation::Receive((socket,)) => format!(
                "OPERATION=wasi:sockets/types#tcp-socket.receive REMOTE-ADDRESS={}",
                display_option(socket.get_remote_address().ok())
            ),
        },
        Operation::UdpSocket(operation) => match operation {
            UdpSocketOperation::Create(args) => format!(
                "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY={}",
                display_family(args.address_family)
            ),
            UdpSocketOperation::Bind((_, args)) => format!(
                "OPERATION=wasi:sockets/types#udp-socket.bind LOCAL-ADDRESS={}",
                socket_addr(args.local_address)
            ),
            UdpSocketOperation::Connect((_, args)) => format!(
                "OPERATION=wasi:sockets/types#udp-socket.connect REMOTE-ADDRESS={}",
                socket_addr(args.remote_address)
            ),
            UdpSocketOperation::Send((socket, args)) => format!(
                "OPERATION=wasi:sockets/types#udp-socket.send DATA-LENGTH={} REMOTE-ADDRESS={}",
                args.data_length,
                display_option(
                    args.remote_address
                        .or_else(|| socket.get_remote_address().ok())
                )
            ),
            UdpSocketOperation::Receive((_, args)) => format!(
                "OPERATION=wasi:sockets/types#udp-socket.receive DATA-LENGTH={} REMOTE-ADDRESS={}",
                args.data_length,
                socket_addr(args.remote_address)
            ),
        },
    }
}

fn display_reason(reason: &SocketsErrorCode) -> String {
    match reason {
        SocketsErrorCode::AccessDenied => "access-denied".to_string(),
        SocketsErrorCode::InvalidArgument => "invalid-argument".to_string(),
        SocketsErrorCode::Other(Some(message)) => message.clone(),
        SocketsErrorCode::Other(None) => "other".to_string(),
    }
}

fn display_error(err: &ErrorCode) -> String {
    match err {
        ErrorCode::InvalidConfig(latch) => format!("invalid-config<{latch}>"),
        ErrorCode::ObservationFailed(latch) => format!("observation-failed<{latch}>"),
        ErrorCode::Other(Some(message)) => message.clone(),
        ErrorCode::Other(None) => "other".to_string(),
    }
}

fn display_family(family: IpAddressFamily) -> &'static str {
    match family {
        IpAddressFamily::Ipv4 => "IPv4",
        IpAddressFamily::Ipv6 => "IPv6",
    }
}

fn display_option(address: Option<IpSocketAddress>) -> String {
    match address {
        Some(address) => socket_addr(address).to_string(),
        None => "none".to_string(),
    }
}

fn socket_addr(address: IpSocketAddress) -> SocketAddr {
    match address {
        IpSocketAddress::Ipv4(ipv4) => {
            SocketAddr::new(ip_addr(IpAddress::Ipv4(ipv4.address)), ipv4.port)
        }
        IpSocketAddress::Ipv6(ipv6) => {
            SocketAddr::new(ip_addr(IpAddress::Ipv6(ipv6.address)), ipv6.port)
        }
    }
}

fn ip_addr(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::from([a, b, c, d]),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => IpAddr::from([a, b, c, d, e, f, g, h]),
    }
}

wit_bindgen::generate!({
    path: "../wit",
    world: "sockets-latch",
    merge_structurally_equal_types: true,
    generate_all
});

export!(DryRunLatch);
