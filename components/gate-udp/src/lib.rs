#![no_main]

use std::fmt::Display;
use std::net;

use heck::ToKebabCase;

use crate::componentized::sockets::latch::{
    authorize, CreateUdpSocketArgs, Decision::Denied, IncomingDatagramOperation, Operation,
    StartBindArgs, UdpCreateSocketOperation, UdpSocketOperation,
};
use crate::componentized::sockets::latch::{
    OutgoingDatagramOperation, ReceiveIncomingDatagramArgs, SendOutgoingDatagramArgs, StreamArgs,
};
use crate::exports::wasi::sockets::udp::{
    ErrorCode, Guest as UdpGuest, GuestIncomingDatagramStream, GuestOutgoingDatagramStream,
    GuestUdpSocket, IncomingDatagram, IncomingDatagramStream, IpAddressFamily, IpSocketAddress,
    Network, OutgoingDatagram, OutgoingDatagramStream, UdpSocket,
};
use crate::exports::wasi::sockets::udp_create_socket::Guest;
use crate::wasi::io::poll::Pollable;
use crate::wasi::logging::logging::{log, Level};
use crate::wasi::sockets::udp;
use crate::wasi::sockets::{network, udp_create_socket};

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
struct GatedUdpCreateSocket {}

impl UdpGuest for GatedUdpCreateSocket {
    type UdpSocket = GatedUdpSocket;

    type IncomingDatagramStream = GatedIncomingDatagramStream;

    type OutgoingDatagramStream = GatedOutgoingDatagramStream;
}

impl Guest for GatedUdpCreateSocket {
    #[doc = " Create a new UDP socket."]
    #[doc = ""]
    #[doc = " Similar to `socket(AF_INET or AF_INET6, SOCK_DGRAM, IPPROTO_UDP)` in POSIX."]
    #[doc = " On IPv6 sockets, IPV6_V6ONLY is enabled by default and can\'t be configured otherwise."]
    #[doc = ""]
    #[doc = " This function does not require a network capability handle. This is considered to be safe because"]
    #[doc = " at time of creation, the socket is not bound to any `network` yet. Up to the moment `bind` is called,"]
    #[doc = " the socket is effectively an in-memory configuration object, unable to communicate with the outside world."]
    #[doc = ""]
    #[doc = " All sockets are non-blocking. Use the wasi-poll interface to block on asynchronous operations."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `not-supported`:     The specified `address-family` is not supported. (EAFNOSUPPORT)"]
    #[doc = " - `new-socket-limit`:  The new socket resource could not be created because of a system limit. (EMFILE, ENFILE)"]
    #[doc = ""]
    #[doc = " # References:"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/socket.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=socket&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn create_udp_socket(address_family: IpAddressFamily) -> Result<UdpSocket, ErrorCode> {
        match authorize(&Operation::UdpCreateSocket(
            UdpCreateSocketOperation::CreateUdpSocket(CreateUdpSocketArgs { address_family }),
        )) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/udp-create-socket#create-udp-socket ADDRESS-FAMILY={address_family}");
                Err(error_code_map(code))
            }
            _ => udp_create_socket::create_udp_socket(address_family)
                .map(udp_socket_map)
                .map_err(error_code_map),
        }
    }
}

struct GatedUdpSocket {
    udp_socket: udp_create_socket::UdpSocket,
}

impl GatedUdpSocket {
    fn new(udp_socket: udp_create_socket::UdpSocket) -> Self {
        Self { udp_socket }
    }
}

impl GuestUdpSocket for GatedUdpSocket {
    #[doc = " Bind the socket to a specific network on the provided IP address and port."]
    #[doc = ""]
    #[doc = " If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is left to the implementation to decide which"]
    #[doc = " network interface(s) to bind to."]
    #[doc = " If the port is zero, the socket will be bound to a random free port."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:          The `local-address` has the wrong address family. (EAFNOSUPPORT, EFAULT on Windows)"]
    #[doc = " - `invalid-state`:             The socket is already bound. (EINVAL)"]
    #[doc = " - `address-in-use`:            No ephemeral ports available. (EADDRINUSE, ENOBUFS on Windows)"]
    #[doc = " - `address-in-use`:            Address is already in use. (EADDRINUSE)"]
    #[doc = " - `address-not-bindable`:      `local-address` is not an address that the `network` can bind to. (EADDRNOTAVAIL)"]
    #[doc = " - `not-in-progress`:           A `bind` operation is not in progress."]
    #[doc = " - `would-block`:               Can\'t finish the operation, it is still in progress. (EWOULDBLOCK, EAGAIN)"]
    #[doc = ""]
    #[doc = " # Implementors note"]
    #[doc = " Unlike in POSIX, in WASI the bind operation is async. This enables"]
    #[doc = " interactive WASI hosts to inject permission prompts. Runtimes that"]
    #[doc = " don\'t want to make use of this ability can simply call the native"]
    #[doc = " `bind` as part of either `start-bind` or `finish-bind`."]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/bind.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=bind&sektion=2&format=html>"]
    #[allow(async_fn_in_trait)]
    fn start_bind(
        &self,
        network: &Network,
        local_address: IpSocketAddress,
    ) -> Result<(), ErrorCode> {
        match authorize(&Operation::UdpSocket((
            &self.udp_socket,
            UdpSocketOperation::StartBind(StartBindArgs {
                network,
                local_address,
            }),
        ))) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/udp#udp-socket.start-bind NETWORK={network:?} LOCAL-ADDRESS={local_address}");
                Err(error_code_map(code))
            }
            _ => self
                .udp_socket
                .start_bind(network, local_address)
                .map_err(error_code_map),
        }
    }

    #[allow(async_fn_in_trait)]
    fn finish_bind(&self) -> Result<(), ErrorCode> {
        self.udp_socket.finish_bind()
    }

    #[doc = " Set up inbound & outbound communication channels, optionally to a specific peer."]
    #[doc = ""]
    #[doc = " This function only changes the local socket configuration and does not generate any network traffic."]
    #[doc = " On success, the `remote-address` of the socket is updated. The `local-address` may be updated as well,"]
    #[doc = " based on the best network path to `remote-address`."]
    #[doc = ""]
    #[doc = " When a `remote-address` is provided, the returned streams are limited to communicating with that specific peer:"]
    #[doc = " - `send` can only be used to send to this destination."]
    #[doc = " - `receive` will only return datagrams sent from the provided `remote-address`."]
    #[doc = ""]
    #[doc = " This method may be called multiple times on the same socket to change its association, but"]
    #[doc = " only the most recently returned pair of streams will be operational. Implementations may trap if"]
    #[doc = " the streams returned by a previous invocation haven\'t been dropped yet before calling `stream` again."]
    #[doc = ""]
    #[doc = " The POSIX equivalent in pseudo-code is:"]
    #[doc = " ```text"]
    #[doc = " if (was previously connected) {"]
    #[doc = " \tconnect(s, AF_UNSPEC)"]
    #[doc = " }"]
    #[doc = " if (remote_address is Some) {"]
    #[doc = " \tconnect(s, remote_address)"]
    #[doc = " }"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " Unlike in POSIX, the socket must already be explicitly bound."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:          The `remote-address` has the wrong address family. (EAFNOSUPPORT)"]
    #[doc = " - `invalid-argument`:          The IP address in `remote-address` is set to INADDR_ANY (`0.0.0.0` / `::`). (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = " - `invalid-argument`:          The port in `remote-address` is set to 0. (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = " - `invalid-state`:             The socket is not bound."]
    #[doc = " - `address-in-use`:            Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE, EADDRNOTAVAIL on Linux, EAGAIN on BSD)"]
    #[doc = " - `remote-unreachable`:        The remote address is not reachable. (ECONNRESET, ENETRESET, EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = " - `connection-refused`:        The connection was refused. (ECONNREFUSED)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/connect.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?connect>"]
    #[allow(async_fn_in_trait)]
    fn stream(
        &self,
        remote_address: Option<IpSocketAddress>,
    ) -> Result<(IncomingDatagramStream, OutgoingDatagramStream), ErrorCode> {
        match authorize(&Operation::UdpSocket((
            &self.udp_socket,
            UdpSocketOperation::Stream(StreamArgs { remote_address }),
        ))) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/udp#udp-socket.start-bind REMOTE-ADDRESS={remote_address:?}");
                Err(error_code_map(code))
            }
            _ => self
                .udp_socket
                .stream(remote_address)
                .map(|(incoming, outgoing)| {
                    (
                        incoming_datagram_stream_map(incoming),
                        outgoing_datagram_stream_map(outgoing),
                    )
                })
                .map_err(error_code_map),
        }
    }

    #[doc = " Get the current bound address."]
    #[doc = ""]
    #[doc = " POSIX mentions:"]
    #[doc = " > If the socket has not been bound to a local name, the value"]
    #[doc = " > stored in the object pointed to by `address` is unspecified."]
    #[doc = ""]
    #[doc = " WASI is stricter and requires `local-address` to return `invalid-state` when the socket hasn\'t been bound yet."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-state`: The socket is not bound to any local address."]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/getsockname.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?getsockname>"]
    #[allow(async_fn_in_trait)]
    fn local_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.udp_socket.local_address()
    }

    #[doc = " Get the address the socket is currently streaming to."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-state`: The socket is not streaming to a specific remote address. (ENOTCONN)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/getpeername.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=getpeername&sektion=2&n=1>"]
    #[allow(async_fn_in_trait)]
    fn remote_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.udp_socket.remote_address()
    }

    #[doc = " Whether this is a IPv4 or IPv6 socket."]
    #[doc = ""]
    #[doc = " Equivalent to the SO_DOMAIN socket option."]
    #[allow(async_fn_in_trait)]
    fn address_family(&self) -> IpAddressFamily {
        self.udp_socket.address_family()
    }

    #[doc = " Equivalent to the IP_TTL & IPV6_UNICAST_HOPS socket options."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:     (set) The TTL value must be 1 or higher."]
    #[allow(async_fn_in_trait)]
    fn unicast_hop_limit(&self) -> Result<u8, ErrorCode> {
        self.udp_socket.unicast_hop_limit()
    }

    #[allow(async_fn_in_trait)]
    fn set_unicast_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        self.udp_socket.set_unicast_hop_limit(value)
    }

    #[doc = " The kernel buffer space reserved for sends/receives on this socket."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = " Any other value will never cause an error, but it might be silently clamped and/or rounded."]
    #[doc = " I.e. after setting a value, reading the same setting back may return a different value."]
    #[doc = ""]
    #[doc = " Equivalent to the SO_RCVBUF and SO_SNDBUF socket options."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn receive_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.udp_socket.receive_buffer_size()
    }

    #[allow(async_fn_in_trait)]
    fn set_receive_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.udp_socket.set_receive_buffer_size(value)
    }

    #[allow(async_fn_in_trait)]
    fn send_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.udp_socket.send_buffer_size()
    }

    #[allow(async_fn_in_trait)]
    fn set_send_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.udp_socket.set_send_buffer_size(value)
    }

    #[doc = " Create a `pollable` which will resolve once the socket is ready for I/O."]
    #[doc = ""]
    #[doc = " Note: this function is here for WASI 0.2 only."]
    #[doc = " It\'s planned to be removed when `future` is natively supported in Preview3."]
    #[allow(async_fn_in_trait)]
    fn subscribe(&self) -> Pollable {
        self.udp_socket.subscribe()
    }
}

struct GatedIncomingDatagramStream {
    stream: udp::IncomingDatagramStream,
}

impl GatedIncomingDatagramStream {
    fn new(stream: udp::IncomingDatagramStream) -> Self {
        Self { stream }
    }
}

impl GuestIncomingDatagramStream for GatedIncomingDatagramStream {
    #[doc = " Receive messages on the socket."]
    #[doc = ""]
    #[doc = " This function attempts to receive up to `max-results` datagrams on the socket without blocking."]
    #[doc = " The returned list may contain fewer elements than requested, but never more."]
    #[doc = ""]
    #[doc = " This function returns successfully with an empty list when either:"]
    #[doc = " - `max-results` is 0, or:"]
    #[doc = " - `max-results` is greater than 0, but no results are immediately available."]
    #[doc = " This function never returns `error(would-block)`."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `remote-unreachable`: The remote address is not reachable. (ECONNRESET, ENETRESET on Windows, EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = " - `connection-refused`: The connection was refused. (ECONNREFUSED)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html>"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/recv.2.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/recvmmsg.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom>"]
    #[doc = " - <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms741687(v=vs.85)>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=recv&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn receive(&self, max_results: u64) -> Result<Vec<IncomingDatagram>, ErrorCode> {
        self.stream
            .receive(max_results)
            .map(|incoming| incoming.iter().filter(|datagram|{
                let operation = Operation::UdpStreamIncomingDatagram(
                       IncomingDatagramOperation::ReceiveIncomingDatagram(
                            ReceiveIncomingDatagramArgs{
                                remote_address: datagram.remote_address,
                                 data_length: u64::try_from(datagram.data.len()).expect("data length 64-bits or less")
                            }
                        )
                );
                match authorize(&operation) {
                    Some(Denied(code)) => {
                        let reason = error_code_display(code);
                        trace!("Denied REASON={reason} OPERATION=wasi:sockets/udp#incoming-datagram-stream.receive ");
                        false
                    }
                    _ => true,
                }
            }).map(incoming_datagram_map).collect())
    }

    #[doc = " Create a `pollable` which will resolve once the stream is ready to receive again."]
    #[doc = ""]
    #[doc = " Note: this function is here for WASI 0.2 only."]
    #[doc = " It\'s planned to be removed when `future` is natively supported in Preview3."]
    #[allow(async_fn_in_trait)]
    fn subscribe(&self) -> Pollable {
        self.stream.subscribe()
    }
}

struct GatedOutgoingDatagramStream {
    stream: udp::OutgoingDatagramStream,
}

impl GatedOutgoingDatagramStream {
    fn new(stream: udp::OutgoingDatagramStream) -> Self {
        Self { stream }
    }
}

impl GuestOutgoingDatagramStream for GatedOutgoingDatagramStream {
    #[doc = " Check readiness for sending. This function never blocks."]
    #[doc = ""]
    #[doc = " Returns the number of datagrams permitted for the next call to `send`,"]
    #[doc = " or an error. Calling `send` with more datagrams than this function has"]
    #[doc = " permitted will trap."]
    #[doc = ""]
    #[doc = " When this function returns ok(0), the `subscribe` pollable will"]
    #[doc = " become ready when this function will report at least ok(1), or an"]
    #[doc = " error."]
    #[doc = ""]
    #[doc = " Never returns `would-block`."]
    #[allow(async_fn_in_trait)]
    fn check_send(&self) -> Result<u64, ErrorCode> {
        self.stream.check_send()
    }

    #[doc = " Send messages on the socket."]
    #[doc = ""]
    #[doc = " This function attempts to send all provided `datagrams` on the socket without blocking and"]
    #[doc = " returns how many messages were actually sent (or queued for sending). This function never"]
    #[doc = " returns `error(would-block)`. If none of the datagrams were able to be sent, `ok(0)` is returned."]
    #[doc = ""]
    #[doc = " This function semantically behaves the same as iterating the `datagrams` list and sequentially"]
    #[doc = " sending each individual datagram until either the end of the list has been reached or the first error occurred."]
    #[doc = " If at least one datagram has been sent successfully, this function never returns an error."]
    #[doc = ""]
    #[doc = " If the input list is empty, the function returns `ok(0)`."]
    #[doc = ""]
    #[doc = " Each call to `send` must be permitted by a preceding `check-send`. Implementations must trap if"]
    #[doc = " either `check-send` was not called or `datagrams` contains more items than `check-send` permitted."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:        The `remote-address` has the wrong address family. (EAFNOSUPPORT)"]
    #[doc = " - `invalid-argument`:        The IP address in `remote-address` is set to INADDR_ANY (`0.0.0.0` / `::`). (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = " - `invalid-argument`:        The port in `remote-address` is set to 0. (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = " - `invalid-argument`:        The socket is in \"connected\" mode and `remote-address` is `some` value that does not match the address passed to `stream`. (EISCONN)"]
    #[doc = " - `invalid-argument`:        The socket is not \"connected\" and no value for `remote-address` was provided. (EDESTADDRREQ)"]
    #[doc = " - `remote-unreachable`:      The remote address is not reachable. (ECONNRESET, ENETRESET on Windows, EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = " - `connection-refused`:      The connection was refused. (ECONNREFUSED)"]
    #[doc = " - `datagram-too-large`:      The datagram is too large. (EMSGSIZE)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html>"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/send.2.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/sendmmsg.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=send&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn send(&self, datagrams: Vec<OutgoingDatagram>) -> Result<u64, ErrorCode> {
        let datagrams: Vec<udp::OutgoingDatagram> =
            datagrams.iter().filter(|datagram|{
                let operation = Operation::UdpStreamOutgoingDatagram(
                       OutgoingDatagramOperation::SendOutgoingDatagram(
                            SendOutgoingDatagramArgs{
                                remote_address: datagram.remote_address,
                                 data_length: u64::try_from(datagram.data.len()).expect("data length 64-bits or less")
                            }
                        )
                );
                match authorize(&operation) {
                    Some(Denied(code)) => {
                        let reason = error_code_display(code);
                        trace!("Denied REASON={reason} OPERATION=wasi:sockets/udp#outgoing-datagram-stream.send ");
                        false
                    }
                    _ => true,
                }
            }).map(map_outgoing_datagram).collect();
        self.stream.send(&datagrams)
    }

    #[doc = " Create a `pollable` which will resolve once the stream is ready to send again."]
    #[doc = ""]
    #[doc = " Note: this function is here for WASI 0.2 only."]
    #[doc = " It\'s planned to be removed when `future` is natively supported in Preview3."]
    #[allow(async_fn_in_trait)]
    fn subscribe(&self) -> Pollable {
        self.stream.subscribe()
    }
}

fn udp_socket_map(udp_socket: udp_create_socket::UdpSocket) -> UdpSocket {
    UdpSocket::new(GatedUdpSocket::new(udp_socket))
}

fn incoming_datagram_stream_map(stream: udp::IncomingDatagramStream) -> IncomingDatagramStream {
    IncomingDatagramStream::new(GatedIncomingDatagramStream::new(stream))
}

fn outgoing_datagram_stream_map(stream: udp::OutgoingDatagramStream) -> OutgoingDatagramStream {
    OutgoingDatagramStream::new(GatedOutgoingDatagramStream::new(stream))
}

fn incoming_datagram_map(incoming: &udp::IncomingDatagram) -> IncomingDatagram {
    IncomingDatagram {
        // TODO can we avoid this clone?
        data: incoming.data.clone(),
        remote_address: incoming.remote_address,
    }
}

fn map_outgoing_datagram(outgoing: &OutgoingDatagram) -> udp::OutgoingDatagram {
    udp::OutgoingDatagram {
        // TODO can we avoid this clone?
        data: outgoing.data.clone(),
        remote_address: outgoing.remote_address,
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

impl Display for IpAddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            network::IpAddressFamily::Ipv4 => f.write_str("IPv4"),
            network::IpAddressFamily::Ipv6 => f.write_str("IPv6"),
        }
    }
}

impl Display for IpSocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpSocketAddress::Ipv4(ipv4) => net::SocketAddrV4::new(
                net::Ipv4Addr::new(
                    ipv4.address.0,
                    ipv4.address.1,
                    ipv4.address.2,
                    ipv4.address.3,
                ),
                ipv4.port,
            )
            .fmt(f),
            IpSocketAddress::Ipv6(ipv6) => net::SocketAddrV6::new(
                net::Ipv6Addr::from_segments(ipv6.address.into()),
                ipv6.port,
                ipv6.flow_info,
                ipv6.scope_id,
            )
            .fmt(f),
        }
    }
}

wit_bindgen::generate!({
    path: "../../wit",
    world: "udp-create-socket",
    generate_all
});

export!(GatedUdpCreateSocket);
