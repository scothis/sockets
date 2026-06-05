#![no_main]

use std::fmt::Display;
use std::net;

use heck::ToKebabCase;

use crate::componentized::sockets::latch::{
    authorize, CreateTcpSocketArgs, Decision::Denied, Operation, StartBindArgs, StartConnectArgs,
    TcpCreateSocketOperation, TcpSocketOperation,
};
use crate::exports::wasi::sockets::tcp::{
    ErrorCode, Guest as TcpGuest, GuestTcpSocket, IpAddressFamily, ShutdownType, TcpSocket,
};
use crate::exports::wasi::sockets::tcp_create_socket::Guest;
use crate::wasi::clocks::monotonic_clock::Duration;
use crate::wasi::io::poll::Pollable;
use crate::wasi::io::streams::{InputStream, OutputStream};
use crate::wasi::logging::logging::{log, Level};
use crate::wasi::sockets::network::{IpSocketAddress, Network};
use crate::wasi::sockets::{network, tcp, tcp_create_socket};

macro_rules! warn {
    ($dst:expr, $($arg:tt)*) => {
        log(Level::Warn, "componentized-gate", &format!($dst, $($arg)*));
    };
    ($dst:expr) => {
        log(Level::Warn, "componentized-gate", &format!($dst));
    };
}

#[derive(Debug, Clone)]
struct GatedTcpCreateSocket {}

impl TcpGuest for GatedTcpCreateSocket {
    type TcpSocket = GatedTcpSocket;
}

impl Guest for GatedTcpCreateSocket {
    #[doc = " Create a new TCP socket."]
    #[doc = ""]
    #[doc = " Similar to `socket(AF_INET or AF_INET6, SOCK_STREAM, IPPROTO_TCP)` in POSIX."]
    #[doc = " On IPv6 sockets, IPV6_V6ONLY is enabled by default and can\'t be configured otherwise."]
    #[doc = ""]
    #[doc = " This function does not require a network capability handle. This is considered to be safe because"]
    #[doc = " at time of creation, the socket is not bound to any `network` yet. Up to the moment `bind`/`connect`"]
    #[doc = " is called, the socket is effectively an in-memory configuration object, unable to communicate with the outside world."]
    #[doc = ""]
    #[doc = " All sockets are non-blocking. Use the wasi-poll interface to block on asynchronous operations."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `not-supported`:     The specified `address-family` is not supported. (EAFNOSUPPORT)"]
    #[doc = " - `new-socket-limit`:  The new socket resource could not be created because of a system limit. (EMFILE, ENFILE)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/socket.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=socket&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn create_tcp_socket(address_family: IpAddressFamily) -> Result<TcpSocket, ErrorCode> {
        match authorize(&Operation::TcpCreateSocket(
            TcpCreateSocketOperation::CreateTcpSocket(CreateTcpSocketArgs { address_family }),
        )) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/tcp-create-socket#create-tcp-socket ADDRESS-FAMILY={address_family}");
                Err(error_code_map(code))
            }
            _ => tcp_create_socket::create_tcp_socket(address_family)
                .map(tcp_socket_map)
                .map_err(error_code_map),
        }
    }
}

struct GatedTcpSocket {
    tcp_socket: tcp_create_socket::TcpSocket,
}

impl GatedTcpSocket {
    fn new(tcp_socket: tcp_create_socket::TcpSocket) -> Self {
        Self { tcp_socket }
    }
}

impl GuestTcpSocket for GatedTcpSocket {
    #[doc = " Bind the socket to a specific network on the provided IP address and port."]
    #[doc = ""]
    #[doc = " If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is left to the implementation to decide which"]
    #[doc = " network interface(s) to bind to."]
    #[doc = " If the TCP/UDP port is zero, the socket will be bound to a random free port."]
    #[doc = ""]
    #[doc = " Bind can be attempted multiple times on the same socket, even with"]
    #[doc = " different arguments on each iteration. But never concurrently and"]
    #[doc = " only as long as the previous bind failed. Once a bind succeeds, the"]
    #[doc = " binding can\'t be changed anymore."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:          The `local-address` has the wrong address family. (EAFNOSUPPORT, EFAULT on Windows)"]
    #[doc = " - `invalid-argument`:          `local-address` is not a unicast address. (EINVAL)"]
    #[doc = " - `invalid-argument`:          `local-address` is an IPv4-mapped IPv6 address. (EINVAL)"]
    #[doc = " - `invalid-state`:             The socket is already bound. (EINVAL)"]
    #[doc = " - `address-in-use`:            No ephemeral ports available. (EADDRINUSE, ENOBUFS on Windows)"]
    #[doc = " - `address-in-use`:            Address is already in use. (EADDRINUSE)"]
    #[doc = " - `address-not-bindable`:      `local-address` is not an address that the `network` can bind to. (EADDRNOTAVAIL)"]
    #[doc = " - `not-in-progress`:           A `bind` operation is not in progress."]
    #[doc = " - `would-block`:               Can\'t finish the operation, it is still in progress. (EWOULDBLOCK, EAGAIN)"]
    #[doc = ""]
    #[doc = " # Implementors note"]
    #[doc = " When binding to a non-zero port, this bind operation shouldn\'t be affected by the TIME_WAIT"]
    #[doc = " state of a recently closed socket on the same local address. In practice this means that the SO_REUSEADDR"]
    #[doc = " socket option should be set implicitly on all platforms, except on Windows where this is the default behavior"]
    #[doc = " and SO_REUSEADDR performs something different entirely."]
    #[doc = ""]
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
        match authorize(&Operation::TcpSocket((
            &self.tcp_socket,
            TcpSocketOperation::StartBind(StartBindArgs {
                network,
                local_address,
            }),
        ))) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/tcp#tcp-socket.start-bind NETWORK={network:?} LOCAL-ADDRESS={local_address}");
                Err(error_code_map(code))
            }
            _ => self
                .tcp_socket
                .start_bind(network, local_address)
                .map_err(error_code_map),
        }
    }

    #[allow(async_fn_in_trait)]
    fn finish_bind(&self) -> Result<(), ErrorCode> {
        self.tcp_socket.finish_bind()
    }

    #[doc = " Connect to a remote endpoint."]
    #[doc = ""]
    #[doc = " On success:"]
    #[doc = " - the socket is transitioned into the `connected` state."]
    #[doc = " - a pair of streams is returned that can be used to read & write to the connection"]
    #[doc = ""]
    #[doc = " After a failed connection attempt, the socket will be in the `closed`"]
    #[doc = " state and the only valid action left is to `drop` the socket. A single"]
    #[doc = " socket can not be used to connect more than once."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:          The `remote-address` has the wrong address family. (EAFNOSUPPORT)"]
    #[doc = " - `invalid-argument`:          `remote-address` is not a unicast address. (EINVAL, ENETUNREACH on Linux, EAFNOSUPPORT on MacOS)"]
    #[doc = " - `invalid-argument`:          `remote-address` is an IPv4-mapped IPv6 address. (EINVAL, EADDRNOTAVAIL on Illumos)"]
    #[doc = " - `invalid-argument`:          The IP address in `remote-address` is set to INADDR_ANY (`0.0.0.0` / `::`). (EADDRNOTAVAIL on Windows)"]
    #[doc = " - `invalid-argument`:          The port in `remote-address` is set to 0. (EADDRNOTAVAIL on Windows)"]
    #[doc = " - `invalid-argument`:          The socket is already attached to a different network. The `network` passed to `connect` must be identical to the one passed to `bind`."]
    #[doc = " - `invalid-state`:             The socket is already in the `connected` state. (EISCONN)"]
    #[doc = " - `invalid-state`:             The socket is already in the `listening` state. (EOPNOTSUPP, EINVAL on Windows)"]
    #[doc = " - `timeout`:                   Connection timed out. (ETIMEDOUT)"]
    #[doc = " - `connection-refused`:        The connection was forcefully rejected. (ECONNREFUSED)"]
    #[doc = " - `connection-reset`:          The connection was reset. (ECONNRESET)"]
    #[doc = " - `connection-aborted`:        The connection was aborted. (ECONNABORTED)"]
    #[doc = " - `remote-unreachable`:        The remote address is not reachable. (EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = " - `address-in-use`:            Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE, EADDRNOTAVAIL on Linux, EAGAIN on BSD)"]
    #[doc = " - `not-in-progress`:           A connect operation is not in progress."]
    #[doc = " - `would-block`:               Can\'t finish the operation, it is still in progress. (EWOULDBLOCK, EAGAIN)"]
    #[doc = ""]
    #[doc = " # Implementors note"]
    #[doc = " The POSIX equivalent of `start-connect` is the regular `connect` syscall."]
    #[doc = " Because all WASI sockets are non-blocking this is expected to return"]
    #[doc = " EINPROGRESS, which should be translated to `ok()` in WASI."]
    #[doc = ""]
    #[doc = " The POSIX equivalent of `finish-connect` is a `poll` for event `POLLOUT`"]
    #[doc = " with a timeout of 0 on the socket descriptor. Followed by a check for"]
    #[doc = " the `SO_ERROR` socket option, in case the poll signaled readiness."]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/connect.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?connect>"]
    #[allow(async_fn_in_trait)]
    fn start_connect(
        &self,
        network: &Network,
        remote_address: IpSocketAddress,
    ) -> Result<(), ErrorCode> {
        match authorize(&Operation::TcpSocket((
            &self.tcp_socket,
            TcpSocketOperation::StartConnect(StartConnectArgs {
                network,
                remote_address,
            }),
        ))) {
            Some(Denied(code)) => {
                let reason = error_code_display(code);
                warn!("Denied REASON={reason} OPERATION=wasi:sockets/tcp#tcp-socket.start-connect NETWORK={network:?} REMOTE-ADDRESS={remote_address}");
                Err(error_code_map(code))
            }
            _ => self
                .tcp_socket
                .start_connect(network, remote_address)
                .map_err(error_code_map),
        }
    }

    #[allow(async_fn_in_trait)]
    fn finish_connect(&self) -> Result<(InputStream, OutputStream), ErrorCode> {
        self.tcp_socket.finish_connect()
    }

    #[doc = " Start listening for new connections."]
    #[doc = ""]
    #[doc = " Transitions the socket into the `listening` state."]
    #[doc = ""]
    #[doc = " Unlike POSIX, the socket must already be explicitly bound."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-state`:             The socket is not bound to any local address. (EDESTADDRREQ)"]
    #[doc = " - `invalid-state`:             The socket is already in the `connected` state. (EISCONN, EINVAL on BSD)"]
    #[doc = " - `invalid-state`:             The socket is already in the `listening` state."]
    #[doc = " - `address-in-use`:            Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE)"]
    #[doc = " - `not-in-progress`:           A listen operation is not in progress."]
    #[doc = " - `would-block`:               Can\'t finish the operation, it is still in progress. (EWOULDBLOCK, EAGAIN)"]
    #[doc = ""]
    #[doc = " # Implementors note"]
    #[doc = " Unlike in POSIX, in WASI the listen operation is async. This enables"]
    #[doc = " interactive WASI hosts to inject permission prompts. Runtimes that"]
    #[doc = " don\'t want to make use of this ability can simply call the native"]
    #[doc = " `listen` as part of either `start-listen` or `finish-listen`."]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/listen.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=listen&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn start_listen(&self) -> Result<(), ErrorCode> {
        todo!()
    }

    #[allow(async_fn_in_trait)]
    fn finish_listen(&self) -> Result<(), ErrorCode> {
        self.tcp_socket.finish_listen()
    }

    #[doc = " Accept a new client socket."]
    #[doc = ""]
    #[doc = " The returned socket is bound and in the `connected` state. The following properties are inherited from the listener socket:"]
    #[doc = " - `address-family`"]
    #[doc = " - `keep-alive-enabled`"]
    #[doc = " - `keep-alive-idle-time`"]
    #[doc = " - `keep-alive-interval`"]
    #[doc = " - `keep-alive-count`"]
    #[doc = " - `hop-limit`"]
    #[doc = " - `receive-buffer-size`"]
    #[doc = " - `send-buffer-size`"]
    #[doc = ""]
    #[doc = " On success, this function returns the newly accepted client socket along with"]
    #[doc = " a pair of streams that can be used to read & write to the connection."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-state`:      Socket is not in the `listening` state. (EINVAL)"]
    #[doc = " - `would-block`:        No pending connections at the moment. (EWOULDBLOCK, EAGAIN)"]
    #[doc = " - `connection-aborted`: An incoming connection was pending, but was terminated by the client before this listener could accept it. (ECONNABORTED)"]
    #[doc = " - `new-socket-limit`:   The new socket resource could not be created because of a system limit. (EMFILE, ENFILE)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/accept.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=accept&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn accept(&self) -> Result<(TcpSocket, InputStream, OutputStream), ErrorCode> {
        todo!()
    }

    #[doc = " Get the bound local address."]
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
        self.tcp_socket.local_address()
    }

    #[doc = " Get the remote address."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-state`: The socket is not connected to a remote address. (ENOTCONN)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/getpeername.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=getpeername&sektion=2&n=1>"]
    #[allow(async_fn_in_trait)]
    fn remote_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.tcp_socket.remote_address()
    }

    #[doc = " Whether the socket is in the `listening` state."]
    #[doc = ""]
    #[doc = " Equivalent to the SO_ACCEPTCONN socket option."]
    #[allow(async_fn_in_trait)]
    fn is_listening(&self) -> bool {
        self.tcp_socket.is_listening()
    }

    #[doc = " Whether this is a IPv4 or IPv6 socket."]
    #[doc = ""]
    #[doc = " Equivalent to the SO_DOMAIN socket option."]
    #[allow(async_fn_in_trait)]
    fn address_family(&self) -> IpAddressFamily {
        self.tcp_socket.address_family()
    }

    #[doc = " Hints the desired listen queue size. Implementations are free to ignore this."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = " Any other value will never cause an error, but it might be silently clamped and/or rounded."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `not-supported`:        (set) The platform does not support changing the backlog size after the initial listen."]
    #[doc = " - `invalid-argument`:     (set) The provided value was 0."]
    #[doc = " - `invalid-state`:        (set) The socket is in the `connect-in-progress` or `connected` state."]
    #[allow(async_fn_in_trait)]
    fn set_listen_backlog_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.tcp_socket.set_listen_backlog_size(value)
    }

    #[doc = " Enables or disables keepalive."]
    #[doc = ""]
    #[doc = " The keepalive behavior can be adjusted using:"]
    #[doc = " - `keep-alive-idle-time`"]
    #[doc = " - `keep-alive-interval`"]
    #[doc = " - `keep-alive-count`"]
    #[doc = " These properties can be configured while `keep-alive-enabled` is false, but only come into effect when `keep-alive-enabled` is true."]
    #[doc = ""]
    #[doc = " Equivalent to the SO_KEEPALIVE socket option."]
    #[allow(async_fn_in_trait)]
    fn keep_alive_enabled(&self) -> Result<bool, ErrorCode> {
        self.tcp_socket.keep_alive_enabled()
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_enabled(&self, value: bool) -> Result<(), ErrorCode> {
        self.tcp_socket.set_keep_alive_enabled(value)
    }

    #[doc = " Amount of time the connection has to be idle before TCP starts sending keepalive packets."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = " Any other value will never cause an error, but it might be silently clamped and/or rounded."]
    #[doc = " I.e. after setting a value, reading the same setting back may return a different value."]
    #[doc = ""]
    #[doc = " Equivalent to the TCP_KEEPIDLE socket option. (TCP_KEEPALIVE on MacOS)"]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn keep_alive_idle_time(&self) -> Result<Duration, ErrorCode> {
        self.tcp_socket.keep_alive_idle_time()
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_idle_time(&self, value: Duration) -> Result<(), ErrorCode> {
        self.tcp_socket.set_keep_alive_idle_time(value)
    }

    #[doc = " The time between keepalive packets."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = " Any other value will never cause an error, but it might be silently clamped and/or rounded."]
    #[doc = " I.e. after setting a value, reading the same setting back may return a different value."]
    #[doc = ""]
    #[doc = " Equivalent to the TCP_KEEPINTVL socket option."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn keep_alive_interval(&self) -> Result<Duration, ErrorCode> {
        self.tcp_socket.keep_alive_interval()
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_interval(&self, value: Duration) -> Result<(), ErrorCode> {
        self.tcp_socket.set_keep_alive_interval(value)
    }

    #[doc = " The maximum amount of keepalive packets TCP should send before aborting the connection."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = " Any other value will never cause an error, but it might be silently clamped and/or rounded."]
    #[doc = " I.e. after setting a value, reading the same setting back may return a different value."]
    #[doc = ""]
    #[doc = " Equivalent to the TCP_KEEPCNT socket option."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn keep_alive_count(&self) -> Result<u32, ErrorCode> {
        self.tcp_socket.keep_alive_count()
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_count(&self, value: u32) -> Result<(), ErrorCode> {
        self.tcp_socket.set_keep_alive_count(value)
    }

    #[doc = " Equivalent to the IP_TTL & IPV6_UNICAST_HOPS socket options."]
    #[doc = ""]
    #[doc = " If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-argument`:     (set) The TTL value must be 1 or higher."]
    #[allow(async_fn_in_trait)]
    fn hop_limit(&self) -> Result<u8, ErrorCode> {
        self.tcp_socket.hop_limit()
    }

    #[allow(async_fn_in_trait)]
    fn set_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        self.tcp_socket.set_hop_limit(value)
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
        self.tcp_socket.receive_buffer_size()
    }

    #[allow(async_fn_in_trait)]
    fn set_receive_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.tcp_socket.set_receive_buffer_size(value)
    }

    #[allow(async_fn_in_trait)]
    fn send_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.tcp_socket.send_buffer_size()
    }

    #[allow(async_fn_in_trait)]
    fn set_send_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.tcp_socket.set_send_buffer_size(value)
    }

    #[doc = " Create a `pollable` which can be used to poll for, or block on,"]
    #[doc = " completion of any of the asynchronous operations of this socket."]
    #[doc = ""]
    #[doc = " When `finish-bind`, `finish-listen`, `finish-connect` or `accept`"]
    #[doc = " return `error(would-block)`, this pollable can be used to wait for"]
    #[doc = " their success or failure, after which the method can be retried."]
    #[doc = ""]
    #[doc = " The pollable is not limited to the async operation that happens to be"]
    #[doc = " in progress at the time of calling `subscribe` (if any). Theoretically,"]
    #[doc = " `subscribe` only has to be called once per socket and can then be"]
    #[doc = " (re)used for the remainder of the socket\'s lifetime."]
    #[doc = ""]
    #[doc = " See <https://github.com/WebAssembly/wasi-sockets/blob/main/TcpSocketOperationalSemantics.md#pollable-readiness>"]
    #[doc = " for more information."]
    #[doc = ""]
    #[doc = " Note: this function is here for WASI 0.2 only."]
    #[doc = " It\'s planned to be removed when `future` is natively supported in Preview3."]
    #[allow(async_fn_in_trait)]
    fn subscribe(&self) -> Pollable {
        self.tcp_socket.subscribe()
    }

    #[doc = " Initiate a graceful shutdown."]
    #[doc = ""]
    #[doc = " - `receive`: The socket is not expecting to receive any data from"]
    #[doc = "   the peer. The `input-stream` associated with this socket will be"]
    #[doc = "   closed. Any data still in the receive queue at time of calling"]
    #[doc = "   this method will be discarded."]
    #[doc = " - `send`: The socket has no more data to send to the peer. The `output-stream`"]
    #[doc = "   associated with this socket will be closed and a FIN packet will be sent."]
    #[doc = " - `both`: Same effect as `receive` & `send` combined."]
    #[doc = ""]
    #[doc = " This function is idempotent; shutting down a direction more than once"]
    #[doc = " has no effect and returns `ok`."]
    #[doc = ""]
    #[doc = " The shutdown function does not close (drop) the socket."]
    #[doc = ""]
    #[doc = " # Typical errors"]
    #[doc = " - `invalid-state`: The socket is not in the `connected` state. (ENOTCONN)"]
    #[doc = ""]
    #[doc = " # References"]
    #[doc = " - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/shutdown.html>"]
    #[doc = " - <https://man7.org/linux/man-pages/man2/shutdown.2.html>"]
    #[doc = " - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-shutdown>"]
    #[doc = " - <https://man.freebsd.org/cgi/man.cgi?query=shutdown&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn shutdown(&self, shutdown_type: ShutdownType) -> Result<(), ErrorCode> {
        let shutdown_type = map_shutdown_type(shutdown_type);
        self.tcp_socket.shutdown(shutdown_type)
    }
}

fn tcp_socket_map(tcp_socket: tcp_create_socket::TcpSocket) -> TcpSocket {
    TcpSocket::new(GatedTcpSocket::new(tcp_socket))
}

fn map_shutdown_type(shutdown_type: ShutdownType) -> tcp::ShutdownType {
    match shutdown_type {
        ShutdownType::Receive => tcp::ShutdownType::Receive,
        ShutdownType::Send => tcp::ShutdownType::Send,
        ShutdownType::Both => tcp::ShutdownType::Both,
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
    world: "tcp-create-socket",
    generate_all
});

export!(GatedTcpCreateSocket);
