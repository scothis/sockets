#![no_main]

use std::fmt::Display;

use heck::ToKebabCase;

use crate::componentized::sockets::latch::{
    self, authorize, Decision::Denied, Operation, TcpSocketOperation, UdpSocketOperation,
};
use crate::exports::wasi::sockets::types::{
    Duration, ErrorCode, Guest, GuestTcpSocket, GuestUdpSocket, IpAddressFamily, IpSocketAddress,
    Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket, UdpSocket,
};
use crate::wasi::logging::logging::{log, Level};
use crate::wasi::sockets::types;

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

struct GatedSocketTypes {}

impl Guest for GatedSocketTypes {
    type TcpSocket = GatedTcpSocket;
    type UdpSocket = GatedUdpSocket;
}

struct GatedTcpSocket {
    socket: types::TcpSocket,
}

impl GatedTcpSocket {
    fn new(socket: types::TcpSocket) -> Self {
        Self { socket }
    }
}

impl GuestTcpSocket for GatedTcpSocket {
    #[doc = "/ Create a new TCP socket."]
    #[doc = "/"]
    #[doc = "/ Similar to `socket(AF_INET or AF_INET6, SOCK_STREAM, IPPROTO_TCP)`"]
    #[doc = "/ in POSIX. On IPv6 sockets, IPV6_V6ONLY is enabled by default and"]
    #[doc = "/ can\'t be configured otherwise."]
    #[doc = "/"]
    #[doc = "/ Unlike POSIX, WASI sockets have no notion of a socket-level"]
    #[doc = "/ `O_NONBLOCK` flag. Instead they fully rely on the Component Model\'s"]
    #[doc = "/ async support."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `not-supported`: The `address-family` is not supported. (EAFNOSUPPORT)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/socket.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=socket&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn create(address_family: IpAddressFamily) -> Result<TcpSocket, ErrorCode> {
        let address_family = address_family.into();
        match authorize(&Operation::TcpSocket(TcpSocketOperation::Create(
            componentized::sockets::latch::TcpSocketCreateArgs { address_family },
        ))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY={address_family}");
                Err(error_code.into())
            }
            _ => {
                let socket = types::TcpSocket::create(address_family)?;
                Ok(TcpSocket::new(GatedTcpSocket::new(socket)))
            }
        }
    }

    #[doc = "/ Bind the socket to the provided IP address and port."]
    #[doc = "/"]
    #[doc = "/ If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is"]
    #[doc = "/ left to the implementation to decide which network interface(s) to"]
    #[doc = "/ bind to. If the TCP/UDP port is zero, the socket will be bound to a"]
    #[doc = "/ random free port."]
    #[doc = "/"]
    #[doc = "/ Bind can be attempted multiple times on the same socket, even with"]
    #[doc = "/ different arguments on each iteration. But never concurrently and"]
    #[doc = "/ only as long as the previous bind failed. Once a bind succeeds, the"]
    #[doc = "/ binding can\'t be changed anymore."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:          The `local-address` has the wrong address family. (EAFNOSUPPORT, EFAULT on Windows)"]
    #[doc = "/ - `invalid-argument`:          `local-address` is not a unicast address. (EINVAL)"]
    #[doc = "/ - `invalid-argument`:          `local-address` is an IPv4-mapped IPv6 address. (EINVAL)"]
    #[doc = "/ - `invalid-state`:             The socket is already bound. (EINVAL)"]
    #[doc = "/ - `address-in-use`:            No ephemeral ports available. (EADDRINUSE, ENOBUFS on Windows)"]
    #[doc = "/ - `address-in-use`:            Address is already in use. (EADDRINUSE)"]
    #[doc = "/ - `address-not-bindable`:      `local-address` is not an address that can be bound to. (EADDRNOTAVAIL)"]
    #[doc = "/"]
    #[doc = "/ # Implementors note"]
    #[doc = "/ The bind operation shouldn\'t be affected by the TIME_WAIT state of a"]
    #[doc = "/ recently closed socket on the same local address. In practice this"]
    #[doc = "/ means that the SO_REUSEADDR socket option should be set implicitly"]
    #[doc = "/ on all platforms, except on Windows where this is the default"]
    #[doc = "/ behavior and SO_REUSEADDR performs something different."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/bind.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=bind&sektion=2&format=html>"]
    #[allow(async_fn_in_trait)]
    fn bind(&self, local_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let local_address = local_address.into();
        match authorize(&Operation::TcpSocket(TcpSocketOperation::Bind((
            &self.socket,
            componentized::sockets::latch::TcpSocketBindArgs { local_address },
        )))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS={local_address}");
                Err(error_code.into())
            }
            _ => self.socket.bind(local_address).map_err(|val| val.into()),
        }
    }

    #[doc = "/ Connect to a remote endpoint."]
    #[doc = "/"]
    #[doc = "/ On success, the socket is transitioned into the `connected` state"]
    #[doc = "/ and the `remote-address` of the socket is updated."]
    #[doc = "/ The `local-address` may be updated as well, based on the best network"]
    #[doc = "/ path to `remote-address`. If the socket was not already explicitly"]
    #[doc = "/ bound, this function will implicitly bind the socket to a random"]
    #[doc = "/ free port."]
    #[doc = "/"]
    #[doc = "/ After a failed connection attempt, the socket will be in the `closed`"]
    #[doc = "/ state and the only valid action left is to `drop` the socket. A single"]
    #[doc = "/ socket can not be used to connect more than once."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:          The `remote-address` has the wrong address family. (EAFNOSUPPORT)"]
    #[doc = "/ - `invalid-argument`:          `remote-address` is not a unicast address. (EINVAL, ENETUNREACH on Linux, EAFNOSUPPORT on MacOS)"]
    #[doc = "/ - `invalid-argument`:          `remote-address` is an IPv4-mapped IPv6 address. (EINVAL, EADDRNOTAVAIL on Illumos)"]
    #[doc = "/ - `invalid-argument`:          The IP address in `remote-address` is set to INADDR_ANY (`0.0.0.0` / `::`). (EADDRNOTAVAIL on Windows)"]
    #[doc = "/ - `invalid-argument`:          The port in `remote-address` is set to 0. (EADDRNOTAVAIL on Windows)"]
    #[doc = "/ - `invalid-state`:             The socket is already in the `connecting` state. (EALREADY)"]
    #[doc = "/ - `invalid-state`:             The socket is already in the `connected` state. (EISCONN)"]
    #[doc = "/ - `invalid-state`:             The socket is already in the `listening` state. (EOPNOTSUPP, EINVAL on Windows)"]
    #[doc = "/ - `timeout`:                   Connection timed out. (ETIMEDOUT)"]
    #[doc = "/ - `connection-refused`:        The connection was forcefully rejected. (ECONNREFUSED)"]
    #[doc = "/ - `connection-reset`:          The connection was reset. (ECONNRESET)"]
    #[doc = "/ - `connection-aborted`:        The connection was aborted. (ECONNABORTED)"]
    #[doc = "/ - `remote-unreachable`:        The remote address is not reachable. (EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = "/ - `address-in-use`:            Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE, EADDRNOTAVAIL on Linux, EAGAIN on BSD)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/connect.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?connect>"]
    #[allow(async_fn_in_trait)]
    async fn connect(&self, remote_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let remote_address = remote_address.into();
        match authorize(&Operation::TcpSocket(TcpSocketOperation::Connect((
            &self.socket,
            componentized::sockets::latch::TcpSocketConnectArgs { remote_address },
        )))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#tcp-socket.bind REMOTE-ADDRESS={remote_address}");
                Err(error_code.into())
            }
            _ => self
                .socket
                .connect(remote_address)
                .await
                .map_err(|val| val.into()),
        }
    }

    #[doc = "/ Start listening and return a stream of new inbound connections."]
    #[doc = "/"]
    #[doc = "/ Transitions the socket into the `listening` state. This can be called"]
    #[doc = "/ at most once per socket."]
    #[doc = "/"]
    #[doc = "/ If the socket is not already explicitly bound, this function will"]
    #[doc = "/ implicitly bind the socket to a random free port."]
    #[doc = "/"]
    #[doc = "/ Normally, the returned sockets are bound, in the `connected` state"]
    #[doc = "/ and immediately ready for I/O. Though, depending on exact timing and"]
    #[doc = "/ circumstances, a newly accepted connection may already be `closed`"]
    #[doc = "/ by the time the server attempts to perform its first I/O on it. This"]
    #[doc = "/ is true regardless of whether the WASI implementation uses"]
    #[doc = "/ \"synthesized\" sockets or not (see Implementors Notes below)."]
    #[doc = "/"]
    #[doc = "/ The following properties are inherited from the listener socket:"]
    #[doc = "/ - `address-family`"]
    #[doc = "/ - `keep-alive-enabled`"]
    #[doc = "/ - `keep-alive-idle-time`"]
    #[doc = "/ - `keep-alive-interval`"]
    #[doc = "/ - `keep-alive-count`"]
    #[doc = "/ - `hop-limit`"]
    #[doc = "/ - `receive-buffer-size`"]
    #[doc = "/ - `send-buffer-size`"]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`:             The socket is already in the `connected` state. (EISCONN, EINVAL on BSD)"]
    #[doc = "/ - `invalid-state`:             The socket is already in the `listening` state."]
    #[doc = "/ - `address-in-use`:            Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE)"]
    #[doc = "/"]
    #[doc = "/ # Implementors note"]
    #[doc = "/ This method returns a single perpetual stream that should only close"]
    #[doc = "/ on fatal errors (if any). Yet, the POSIX\' `accept` function may also"]
    #[doc = "/ return transient errors (e.g. ECONNABORTED). The exact details differ"]
    #[doc = "/ per operation system. For example, the Linux manual mentions:"]
    #[doc = "/"]
    #[doc = "/ > Linux accept() passes already-pending network errors on the new"]
    #[doc = "/ > socket as an error code from accept(). This behavior differs from"]
    #[doc = "/ > other BSD socket implementations. For reliable operation the"]
    #[doc = "/ > application should detect the network errors defined for the"]
    #[doc = "/ > protocol after accept() and treat them like EAGAIN by retrying."]
    #[doc = "/ > In the case of TCP/IP, these are ENETDOWN, EPROTO, ENOPROTOOPT,"]
    #[doc = "/ > EHOSTDOWN, ENONET, EHOSTUNREACH, EOPNOTSUPP, and ENETUNREACH."]
    #[doc = "/ Source: https://man7.org/linux/man-pages/man2/accept.2.html"]
    #[doc = "/"]
    #[doc = "/ WASI implementations have two options to handle this:"]
    #[doc = "/ - Optionally log it and then skip over non-fatal errors returned by"]
    #[doc = "/   `accept`. Guest code never gets to see these failures. Or:"]
    #[doc = "/ - Synthesize a `tcp-socket` resource that exposes the error when"]
    #[doc = "/   attempting to send or receive on it. Guest code then sees these"]
    #[doc = "/   failures as regular I/O errors."]
    #[doc = "/"]
    #[doc = "/ In either case, the stream returned by this `listen` method remains"]
    #[doc = "/ operational."]
    #[doc = "/"]
    #[doc = "/ WASI requires `listen` to perform an implicit bind if the socket"]
    #[doc = "/ has not already been bound. Not all platforms (notably Windows)"]
    #[doc = "/ exhibit this behavior out of the box. On platforms that require it,"]
    #[doc = "/ the WASI implementation can emulate this behavior by performing"]
    #[doc = "/ the bind itself if the guest hasn\'t already done so."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html>"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/listen.2.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/accept.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=listen&sektion=2>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=accept&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn listen(&self) -> Result<wit_bindgen::rt::async_support::StreamReader<TcpSocket>, ErrorCode> {
        match authorize(&Operation::TcpSocket(TcpSocketOperation::Listen((
            &self.socket,
        )))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#tcp-socket.listen");
                Err(error_code.into())
            }
            _ => match self.socket.listen() {
                Ok(mut stream) => {
                    let (mut stream_writer, stream_reader) = wit_stream::new::<TcpSocket>();
                    wit_bindgen::spawn(async move {
                        while let Some(socket) = stream.next().await {
                            match authorize(&Operation::TcpSocket(
                                TcpSocketOperation::ListenConnection((&socket,)),
                            )) {
                                Some(Denied(error_code)) => {
                                    trace!("Denied REASON={error_code} OPERATION=wasi:sockets/types#tcp-socket.listen.connection");
                                }
                                _ => {
                                    let socket = TcpSocket::new(GatedTcpSocket::new(socket));
                                    stream_writer
                                        .write_one(socket)
                                        .await
                                        .expect("stream write to succeed");
                                }
                            }
                        }
                    });
                    // TODO do we close the stream or is it dropped automatically?
                    Ok(stream_reader)
                }
                Err(error_code) => Err(error_code.into()),
            },
        }
    }

    #[doc = "/ Transmit data to peer."]
    #[doc = "/"]
    #[doc = "/ The caller should close the stream when it has no more data to send"]
    #[doc = "/ to the peer. Under normal circumstances this will cause a FIN packet"]
    #[doc = "/ to be sent out. Closing the stream is equivalent to calling"]
    #[doc = "/ `shutdown(SHUT_WR)` in POSIX."]
    #[doc = "/"]
    #[doc = "/ This function may be called at most once and returns once the full"]
    #[doc = "/ contents of the stream are transmitted or an error is encountered."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`:             The socket is not in the `connected` state. (ENOTCONN)"]
    #[doc = "/ - `invalid-state`:             `send` has already been called on this socket."]
    #[doc = "/ - `connection-broken`:         The connection is not writable anymore. (EPIPE, ECONNABORTED on Windows)"]
    #[doc = "/ - `connection-reset`:          The connection was reset. (ECONNRESET)"]
    #[doc = "/ - `remote-unreachable`:        The remote address is not reachable. (EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = "/"]
    #[doc = "/  # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/send.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=send&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn send(
        &self,
        data: wit_bindgen::StreamReader<u8>,
    ) -> wit_bindgen::FutureReader<Result<(), ErrorCode>> {
        let (tx, rx) = wit_future::new(|| Err(ErrorCode::Other(None)));
        let send_result = self.socket.send(data);
        wit_bindgen::spawn(async move {
            tx.write(send_result.await.map_err(|val| val.into()))
                .await
                .expect("future write to succeed");
        });
        rx
    }

    #[doc = "/ Read data from peer."]
    #[doc = "/"]
    #[doc = "/ Returns a `stream` of data sent by the peer. The implementation"]
    #[doc = "/ drops the stream once no more data is available. At that point, the"]
    #[doc = "/ returned `future` resolves to:"]
    #[doc = "/ - `ok` after a graceful shutdown from the peer (i.e. a FIN packet), or"]
    #[doc = "/ - `err` if the socket was closed abnormally."]
    #[doc = "/"]
    #[doc = "/ `receive` may be called only once per socket. Subsequent calls return"]
    #[doc = "/ a closed stream and a future resolved to `err(invalid-state)`."]
    #[doc = "/"]
    #[doc = "/ If the caller is not expecting to receive any more data from the peer,"]
    #[doc = "/ they should drop the stream. Any data still in the receive queue"]
    #[doc = "/ will be discarded. This is equivalent to calling `shutdown(SHUT_RD)`"]
    #[doc = "/ in POSIX."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`:             The socket is not in the `connected` state. (ENOTCONN)"]
    #[doc = "/ - `invalid-state`:             `receive` has already been called on this socket."]
    #[doc = "/ - `connection-reset`:          The connection was reset. (ECONNRESET)"]
    #[doc = "/ - `remote-unreachable`:        The remote address is not reachable. (EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/recv.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=recv&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn receive(
        &self,
    ) -> (
        wit_bindgen::StreamReader<u8>,
        wit_bindgen::FutureReader<Result<(), ErrorCode>>,
    ) {
        let (data, result) = self.socket.receive();
        let (tx, rx) = wit_future::new(|| Err(ErrorCode::Other(None)));

        wit_bindgen::spawn(async move {
            tx.write(result.await.map_err(|val| val.into()))
                .await
                .expect("future write to succeed");
        });

        (data, rx)
    }

    #[doc = "/ Get the bound local address."]
    #[doc = "/"]
    #[doc = "/ POSIX mentions:"]
    #[doc = "/ > If the socket has not been bound to a local name, the value"]
    #[doc = "/ > stored in the object pointed to by `address` is unspecified."]
    #[doc = "/"]
    #[doc = "/ WASI is stricter and requires `get-local-address` to return"]
    #[doc = "/ `invalid-state` when the socket hasn\'t been bound yet."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`: The socket is not bound to any local address."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/getsockname.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?getsockname>"]
    #[allow(async_fn_in_trait)]
    fn get_local_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.socket
            .get_local_address()
            .map(|val| val.into())
            .map_err(|val| val.into())
    }

    #[doc = "/ Get the remote address."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`: The socket is not connected to a remote address. (ENOTCONN)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/getpeername.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=getpeername&sektion=2&n=1>"]
    #[allow(async_fn_in_trait)]
    fn get_remote_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.socket
            .get_remote_address()
            .map(|val| val.into())
            .map_err(|val| val.into())
    }

    #[doc = "/ Whether the socket is in the `listening` state."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the SO_ACCEPTCONN socket option."]
    #[allow(async_fn_in_trait)]
    fn get_is_listening(&self) -> bool {
        self.socket.get_is_listening()
    }

    #[doc = "/ Whether this is a IPv4 or IPv6 socket."]
    #[doc = "/"]
    #[doc = "/ This is the value passed to the constructor."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the SO_DOMAIN socket option."]
    #[allow(async_fn_in_trait)]
    fn get_address_family(&self) -> IpAddressFamily {
        self.socket.get_address_family().into()
    }

    #[doc = "/ Hints the desired listen queue size. Implementations are free to"]
    #[doc = "/ ignore this."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/ Any other value will never cause an error, but it might be silently"]
    #[doc = "/ clamped and/or rounded."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `not-supported`:        (set) The platform does not support changing the backlog size after the initial listen."]
    #[doc = "/ - `invalid-argument`:     (set) The provided value was 0."]
    #[doc = "/ - `invalid-state`:        (set) The socket is in the `connecting` or `connected` state."]
    #[allow(async_fn_in_trait)]
    fn set_listen_backlog_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.socket
            .set_listen_backlog_size(value)
            .map_err(|val| val.into())
    }

    #[doc = "/ Enables or disables keepalive."]
    #[doc = "/"]
    #[doc = "/ The keepalive behavior can be adjusted using:"]
    #[doc = "/ - `keep-alive-idle-time`"]
    #[doc = "/ - `keep-alive-interval`"]
    #[doc = "/ - `keep-alive-count`"]
    #[doc = "/ These properties can be configured while `keep-alive-enabled` is"]
    #[doc = "/ false, but only come into effect when `keep-alive-enabled` is true."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the SO_KEEPALIVE socket option."]
    #[allow(async_fn_in_trait)]
    fn get_keep_alive_enabled(&self) -> Result<bool, ErrorCode> {
        self.socket
            .get_keep_alive_enabled()
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_enabled(&self, value: bool) -> Result<(), ErrorCode> {
        self.socket
            .set_keep_alive_enabled(value)
            .map_err(|val| val.into())
    }

    #[doc = "/ Amount of time the connection has to be idle before TCP starts"]
    #[doc = "/ sending keepalive packets."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/ All other values are accepted without error, but may be"]
    #[doc = "/ clamped or rounded. As a result, the value read back from"]
    #[doc = "/ this setting may differ from the value that was set."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the TCP_KEEPIDLE socket option. (TCP_KEEPALIVE on MacOS)"]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn get_keep_alive_idle_time(&self) -> Result<Duration, ErrorCode> {
        self.socket
            .get_keep_alive_idle_time()
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_idle_time(&self, value: Duration) -> Result<(), ErrorCode> {
        self.socket
            .set_keep_alive_idle_time(value)
            .map_err(|val| val.into())
    }

    #[doc = "/ The time between keepalive packets."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/ All other values are accepted without error, but may be"]
    #[doc = "/ clamped or rounded. As a result, the value read back from"]
    #[doc = "/ this setting may differ from the value that was set."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the TCP_KEEPINTVL socket option."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn get_keep_alive_interval(&self) -> Result<Duration, ErrorCode> {
        self.socket
            .get_keep_alive_interval()
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_interval(&self, value: Duration) -> Result<(), ErrorCode> {
        self.socket
            .set_keep_alive_interval(value)
            .map_err(|val| val.into())
    }

    #[doc = "/ The maximum amount of keepalive packets TCP should send before"]
    #[doc = "/ aborting the connection."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/ All other values are accepted without error, but may be"]
    #[doc = "/ clamped or rounded. As a result, the value read back from"]
    #[doc = "/ this setting may differ from the value that was set."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the TCP_KEEPCNT socket option."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn get_keep_alive_count(&self) -> Result<u32, ErrorCode> {
        self.socket.get_keep_alive_count().map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_keep_alive_count(&self, value: u32) -> Result<(), ErrorCode> {
        self.socket
            .set_keep_alive_count(value)
            .map_err(|val| val.into())
    }

    #[doc = "/ Equivalent to the IP_TTL & IPV6_UNICAST_HOPS socket options."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The TTL value must be 1 or higher."]
    #[allow(async_fn_in_trait)]
    fn get_hop_limit(&self) -> Result<u8, ErrorCode> {
        self.socket.get_hop_limit().map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        self.socket.set_hop_limit(value).map_err(|val| val.into())
    }

    #[doc = "/ Kernel buffer space reserved for sending/receiving on this socket."]
    #[doc = "/ Implementations usually treat this as a cap the buffer can grow to,"]
    #[doc = "/ rather than allocating the full amount immediately."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/ All other values are accepted without error, but may be"]
    #[doc = "/ clamped or rounded. As a result, the value read back from"]
    #[doc = "/ this setting may differ from the value that was set."]
    #[doc = "/"]
    #[doc = "/ This is only a performance hint. The implementation may ignore it or"]
    #[doc = "/ tweak it based on real traffic patterns."]
    #[doc = "/ Linux and macOS appear to behave differently depending on whether a"]
    #[doc = "/ buffer size was explicitly set. When set, they tend to honor it; when"]
    #[doc = "/ not set, they dynamically adjust the buffer size as the connection"]
    #[doc = "/ progresses. This is especially noticeable when comparing the values"]
    #[doc = "/ from before and after connection establishment."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the SO_RCVBUF and SO_SNDBUF socket options."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn get_receive_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.socket
            .get_receive_buffer_size()
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_receive_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.socket
            .set_receive_buffer_size(value)
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn get_send_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.socket.get_send_buffer_size().map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_send_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.socket
            .set_send_buffer_size(value)
            .map_err(|val| val.into())
    }
}

struct GatedUdpSocket {
    socket: types::UdpSocket,
}

impl GatedUdpSocket {
    fn new(socket: types::UdpSocket) -> Self {
        Self { socket }
    }
}

impl GuestUdpSocket for GatedUdpSocket {
    #[doc = "/ Create a new UDP socket."]
    #[doc = "/"]
    #[doc = "/ Similar to `socket(AF_INET or AF_INET6, SOCK_DGRAM, IPPROTO_UDP)`"]
    #[doc = "/ in POSIX. On IPv6 sockets, IPV6_V6ONLY is enabled by default and"]
    #[doc = "/ can\'t be configured otherwise."]
    #[doc = "/"]
    #[doc = "/ Unlike POSIX, WASI sockets have no notion of a socket-level"]
    #[doc = "/ `O_NONBLOCK` flag. Instead they fully rely on the Component Model\'s"]
    #[doc = "/ async support."]
    #[doc = "/"]
    #[doc = "/ # References:"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/socket.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=socket&sektion=2>"]
    #[allow(async_fn_in_trait)]
    fn create(address_family: IpAddressFamily) -> Result<UdpSocket, ErrorCode> {
        let address_family = address_family.into();
        match authorize(&Operation::TcpSocket(TcpSocketOperation::Create(
            componentized::sockets::latch::TcpSocketCreateArgs { address_family },
        ))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY={address_family}");
                Err(error_code.into())
            }
            _ => {
                let socket = types::UdpSocket::create(address_family)?;
                Ok(UdpSocket::new(GatedUdpSocket::new(socket)))
            }
        }
    }

    #[doc = "/ Bind the socket to the provided IP address and port."]
    #[doc = "/"]
    #[doc = "/ If the IP address is zero (`0.0.0.0` in IPv4, `::` in IPv6), it is"]
    #[doc = "/ left to the implementation to decide which network interface(s) to"]
    #[doc = "/ bind to. If the port is zero, the socket will be bound to a random"]
    #[doc = "/ free port."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:          The `local-address` has the wrong address family. (EAFNOSUPPORT, EFAULT on Windows)"]
    #[doc = "/ - `invalid-state`:             The socket is already bound. (EINVAL)"]
    #[doc = "/ - `address-in-use`:            No ephemeral ports available. (EADDRINUSE, ENOBUFS on Windows)"]
    #[doc = "/ - `address-in-use`:            Address is already in use. (EADDRINUSE)"]
    #[doc = "/ - `address-not-bindable`:      `local-address` is not an address that can be bound to. (EADDRNOTAVAIL)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/bind.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=bind&sektion=2&format=html>"]
    #[allow(async_fn_in_trait)]
    fn bind(&self, local_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let local_address = local_address.into();
        match authorize(&Operation::UdpSocket(UdpSocketOperation::Bind((
            &self.socket,
            componentized::sockets::latch::UdpSocketBindArgs { local_address },
        )))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#udp-socket.bind LOCAL-ADDRESS={local_address}");
                Err(error_code.into())
            }
            _ => self.socket.bind(local_address).map_err(|val| val.into()),
        }
    }

    #[doc = "/ Associate this socket with a specific peer address."]
    #[doc = "/"]
    #[doc = "/ On success, the `remote-address` of the socket is updated."]
    #[doc = "/ The `local-address` may be updated as well, based on the best network"]
    #[doc = "/ path to `remote-address`. If the socket was not already explicitly"]
    #[doc = "/ bound, this function will implicitly bind the socket to a random"]
    #[doc = "/ free port."]
    #[doc = "/"]
    #[doc = "/ When a UDP socket is \"connected\", the `send` and `receive` methods"]
    #[doc = "/ are limited to communicating with that peer only:"]
    #[doc = "/ - `send` can only be used to send to this destination."]
    #[doc = "/ - `receive` will only return datagrams sent from the provided `remote-address`."]
    #[doc = "/"]
    #[doc = "/ The name \"connect\" was kept to align with the existing POSIX"]
    #[doc = "/ terminology. Other than that, this function only changes the local"]
    #[doc = "/ socket configuration and does not generate any network traffic."]
    #[doc = "/ The peer is not aware of this \"connection\"."]
    #[doc = "/"]
    #[doc = "/ This method may be called multiple times on the same socket to change"]
    #[doc = "/ its association, but only the most recent one will be effective."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:          The `remote-address` has the wrong address family. (EAFNOSUPPORT)"]
    #[doc = "/ - `invalid-argument`:          The IP address in `remote-address` is set to INADDR_ANY (`0.0.0.0` / `::`). (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = "/ - `invalid-argument`:          The port in `remote-address` is set to 0. (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = "/ - `address-in-use`:            Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE, EADDRNOTAVAIL on Linux, EAGAIN on BSD)"]
    #[doc = "/"]
    #[doc = "/ # Implementors note"]
    #[doc = "/ If the socket is already connected, some platforms (e.g. Linux)"]
    #[doc = "/ require a disconnect before connecting to a different peer address."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/connect.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?connect>"]
    #[allow(async_fn_in_trait)]
    fn connect(&self, remote_address: IpSocketAddress) -> Result<(), ErrorCode> {
        let remote_address = remote_address.into();
        match authorize(&Operation::UdpSocket(UdpSocketOperation::Connect((
            &self.socket,
            componentized::sockets::latch::UdpSocketConnectArgs { remote_address },
        )))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#udp-socket.connect REMOTE-ADDRESS={remote_address}");
                Err(error_code.into())
            }
            _ => self
                .socket
                .connect(remote_address)
                .map_err(|val| val.into()),
        }
    }

    #[doc = "/ Dissociate this socket from its peer address."]
    #[doc = "/"]
    #[doc = "/ After calling this method, `send` & `receive` are free to communicate"]
    #[doc = "/ with any remote address again."]
    #[doc = "/"]
    #[doc = "/ The POSIX equivalent of this is calling `connect` with an `AF_UNSPEC` address."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`:           The socket is not connected."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/connect.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?connect>"]
    #[allow(async_fn_in_trait)]
    fn disconnect(&self) -> Result<(), ErrorCode> {
        self.socket.disconnect().map_err(|val| val.into())
    }

    #[doc = "/ Send a message on the socket to a particular peer."]
    #[doc = "/"]
    #[doc = "/ If the socket is connected, the peer address may be left empty. In"]
    #[doc = "/ that case this is equivalent to `send` in POSIX. Otherwise it is"]
    #[doc = "/ equivalent to `sendto`."]
    #[doc = "/"]
    #[doc = "/ Additionally, if the socket is connected, a `remote-address` argument"]
    #[doc = "/ _may_ be provided but then it must be identical to the address"]
    #[doc = "/ passed to `connect`."]
    #[doc = "/"]
    #[doc = "/ If the socket has not been explicitly bound, it will be"]
    #[doc = "/ implicitly bound to a random free port."]
    #[doc = "/"]
    #[doc = "/ Implementations may trap if the `data` length exceeds 64 KiB."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:        The `remote-address` has the wrong address family. (EAFNOSUPPORT)"]
    #[doc = "/ - `invalid-argument`:        The IP address in `remote-address` is set to INADDR_ANY (`0.0.0.0` / `::`). (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = "/ - `invalid-argument`:        The port in `remote-address` is set to 0. (EDESTADDRREQ, EADDRNOTAVAIL)"]
    #[doc = "/ - `invalid-argument`:        The socket is in \"connected\" mode and `remote-address` is `some` value that does not match the address passed to `connect`. (EISCONN)"]
    #[doc = "/ - `invalid-argument`:        The socket is not \"connected\" and no value for `remote-address` was provided. (EDESTADDRREQ)"]
    #[doc = "/ - `remote-unreachable`:      The remote address is not reachable. (ECONNRESET, ENETRESET on Windows, EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = "/ - `connection-refused`:      The connection was refused. (ECONNREFUSED)"]
    #[doc = "/ - `datagram-too-large`:      The datagram is too large. (EMSGSIZE)"]
    #[doc = "/ - `address-in-use`:          Tried to perform an implicit bind, but there were no ephemeral ports available. (EADDRINUSE)"]
    #[doc = "/"]
    #[doc = "/ # Implementors note"]
    #[doc = "/ WASI requires `send` to perform an implicit bind if the socket"]
    #[doc = "/ has not been bound. Not all platforms (notably Windows) exhibit"]
    #[doc = "/ this behavior natively. On such platforms, the WASI implementation"]
    #[doc = "/ should emulate it by performing the bind if the guest has not"]
    #[doc = "/ already done so."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html>"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/send.2.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/sendmmsg.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=send&sektion=2>"]
    #[allow(async_fn_in_trait)]
    async fn send(
        &self,
        data: Vec<u8>,
        remote_address: Option<IpSocketAddress>,
    ) -> Result<(), ErrorCode> {
        let remote_address = remote_address.map(|val| val.into());
        match authorize(&Operation::UdpSocket(UdpSocketOperation::Send((
            &self.socket,
            componentized::sockets::latch::UdpSocketSendArgs {
                data_length: data.len().try_into().expect("data length exceeded 64 bits"),
                remote_address,
            },
        )))) {
            Some(Denied(error_code)) => {
                warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#udp-socket.send DATA-LENGTH={} REMOTE-ADDRESS={}", data.len(), DisplayOption(remote_address));
                Err(error_code.into())
            }
            _ => self
                .socket
                .send(data, remote_address)
                .await
                .map_err(|val| val.into()),
        }
    }

    #[doc = "/ Receive a message on the socket."]
    #[doc = "/"]
    #[doc = "/ On success, the return value contains a tuple of the received data"]
    #[doc = "/ and the address of the sender. Theoretical maximum length of the"]
    #[doc = "/ data is 64 KiB. Though in practice, it will typically be less than"]
    #[doc = "/ 1500 bytes."]
    #[doc = "/"]
    #[doc = "/ If the socket is connected, the sender address is guaranteed to"]
    #[doc = "/ match the remote address passed to `connect`."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`:        The socket has not been bound yet."]
    #[doc = "/ - `remote-unreachable`:   The remote address is not reachable. (ECONNRESET, ENETRESET on Windows, EHOSTUNREACH, EHOSTDOWN, ENETUNREACH, ENETDOWN, ENONET)"]
    #[doc = "/ - `connection-refused`:   The connection was refused. (ECONNREFUSED)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html>"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/recv.2.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/recvmmsg.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=recv&sektion=2>"]
    #[allow(async_fn_in_trait)]
    async fn receive(&self) -> Result<(Vec<u8>, IpSocketAddress), ErrorCode> {
        match self.socket.receive().await {
            Ok((data, remote_address)) => {
                match authorize(&Operation::UdpSocket(UdpSocketOperation::Receive((
                    &self.socket,
                    componentized::sockets::latch::UdpSocketReceiveReturns {
                        data_length: data.len().try_into().expect("data length exceeded 64 bits"),
                        remote_address: remote_address.into(),
                    },
                )))) {
                    Some(Denied(error_code)) => {
                        warn!("Denied REASON={error_code} OPERATION=wasi:sockets/types#udp-socket.receive DATA-LENGTH={} REMOTE-ADDRESS={}", data.len(), remote_address);
                        Err(error_code.into())
                    }
                    _ => Ok((data, remote_address.into())),
                }
            }
            Err(error_code) => Err(error_code.into()),
        }
    }

    #[doc = "/ Get the current bound address."]
    #[doc = "/"]
    #[doc = "/ POSIX mentions:"]
    #[doc = "/ > If the socket has not been bound to a local name, the value"]
    #[doc = "/ > stored in the object pointed to by `address` is unspecified."]
    #[doc = "/"]
    #[doc = "/ WASI is stricter and requires `get-local-address` to return"]
    #[doc = "/ `invalid-state` when the socket hasn\'t been bound yet."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`: The socket is not bound to any local address."]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/getsockname.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?getsockname>"]
    #[allow(async_fn_in_trait)]
    fn get_local_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.socket
            .get_local_address()
            .map(|val| val.into())
            .map_err(|val| val.into())
    }

    #[doc = "/ Get the address the socket is currently \"connected\" to."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-state`: The socket is not \"connected\" to a specific remote address. (ENOTCONN)"]
    #[doc = "/"]
    #[doc = "/ # References"]
    #[doc = "/ - <https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html>"]
    #[doc = "/ - <https://man7.org/linux/man-pages/man2/getpeername.2.html>"]
    #[doc = "/ - <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername>"]
    #[doc = "/ - <https://man.freebsd.org/cgi/man.cgi?query=getpeername&sektion=2&n=1>"]
    #[allow(async_fn_in_trait)]
    fn get_remote_address(&self) -> Result<IpSocketAddress, ErrorCode> {
        self.socket
            .get_remote_address()
            .map(|val| val.into())
            .map_err(|val| val.into())
    }

    #[doc = "/ Whether this is a IPv4 or IPv6 socket."]
    #[doc = "/"]
    #[doc = "/ This is the value passed to the constructor."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the SO_DOMAIN socket option."]
    #[allow(async_fn_in_trait)]
    fn get_address_family(&self) -> IpAddressFamily {
        self.socket.get_address_family().into()
    }

    #[doc = "/ Equivalent to the IP_TTL & IPV6_UNICAST_HOPS socket options."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The TTL value must be 1 or higher."]
    #[allow(async_fn_in_trait)]
    fn get_unicast_hop_limit(&self) -> Result<u8, ErrorCode> {
        self.socket
            .get_unicast_hop_limit()
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_unicast_hop_limit(&self, value: u8) -> Result<(), ErrorCode> {
        self.socket
            .set_unicast_hop_limit(value)
            .map_err(|val| val.into())
    }

    #[doc = "/ Kernel buffer space reserved for sending/receiving on this socket."]
    #[doc = "/ Implementations usually treat this as a cap the buffer can grow to,"]
    #[doc = "/ rather than allocating the full amount immediately."]
    #[doc = "/"]
    #[doc = "/ If the provided value is 0, an `invalid-argument` error is returned."]
    #[doc = "/ All other values are accepted without error, but may be"]
    #[doc = "/ clamped or rounded. As a result, the value read back from"]
    #[doc = "/ this setting may differ from the value that was set."]
    #[doc = "/"]
    #[doc = "/ Equivalent to the SO_RCVBUF and SO_SNDBUF socket options."]
    #[doc = "/"]
    #[doc = "/ # Typical errors"]
    #[doc = "/ - `invalid-argument`:     (set) The provided value was 0."]
    #[allow(async_fn_in_trait)]
    fn get_receive_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.socket
            .get_receive_buffer_size()
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_receive_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.socket
            .set_receive_buffer_size(value)
            .map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn get_send_buffer_size(&self) -> Result<u64, ErrorCode> {
        self.socket.get_send_buffer_size().map_err(|val| val.into())
    }

    #[allow(async_fn_in_trait)]
    fn set_send_buffer_size(&self, value: u64) -> Result<(), ErrorCode> {
        self.socket
            .set_send_buffer_size(value)
            .map_err(|val| val.into())
    }
}

impl From<IpAddressFamily> for types::IpAddressFamily {
    fn from(value: IpAddressFamily) -> types::IpAddressFamily {
        match value {
            IpAddressFamily::Ipv4 => types::IpAddressFamily::Ipv4,
            IpAddressFamily::Ipv6 => types::IpAddressFamily::Ipv6,
        }
    }
}

impl From<types::IpAddressFamily> for IpAddressFamily {
    fn from(value: types::IpAddressFamily) -> IpAddressFamily {
        match value {
            types::IpAddressFamily::Ipv4 => IpAddressFamily::Ipv4,
            types::IpAddressFamily::Ipv6 => IpAddressFamily::Ipv6,
        }
    }
}

impl From<IpSocketAddress> for types::IpSocketAddress {
    fn from(value: IpSocketAddress) -> types::IpSocketAddress {
        match value {
            IpSocketAddress::Ipv4(ipv4) => types::IpSocketAddress::Ipv4(types::Ipv4SocketAddress {
                port: ipv4.port,
                address: ipv4.address,
            }),
            IpSocketAddress::Ipv6(ipv6) => types::IpSocketAddress::Ipv6(types::Ipv6SocketAddress {
                port: ipv6.port,
                flow_info: ipv6.flow_info,
                address: ipv6.address,
                scope_id: ipv6.scope_id,
            }),
        }
    }
}

impl From<types::IpSocketAddress> for IpSocketAddress {
    fn from(value: types::IpSocketAddress) -> IpSocketAddress {
        match value {
            types::IpSocketAddress::Ipv4(ipv4) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: ipv4.port,
                address: ipv4.address,
            }),
            types::IpSocketAddress::Ipv6(ipv6) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: ipv6.port,
                flow_info: ipv6.flow_info,
                address: ipv6.address,
                scope_id: ipv6.scope_id,
            }),
        }
    }
}

impl From<types::ErrorCode> for ErrorCode {
    fn from(value: types::ErrorCode) -> Self {
        match value {
            types::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
            types::ErrorCode::NotSupported => ErrorCode::NotSupported,
            types::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
            types::ErrorCode::OutOfMemory => ErrorCode::OutOfMemory,
            types::ErrorCode::Timeout => ErrorCode::Timeout,
            types::ErrorCode::InvalidState => ErrorCode::InvalidState,
            types::ErrorCode::AddressNotBindable => ErrorCode::AddressNotBindable,
            types::ErrorCode::AddressInUse => ErrorCode::AddressInUse,
            types::ErrorCode::RemoteUnreachable => ErrorCode::RemoteUnreachable,
            types::ErrorCode::ConnectionRefused => ErrorCode::ConnectionRefused,
            types::ErrorCode::ConnectionBroken => ErrorCode::ConnectionBroken,
            types::ErrorCode::ConnectionReset => ErrorCode::ConnectionReset,
            types::ErrorCode::ConnectionAborted => ErrorCode::ConnectionAborted,
            types::ErrorCode::DatagramTooLarge => ErrorCode::DatagramTooLarge,
            types::ErrorCode::Other(error) => ErrorCode::Other(error),
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

impl Display for types::IpAddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}",
            match self {
                types::IpAddressFamily::Ipv4 => "IPv4",
                types::IpAddressFamily::Ipv6 => "IPv6",
            }
        ))
    }
}

impl Display for types::IpSocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}",
            match self {
                types::IpSocketAddress::Ipv4(ipv4) =>
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from_octets(ipv4.address.into()),
                        ipv4.port
                    )),
                types::IpSocketAddress::Ipv6(ipv6) =>
                    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from_segments(ipv6.address.into()),
                        ipv6.port,
                        ipv6.flow_info,
                        ipv6.scope_id
                    )),
            }
        ))
    }
}

impl Display for latch::ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{}",
            match self {
                latch::ErrorCode::Other(Some(error_code)) => format!("other<{error_code}>"),
                _ => self.to_string().to_kebab_case(),
            }
        ))
    }
}

struct DisplayOption<T>(Option<T>);

// Implement Display for your local wrapper
impl<T: Display> Display for DisplayOption<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(value) => write!(f, "some<{}>", value),
            None => write!(f, "none"), // Customize what to print if empty
        }
    }
}

// additional types missed by wit-bindgen
pub mod bindgen_hacks;

wit_bindgen::generate!({
    path: "../../wit",
    world: "gated-types",
    generate_all
});

export!(GatedSocketTypes);
