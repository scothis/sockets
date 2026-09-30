use std::time::Duration;

use test_harness::bindings::componentized::sockets::latch::{Decision, SocketsErrorCode};
use test_harness::{
    ErrorCode, Harness, HostLatch, IpAddressFamily, LogEntry, Observation, collect,
    ip_socket_address, loopback, socket_addr, stream,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const LATCH: &str = "latch-cidr-egress";

#[tokio::test(flavor = "multi_thread")]
async fn udp_send_denied_to_matching_range() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    // aggregated with the host latch, which defers everything
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::defer())
        .config("deny", "127.0.0.0/8")
        .build()
        .await?;
    let (result, local_address) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            let result = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            Ok((result, socket_addr(local_address)))
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));

    let mut buf = [0; 16];
    assert!(
        timeout(Duration::from_millis(200), peer.recv_from(&mut buf))
            .await
            .is_err(),
        "no datagram should reach the peer"
    );
    // latch-n stops at the first denial, the host latch is not asked about the send but observes
    // the final decision
    assert_eq!(
        gate.recorder().operations(),
        vec!["udp-socket.create", "udp-socket.bind"]
    );
    assert_eq!(
        gate.recorder().observations().last(),
        Some(&Observation {
            operation: "udp-socket.send".to_string(),
            denied: true,
        })
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.send SOCKET={local_address}<-- DATA-LENGTH=5 REMOTE-ADDRESS=some<{}>",
                peer.local_addr()?
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_send_deferred_for_unmatched_range() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "10.0.0.0/8")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            Ok(udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?)
        })
        .await?;
    assert!(result.is_ok());

    let mut buf = [0; 16];
    let (len, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_send_on_connected_socket_checks_remote_address() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "127.0.0.0/8")
        .build()
        .await?;
    let (connected, sent) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            // connect is not restricted, sending without a remote address must still be checked
            let connected = udp.call_connect(accessor, socket, address).await?;
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), None)
                .await?;
            Ok((connected, sent))
        })
        .await?;
    assert!(connected.is_ok());
    assert!(matches!(sent, Err(ErrorCode::AccessDenied)));

    let mut buf = [0; 16];
    assert!(
        timeout(Duration::from_millis(200), peer.recv_from(&mut buf))
            .await
            .is_err(),
        "no datagram should reach the peer"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn more_specific_range_decides() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let allowed = ip_socket_address(peer.local_addr()?);
    // TEST-NET-1, only a latch denial explains access-denied, nothing is sent
    let blocked = ip_socket_address("192.0.2.1:9".parse()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("defer", "127.0.0.1")
        .config("deny", "0.0.0.0/0")
        .build()
        .await?;
    let (allowed_result, blocked_result) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let allowed = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(allowed))
                .await?;
            let blocked = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(blocked))
                .await?;
            Ok((allowed, blocked))
        })
        .await?;
    assert!(allowed_result.is_ok());
    assert!(matches!(blocked_result, Err(ErrorCode::AccessDenied)));

    let mut buf = [0; 16];
    let (len, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn default_deny_with_reason() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .config("reason", "invalid-argument")
        .build()
        .await?;
    let (created, bound, sent) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let created = udp.call_create(accessor, IpAddressFamily::Ipv4).await?;
            let socket = *created.as_ref().expect("create");
            let bound = udp.call_bind(accessor, socket, loopback(0)).await?;
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            Ok((created.is_ok(), bound, sent))
        })
        .await?;
    // create and bind are not restricted
    assert!(created);
    assert!(bound.is_ok());
    assert!(matches!(sent, Err(ErrorCode::InvalidArgument)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_config_fails_every_send() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "10.0.0.0/33")
        .build()
        .await?;
    let (first, second) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let first = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            let second = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            Ok((first, second))
        })
        .await?;
    for result in [first, second] {
        assert!(
            matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<latch-cidr-egress>")
        );
    }
    let logs = gate.recorder().logs();
    // the cause is logged once when the config is loaded, the gate logs each failed send
    assert_eq!(logs.len(), 3, "{logs:?}");
    assert_eq!(logs[0].context, "componentized-latch");
    assert!(
        logs[0].message.starts_with(
            "Invalid config LATCH=latch-cidr-egress KEY=deny VALUE=10.0.0.0/33 ERROR="
        ),
        "{}",
        logs[0].message
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_denied_to_matching_range() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "127.0.0.0/8")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_connect(accessor, socket, address).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert!(
        timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "no connection should reach the listener"
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.connect SOCKET=--- REMOTE-ADDRESS={}",
                listener.local_addr()?
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_deferred_for_unmatched_range() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "10.0.0.0/8")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let result = tcp.call_connect(accessor, socket, address).await?;
            timeout(Duration::from_secs(5), listener.accept()).await??;
            Ok(result)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_inbound_connections_are_not_restricted() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    gate.run(async |accessor, gate| {
        let tcp = gate.wasi_sockets_types().tcp_socket();
        let socket = tcp
            .call_create(accessor, IpAddressFamily::Ipv4)
            .await?
            .expect("create");
        tcp.call_bind(accessor, socket, loopback(0))
            .await?
            .expect("bind");
        let connections = tcp.call_listen(accessor, socket).await?.expect("listen");
        let address = tcp
            .call_get_local_address(accessor, socket)
            .await?
            .expect("local address");
        let mut connections = collect(accessor, connections)?;

        let _client = TcpStream::connect(socket_addr(address)).await?;
        let accepted = timeout(Duration::from_secs(5), connections.recv()).await?;
        assert!(accepted.is_some(), "connection should be accepted");
        Ok(())
    })
    .await?;
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_reply_to_received_peer_deferred() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);
    // same host as the peer, but it has not sent anything to the guest
    let other = UdpSocket::bind("127.0.0.1:0").await?;
    let other_address = ip_socket_address(other.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let (first_send, reply, other_send) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");

            // the guest may not originate traffic to the peer
            let first_send = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(peer_address))
                .await?;

            peer.send_to(b"ping", socket_addr(local_address)).await?;
            let (data, _) = timeout(Duration::from_secs(5), udp.call_receive(accessor, socket))
                .await??
                .expect("receive");
            assert_eq!(data, b"ping");

            let reply = udp
                .call_send(accessor, socket, b"pong".to_vec(), Some(peer_address))
                .await?;
            let other_send = udp
                .call_send(accessor, socket, b"pong".to_vec(), Some(other_address))
                .await?;
            Ok((first_send, reply, other_send))
        })
        .await?;
    assert!(matches!(first_send, Err(ErrorCode::AccessDenied)));
    assert!(reply.is_ok());
    assert!(matches!(other_send, Err(ErrorCode::AccessDenied)));

    let mut buf = [0; 16];
    let (len, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"pong");
    assert!(
        timeout(Duration::from_millis(200), other.recv_from(&mut buf))
            .await
            .is_err(),
        "no datagram should reach the other peer"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_reply_on_connected_socket_deferred() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let reply = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            udp.call_connect(accessor, socket, peer_address)
                .await?
                .expect("connect");

            peer.send_to(b"ping", socket_addr(local_address)).await?;
            timeout(Duration::from_secs(5), udp.call_receive(accessor, socket))
                .await??
                .expect("receive");

            Ok(udp
                .call_send(accessor, socket, b"pong".to_vec(), None)
                .await?)
        })
        .await?;
    assert!(reply.is_ok());

    let mut buf = [0; 16];
    let (len, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"pong");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_receive_denied_by_aggregated_latch_is_not_return_traffic() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);
    let other = UdpSocket::bind("127.0.0.1:0").await?;
    let other_address = ip_socket_address(other.local_addr()?);

    // the aggregated latch denies the first datagram, from the peer
    let mut denied = false;
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .host_latch(HostLatch::new(move |auth| {
            if auth.operation == "udp-socket.receive" && !denied {
                denied = true;
                Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
            } else {
                Ok(Decision::Deferred)
            }
        }))
        .build()
        .await?;
    let (received, to_peer, to_other) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");

            peer.send_to(b"ping", socket_addr(local_address)).await?;
            other.send_to(b"ping", socket_addr(local_address)).await?;
            let received =
                timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??;
            let to_peer = udp
                .call_send(accessor, socket, b"pong".to_vec(), Some(peer_address))
                .await?;
            let to_other = udp
                .call_send(accessor, socket, b"pong".to_vec(), Some(other_address))
                .await?;
            Ok((received, to_peer, to_other))
        })
        .await?;
    // the guest never saw the peer's datagram, so there is nothing to reply to
    let (_, from) = received.expect("receive");
    assert_eq!(socket_addr(from), other.local_addr()?);
    assert!(matches!(to_peer, Err(ErrorCode::AccessDenied)));
    assert!(to_other.is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregated_latch_denial_passes_through() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    // a distinct reason shows the aggregated latch's decision is returned, the ranges would defer
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::new(|auth| {
            if auth.operation == "tcp-socket.connect" {
                Ok(Decision::Denied(SocketsErrorCode::InvalidArgument))
            } else {
                Ok(Decision::Deferred)
            }
        }))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_connect(accessor, socket, address).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::InvalidArgument)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregated_latch_error_passes_through() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::error("boom"))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            Ok(udp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: boom")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregated_latch_component() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    // latch-deny-connect denies what the ranges would allow
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .latch("latch-deny-connect")
        .config("defer", "127.0.0.0/8")
        .build()
        .await?;
    let (connected, sent) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let connected = udp.call_connect(accessor, socket, address).await?;
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            Ok((connected, sent))
        })
        .await?;
    assert!(matches!(connected, Err(ErrorCode::AccessDenied)));
    assert!(sent.is_ok());

    let mut buf = [0; 16];
    let (len, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv6_all_range_covers_ipv4() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "::/0")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            Ok(udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_send_on_accepted_connection_deferred() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let received = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let connections = tcp.call_listen(accessor, socket).await?.expect("listen");
            let address = tcp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            let mut connections = collect(accessor, connections)?;

            let mut client = TcpStream::connect(socket_addr(address)).await?;
            let accepted = timeout(Duration::from_secs(5), connections.recv())
                .await?
                .expect("connection should be accepted");

            // replying on an inbound connection is return traffic
            let data = stream(accessor, b"hello".to_vec())?;
            let _sent = tcp.call_send(accessor, accepted, data).await?;

            let mut received = vec![];
            timeout(Duration::from_secs(5), client.read_to_end(&mut received)).await??;
            Ok(received)
        })
        .await?;
    assert_eq!(received, b"hello");
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_denied_to_matching_port() -> wasmtime::Result<()> {
    let denied = TcpListener::bind("127.0.0.1:0").await?;
    let allowed = TcpListener::bind("127.0.0.1:0").await?;
    let denied_address = ip_socket_address(denied.local_addr()?);
    let allowed_address = ip_socket_address(allowed.local_addr()?);

    // outbound traffic matches the remote port
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config(
            "deny",
            &format!("127.0.0.1:{}", denied.local_addr()?.port()),
        )
        .build()
        .await?;
    let (to_denied, to_allowed) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let first = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let to_denied = tcp.call_connect(accessor, first, denied_address).await?;
            let second = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let to_allowed = tcp.call_connect(accessor, second, allowed_address).await?;
            timeout(Duration::from_secs(5), allowed.accept()).await??;
            Ok((to_denied, to_allowed))
        })
        .await?;
    assert!(matches!(to_denied, Err(ErrorCode::AccessDenied)));
    assert!(to_allowed.is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_denied_to_matching_port_on_any_address() -> wasmtime::Result<()> {
    let denied = TcpListener::bind("127.0.0.1:0").await?;
    let allowed = TcpListener::bind("127.0.0.1:0").await?;
    let denied_address = ip_socket_address(denied.local_addr()?);
    let allowed_address = ip_socket_address(allowed.local_addr()?);

    // ports without an address match every address
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", &format!(":{}", denied.local_addr()?.port()))
        .build()
        .await?;
    let (to_denied, to_allowed) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let first = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let to_denied = tcp.call_connect(accessor, first, denied_address).await?;
            let second = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let to_allowed = tcp.call_connect(accessor, second, allowed_address).await?;
            timeout(Duration::from_secs(5), allowed.accept()).await??;
            Ok((to_denied, to_allowed))
        })
        .await?;
    assert!(matches!(to_denied, Err(ErrorCode::AccessDenied)));
    assert!(to_allowed.is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn config_mistakes_are_warned() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deni", "10.0.0.0/8")
        .config("deny", "127.1.2.3/8")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_connect(accessor, socket, address).await?)
        })
        .await?;
    // the config is accepted as documented, host bits are ignored so 127.0.0.0/8 is denied
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    let warnings: Vec<_> = gate
        .recorder()
        .logs()
        .into_iter()
        .filter(|log| log.context == "componentized-latch")
        .collect();
    assert_eq!(
        warnings,
        vec![
            LogEntry::warn(
                "componentized-latch",
                "Config issue LATCH=latch-cidr-egress KEY=deni VALUE=10.0.0.0/8 DETAIL=unknown key is ignored, expected a key starting with 'deny' or 'defer', 'default' or 'reason'"
            ),
            LogEntry::warn(
                "componentized-latch",
                "Config issue LATCH=latch-cidr-egress KEY=deny VALUE=127.1.2.3/8 DETAIL=bits set beyond the prefix length are ignored, the range is 127.0.0.0/8"
            ),
        ]
    );
    Ok(())
}
