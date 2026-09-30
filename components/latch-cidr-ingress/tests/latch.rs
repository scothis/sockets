use std::time::Duration;

use test_harness::bindings::componentized::sockets::latch::{Decision, SocketsErrorCode};
use test_harness::{
    ErrorCode, Harness, HostLatch, IpAddressFamily, LogEntry, Observation, collect,
    ip_socket_address, loopback, socket_addr, stream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const LATCH: &str = "latch-cidr-ingress";

#[tokio::test(flavor = "multi_thread")]
async fn tcp_inbound_connection_denied_from_matching_range() -> wasmtime::Result<()> {
    // aggregated with the host latch, which defers everything
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::defer())
        .config("deny", "127.0.0.0/8")
        .build()
        .await?;
    let (listen_address, client_address) = gate
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

            let client = TcpStream::connect(socket_addr(address)).await?;
            assert!(
                timeout(Duration::from_millis(200), connections.recv())
                    .await
                    .is_err(),
                "the connection should not reach the guest"
            );
            Ok((socket_addr(address), client.local_addr()?))
        })
        .await?;
    // latch-n stops at the first denial, the host latch is not asked about the connection but
    // observes the final decision
    assert_eq!(
        gate.recorder().operations(),
        vec!["tcp-socket.create", "tcp-socket.bind", "tcp-socket.listen"]
    );
    assert_eq!(
        gate.recorder().observations().last(),
        Some(&Observation {
            operation: "tcp-socket.listen.connection".to_string(),
            denied: true,
        })
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.listen SOCKET={listen_address}<->{client_address}"
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_inbound_connection_deferred_for_unmatched_range() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "10.0.0.0/8")
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
async fn tcp_outbound_connection_is_not_restricted() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

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
            tcp.call_connect(accessor, socket, address)
                .await?
                .expect("connect");
            let (mut peer, _) = timeout(Duration::from_secs(5), listener.accept()).await??;

            // sending and receiving on a connection the guest opened is not restricted
            let data = stream(accessor, b"ping".to_vec())?;
            let _sent = tcp.call_send(accessor, socket, data).await?;
            let mut ping = [0; 4];
            timeout(Duration::from_secs(5), peer.read_exact(&mut ping)).await??;
            assert_eq!(&ping, b"ping");

            peer.write_all(b"pong").await?;
            peer.shutdown().await?;
            let (data, _done) = tcp.call_receive(accessor, socket).await?;
            let mut data = collect(accessor, data)?;
            let mut received = vec![];
            while let Some(byte) = timeout(Duration::from_secs(5), data.recv()).await? {
                received.push(byte);
            }
            Ok(received)
        })
        .await?;
    assert_eq!(received, b"pong");
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_receive_denied_from_matching_range() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);
    let other = UdpSocket::bind("127.0.0.1:0").await?;

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
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
            // the peer is established, the other sender is not
            udp.call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?
                .expect("send");

            other.send_to(b"hello", socket_addr(local_address)).await?;
            peer.send_to(b"pong", socket_addr(local_address)).await?;
            let result =
                timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??;
            Ok((result, socket_addr(local_address)))
        })
        .await?;
    // the denied datagram is dropped, the receive continues with the next one
    let (data, _) = result.expect("receive");
    assert_eq!(data, b"pong");
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.receive SOCKET={local_address}<-- DATA-LENGTH=5 REMOTE-ADDRESS={}",
                other.local_addr()?
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_receive_deferred_for_unmatched_range() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;

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
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            peer.send_to(b"hello", socket_addr(local_address)).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    let (data, _) = result.expect("receive");
    assert_eq!(data, b"hello");
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_reply_from_sent_peer_deferred() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);
    // same host as the peer, but the guest has not sent anything to it
    let other = UdpSocket::bind("127.0.0.1:0").await?;

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let received = gate
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
            udp.call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?
                .expect("send");

            other.send_to(b"spoof", socket_addr(local_address)).await?;
            let mut buf = [0; 16];
            let (_, guest) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
            peer.send_to(b"pong", guest).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    // the other sender's datagram is dropped, only the peer's reply reaches the guest
    let (data, from) = received.expect("receive");
    assert_eq!(data, b"pong");
    assert_eq!(socket_addr(from), peer.local_addr()?);
    assert_eq!(gate.recorder().logs().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_reply_after_implicit_bind_deferred() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            // the socket is bound by the send, it has no local address when the send is checked
            udp.call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?
                .expect("send");

            let mut buf = [0; 16];
            let (_, guest) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
            peer.send_to(b"pong", guest).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    let (data, _) = result.expect("receive");
    assert_eq!(data, b"pong");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_receive_on_connected_socket_deferred() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
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
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            // connecting establishes the peer without sending anything
            udp.call_connect(accessor, socket, peer_address)
                .await?
                .expect("connect");

            peer.send_to(b"hello", socket_addr(local_address)).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    let (data, _) = result.expect("receive");
    assert_eq!(data, b"hello");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_send_denied_by_aggregated_latch_is_not_established() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);
    let other = UdpSocket::bind("127.0.0.1:0").await?;
    let other_address = ip_socket_address(other.local_addr()?);

    // the aggregated latch denies the first send, to the peer
    let mut denied = false;
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .host_latch(HostLatch::new(move |auth| {
            if auth.operation == "udp-socket.send" && !denied {
                denied = true;
                Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
            } else {
                Ok(Decision::Deferred)
            }
        }))
        .build()
        .await?;
    let (sent, received) = gate
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
            let sent = udp
                .call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?;
            udp.call_send(accessor, socket, b"ping".to_vec(), Some(other_address))
                .await?
                .expect("send");

            peer.send_to(b"hello", socket_addr(local_address)).await?;
            other.send_to(b"pong", socket_addr(local_address)).await?;
            let received =
                timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??;
            Ok((sent, received))
        })
        .await?;
    // the peer never heard from the guest, so its datagram is not return traffic and is dropped
    assert!(matches!(sent, Err(ErrorCode::AccessDenied)));
    let (data, from) = received.expect("receive");
    assert_eq!(data, b"pong");
    assert_eq!(socket_addr(from), other.local_addr()?);
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
async fn composes_with_egress_latch() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    // both latches read the same config, the harness shares config across the composition
    let mut gate = Harness::new("gate-types")
        .latch("latch-cidr-egress")
        .latch(LATCH)
        .config("default", "deny")
        .config("defer", &peer.local_addr()?.ip().to_string())
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
            udp.call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?
                .expect("send");

            let mut buf = [0; 16];
            let (_, guest) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
            peer.send_to(b"pong", guest).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    let (data, _) = result.expect("receive");
    assert_eq!(data, b"pong");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_config_fails_every_receive() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "10.0.0.0/33")
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
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            peer.send_to(b"hello", socket_addr(local_address)).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<latch-cidr-ingress>")
    );
    let logs = gate.recorder().logs();
    assert_eq!(logs[0].context, "componentized-latch");
    assert!(
        logs[0].message.starts_with(
            "Invalid config LATCH=latch-cidr-ingress KEY=deny VALUE=10.0.0.0/33 ERROR="
        ),
        "{}",
        logs[0].message
    );
    Ok(())
}

/// A port that is free on loopback, the listener is closed so the guest can bind it.
fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_inbound_connection_denied_to_matching_local_port() -> wasmtime::Result<()> {
    let denied_port = free_port()?;

    // inbound traffic matches the guest's local port, not the peer's ephemeral port
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", &format!("127.0.0.0/8:{denied_port}"))
        .build()
        .await?;
    gate.run(async |accessor, gate| {
        let tcp = gate.wasi_sockets_types().tcp_socket();
        let listen = async |port| -> wasmtime::Result<_> {
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_bind(accessor, socket, loopback(port))
                .await?
                .expect("bind");
            let connections = tcp.call_listen(accessor, socket).await?.expect("listen");
            let address = tcp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            Ok((collect(accessor, connections)?, socket_addr(address)))
        };
        let (mut denied, denied_address) = listen(denied_port).await?;
        let (mut allowed, allowed_address) = listen(0).await?;

        let _to_denied = TcpStream::connect(denied_address).await?;
        let _to_allowed = TcpStream::connect(allowed_address).await?;
        assert!(
            timeout(Duration::from_secs(5), allowed.recv())
                .await?
                .is_some(),
            "the connection to the other port should be accepted"
        );
        assert!(
            timeout(Duration::from_millis(200), denied.recv())
                .await
                .is_err(),
            "the connection to the denied port should not reach the guest"
        );
        Ok(())
    })
    .await?;
    Ok(())
}
