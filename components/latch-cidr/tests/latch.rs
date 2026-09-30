//! Tests for the `latch-cidr` component, composed from `latch-cidr.wac`. Tests for the
//! individual latches live with each latch component.

use std::time::Duration;

use test_harness::{
    ErrorCode, Harness, IpAddressFamily, collect, ip_socket_address, loopback, socket_addr,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const LATCH: &str = "latch-cidr";

#[tokio::test(flavor = "multi_thread")]
async fn restricts_both_directions() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "127.0.0.0/8")
        .build()
        .await?;
    let connected = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();

            // outbound
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let connected = tcp.call_connect(accessor, socket, address).await?;

            // inbound
            let server = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_bind(accessor, server, loopback(0))
                .await?
                .expect("bind");
            let connections = tcp.call_listen(accessor, server).await?.expect("listen");
            let server_address = tcp
                .call_get_local_address(accessor, server)
                .await?
                .expect("local address");
            let mut connections = collect(accessor, connections)?;
            let _client = TcpStream::connect(socket_addr(server_address)).await?;
            assert!(
                timeout(Duration::from_millis(200), connections.recv())
                    .await
                    .is_err(),
                "the inbound connection should not reach the guest"
            );
            Ok(connected)
        })
        .await?;
    assert!(matches!(connected, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn allows_both_directions() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .config("defer", "127.0.0.1")
        .build()
        .await?;
    gate.run(async |accessor, gate| {
        let tcp = gate.wasi_sockets_types().tcp_socket();

        let socket = tcp
            .call_create(accessor, IpAddressFamily::Ipv4)
            .await?
            .expect("create");
        tcp.call_connect(accessor, socket, address)
            .await?
            .expect("connect");
        timeout(Duration::from_secs(5), listener.accept()).await??;

        let server = tcp
            .call_create(accessor, IpAddressFamily::Ipv4)
            .await?
            .expect("create");
        tcp.call_bind(accessor, server, loopback(0))
            .await?
            .expect("bind");
        let connections = tcp.call_listen(accessor, server).await?.expect("listen");
        let server_address = tcp
            .call_get_local_address(accessor, server)
            .await?
            .expect("local address");
        let mut connections = collect(accessor, connections)?;
        let _client = TcpStream::connect(socket_addr(server_address)).await?;
        let accepted = timeout(Duration::from_secs(5), connections.recv()).await?;
        assert!(accepted.is_some(), "connection should be accepted");
        Ok(())
    })
    .await?;
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unsolicited_datagram_does_not_open_egress() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let (received, sent) = gate
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

            // ingress drops the datagram before egress can remember its sender, the receive keeps
            // waiting for a datagram that is allowed, there is none
            peer.send_to(b"hello", socket_addr(local_address)).await?;
            let received = timeout(
                Duration::from_millis(500),
                udp.call_receive(accessor, socket),
            )
            .await;
            let sent = udp
                .call_send(accessor, socket, b"reply".to_vec(), Some(peer_address))
                .await?;
            Ok((received.is_err(), sent))
        })
        .await?;
    assert!(received, "no datagram should reach the guest");
    assert!(matches!(sent, Err(ErrorCode::AccessDenied)));
    // the dropped datagram was seen by the latches
    let logs = gate.recorder().logs();
    assert!(
        logs.iter().any(|log| log
            .message
            .contains("OPERATION=wasi:sockets/types#udp-socket.receive")),
        "{logs:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_config() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "10.0.0.0/33")
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
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<latch-cidr-egress>")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_send_does_not_open_ingress() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let (first, received, second) = gate
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

            // egress denies the send, ingress observes the denial and does not remember the peer
            let first = udp
                .call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?;
            peer.send_to(b"pong", socket_addr(local_address)).await?;
            let received = timeout(
                Duration::from_millis(500),
                udp.call_receive(accessor, socket),
            )
            .await;
            let second = udp
                .call_send(accessor, socket, b"ping".to_vec(), Some(peer_address))
                .await?;
            Ok((first, received.is_err(), second))
        })
        .await?;
    assert!(matches!(first, Err(ErrorCode::AccessDenied)));
    assert!(received, "the peer's datagram should not reach the guest");
    assert!(matches!(second, Err(ErrorCode::AccessDenied)));
    Ok(())
}
