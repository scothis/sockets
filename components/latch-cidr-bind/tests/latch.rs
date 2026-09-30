use std::time::Duration;

use test_harness::{ErrorCode, Harness, IpAddressFamily, LogEntry, ip_socket_address, loopback};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const LATCH: &str = "latch-cidr-bind";

/// A port that is free on loopback, the listener is closed so the guest can bind it.
fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_bind_denied_to_matching_range() -> wasmtime::Result<()> {
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
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_bind_denied_to_matching_range() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("deny", "127.0.0.0/8")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(udp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_deferred_for_unmatched_range() -> wasmtime::Result<()> {
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
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_restricted_by_local_port() -> wasmtime::Result<()> {
    let allowed_port = free_port()?;
    assert!(allowed_port >= 1024, "ephemeral ports are unprivileged");

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .config("defer", "127.0.0.1:1024-65535")
        .build()
        .await?;
    let (allowed, privileged, any_port) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let bind = async |port| -> wasmtime::Result<_> {
                let socket = tcp
                    .call_create(accessor, IpAddressFamily::Ipv4)
                    .await?
                    .expect("create");
                Ok(tcp.call_bind(accessor, socket, loopback(port)).await?)
            };
            Ok((bind(allowed_port).await?, bind(80).await?, bind(0).await?))
        })
        .await?;
    assert!(allowed.is_ok());
    assert!(matches!(privileged, Err(ErrorCode::AccessDenied)));
    // port 0 asks for any free port, it is not in the deferred port range
    assert!(matches!(any_port, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unspecified_address_is_not_covered_by_specific_ranges() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .config("defer", "127.0.0.1")
        .build()
        .await?;
    let (loopback_bind, unspecified_bind) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let first = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let loopback_bind = tcp.call_bind(accessor, first, loopback(0)).await?;
            let second = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let unspecified = ip_socket_address("0.0.0.0:0".parse()?);
            let unspecified_bind = tcp.call_bind(accessor, second, unspecified).await?;
            Ok((loopback_bind, unspecified_bind))
        })
        .await?;
    assert!(loopback_bind.is_ok());
    // binding every local address is not binding loopback
    assert!(matches!(unspecified_bind, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn implicit_binds_are_not_checked() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .config("default", "deny")
        .build()
        .await?;
    let (listened, sent) = gate
        .run(async |accessor, gate| {
            // listen and send bind the sockets implicitly, there is no bind operation to check
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let listened = tcp.call_listen(accessor, socket).await?.is_ok();

            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(peer_address))
                .await?;
            Ok((listened, sent))
        })
        .await?;
    assert!(listened);
    assert!(sent.is_ok());

    let mut buf = [0; 16];
    let (len, from) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    assert_ne!(from.port(), 0, "the socket was bound to an ephemeral port");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_config_fails_every_bind() -> wasmtime::Result<()> {
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
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<latch-cidr-bind>")
    );
    Ok(())
}
