use std::time::Duration;

use gate_tests::bindings::componentized::sockets::latch::{Decision, ErrorCode as LatchErrorCode};
use gate_tests::{
    ip_socket_address, loopback, socket_addr, ErrorCode, Harness, HostLatch, IpAddressFamily,
    LogEntry,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
async fn create_abstained() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types").build().await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            Ok(udp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(gate.recorder().operations(), vec!["udp-socket.create"]);
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_denied() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["udp-socket.create"]))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            Ok(udp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(gate.recorder().operations(), vec!["udp-socket.create"]);
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_latch_error() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
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
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "Latch error CODE=boom OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_denied_by_latch_component() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch("latch-deny-bind")
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
    // latch-deny-bind decides every operation itself, the host latch is never consulted
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.bind LOCAL-ADDRESS=127.0.0.1:0"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_abstained() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types").build().await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_connect(accessor, socket, address).await?.expect("connect");
            Ok(udp.call_get_remote_address(accessor, socket).await?)
        })
        .await?;
    assert_eq!(socket_addr(result.expect("remote address")), peer.local_addr()?);
    assert_eq!(
        gate.recorder().operations(),
        vec!["udp-socket.create", "udp-socket.connect"]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_denied_by_latch_component() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch("latch-deny-connect")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(udp.call_connect(accessor, socket, address).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(format!(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.connect REMOTE-ADDRESS={}",
            peer.local_addr()?
        ))]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_abstained() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types").build().await?;
    let (result, local_address) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0)).await?.expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            let result = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            Ok((result, local_address))
        })
        .await?;
    assert!(result.is_ok());

    let mut buf = [0; 16];
    let (len, from) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(from, socket_addr(local_address));

    assert_eq!(
        gate.recorder().operations(),
        vec!["udp-socket.create", "udp-socket.bind", "udp-socket.send"]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_denied() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["udp-socket.send"]))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0)).await?.expect("bind");
            Ok(udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?)
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

    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(format!(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.send DATA-LENGTH=5 REMOTE-ADDRESS=some<{}>",
            peer.local_addr()?
        ))]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_abstained() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;

    let mut gate = Harness::new("gate-types").build().await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0)).await?.expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            peer.send_to(b"hello", socket_addr(local_address)).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    let (data, remote_address) = result.expect("receive");
    assert_eq!(data, b"hello");
    assert_eq!(socket_addr(remote_address), peer.local_addr()?);
    assert_eq!(
        gate.recorder().operations(),
        vec!["udp-socket.create", "udp-socket.bind", "udp-socket.receive"]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_denied() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;

    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["udp-socket.receive"]))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0)).await?.expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            peer.send_to(b"hello", socket_addr(local_address)).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(format!(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#udp-socket.receive DATA-LENGTH=5 REMOTE-ADDRESS={}",
            peer.local_addr()?
        ))]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_latch_error() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;

    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::new(|auth| {
            if auth.operation == "udp-socket.receive" {
                Err(LatchErrorCode::Other(Some("boom".to_string())))
            } else {
                Ok(Decision::Abstained)
            }
        }))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0)).await?.expect("bind");
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            peer.send_to(b"hello", socket_addr(local_address)).await?;
            Ok(timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: boom")
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(format!(
            "Latch error CODE=boom OPERATION=wasi:sockets/types#udp-socket.receive DATA-LENGTH=5 REMOTE-ADDRESS={}",
            peer.local_addr()?
        ))]
    );
    Ok(())
}
