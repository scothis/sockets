use std::time::Duration;

use gate_tests::{
    collect, ip_socket_address, loopback, socket_addr, ErrorCode, Harness, HostLatch,
    IpAddressFamily, LogEntry,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
async fn create_abstained() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types").build().await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(gate.recorder().operations(), vec!["tcp-socket.create"]);
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_denied() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.create"]))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
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
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: boom")
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "Latch error CODE=boom OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
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
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    // latch-deny-bind decides every operation itself, the host latch is never consulted
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS=127.0.0.1:0"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_abstained() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types").build().await?;
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
    assert_eq!(
        gate.recorder().operations(),
        vec!["tcp-socket.create", "tcp-socket.connect"]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_denied_by_latch_component() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .latch("latch-deny-connect")
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
        vec![LogEntry::warn(format!(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.connect REMOTE-ADDRESS={}",
            listener.local_addr()?
        ))]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_denied() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.listen"]))
        .build()
        .await?;
    let denied = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            Ok(matches!(
                tcp.call_listen(accessor, socket).await?,
                Err(ErrorCode::AccessDenied)
            ))
        })
        .await?;
    assert!(denied);
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.listen"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_forwards_connections() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types").build().await?;
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
        assert!(accepted.is_some(), "connection should be forwarded");
        Ok(())
    })
    .await?;
    assert_eq!(
        gate.recorder().operations(),
        vec![
            "tcp-socket.create",
            "tcp-socket.bind",
            "tcp-socket.listen",
            "tcp-socket.listen.connection",
        ]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_connection_denied() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.listen.connection"]))
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
        assert!(
            timeout(Duration::from_millis(500), connections.recv())
                .await
                .is_err(),
            "denied connection should not be forwarded"
        );
        Ok(())
    })
    .await?;
    assert!(gate
        .recorder()
        .operations()
        .contains(&"tcp-socket.listen.connection".to_string()));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.listen.connection"
        )]
    );
    Ok(())
}
