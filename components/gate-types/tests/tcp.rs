use std::time::Duration;

use test_harness::bindings::componentized::sockets::latch::{
    Decision, ErrorCode as LatchErrorCode,
};
use test_harness::{
    ErrorCode, Harness, HostLatch, IpAddressFamily, LogEntry, Observation, collect,
    ip_socket_address, loopback, resolve, socket_addr, stream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
async fn create_deferred() -> wasmtime::Result<()> {
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
            "componentized-gate",
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
            "componentized-gate",
            "Latch error CODE=boom OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_latch_invalid_config() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::invalid_config("my-latch"))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<my-latch>")
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "componentized-gate",
            "Latch error CODE=invalid-config<my-latch> OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
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
            "componentized-gate",
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_deferred() -> wasmtime::Result<()> {
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
async fn listen_denied() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.listen"]))
        .build()
        .await?;
    let (denied, local_address) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let local_address = tcp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            let denied = matches!(
                tcp.call_listen(accessor, socket).await?,
                Err(ErrorCode::AccessDenied)
            );
            Ok((denied, socket_addr(local_address)))
        })
        .await?;
    assert!(denied);
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.listen SOCKET={local_address}<--"
            )
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
    let (local_address, remote_address) = gate
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
                timeout(Duration::from_millis(500), connections.recv())
                    .await
                    .is_err(),
                "denied connection should not be forwarded"
            );
            // the accepted connection is local to the listener, and remote to the client
            Ok((socket_addr(address), client.local_addr()?))
        })
        .await?;
    assert!(
        gate.recorder()
            .operations()
            .contains(&"tcp-socket.listen.connection".to_string())
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.listen SOCKET={local_address}<->{remote_address}"
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_forwards_connections_from_multiple_listeners() -> wasmtime::Result<()> {
    let peer = TcpListener::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types").build().await?;
    gate.run(async |accessor, gate| {
        let tcp = gate.wasi_sockets_types().tcp_socket();

        // the first listen starts the background executor
        let first = tcp
            .call_create(accessor, IpAddressFamily::Ipv4)
            .await?
            .expect("create");
        tcp.call_bind(accessor, first, loopback(0))
            .await?
            .expect("bind");
        let first_connections = tcp.call_listen(accessor, first).await?.expect("listen");
        let first_address = tcp
            .call_get_local_address(accessor, first)
            .await?
            .expect("local address");
        let mut first_connections = collect(accessor, first_connections)?;
        let _client = TcpStream::connect(socket_addr(first_address)).await?;
        let accepted = timeout(Duration::from_secs(5), first_connections.recv()).await?;
        assert!(accepted.is_some(), "first listener should forward");

        // an async export runs while the executor is parked
        let outbound = tcp
            .call_create(accessor, IpAddressFamily::Ipv4)
            .await?
            .expect("create");
        tcp.call_connect(accessor, outbound, peer_address)
            .await?
            .expect("connect");
        timeout(Duration::from_secs(5), peer.accept()).await??;

        // the second listen, from another task, wakes the parked executor
        let second = tcp
            .call_create(accessor, IpAddressFamily::Ipv4)
            .await?
            .expect("create");
        tcp.call_bind(accessor, second, loopback(0))
            .await?
            .expect("bind");
        let second_connections = tcp.call_listen(accessor, second).await?.expect("listen");
        let second_address = tcp
            .call_get_local_address(accessor, second)
            .await?
            .expect("local address");
        let mut second_connections = collect(accessor, second_connections)?;
        let _client = TcpStream::connect(socket_addr(second_address)).await?;
        let accepted = timeout(Duration::from_secs(5), second_connections.recv()).await?;
        assert!(accepted.is_some(), "second listener should forward");

        // the first listener keeps forwarding
        let _client = TcpStream::connect(socket_addr(first_address)).await?;
        let accepted = timeout(Duration::from_secs(5), first_connections.recv()).await?;
        assert!(accepted.is_some(), "first listener should keep forwarding");
        Ok(())
    })
    .await?;
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_deferred() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types").build().await?;
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

            let data = stream(accessor, b"hello".to_vec())?;
            // the future comes straight from the host socket, see `resolve`
            let _sent = tcp.call_send(accessor, socket, data).await?;

            // the data stream closed, so the peer reads to the end
            let mut received = vec![];
            timeout(Duration::from_secs(5), peer.read_to_end(&mut received)).await??;
            Ok(received)
        })
        .await?;
    assert_eq!(received, b"hello");
    assert_eq!(
        gate.recorder().operations(),
        vec!["tcp-socket.create", "tcp-socket.connect", "tcp-socket.send"]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_denied() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.send"]))
        .build()
        .await?;
    let (result, local_address) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_connect(accessor, socket, address)
                .await?
                .expect("connect");
            let (mut peer, local_address) =
                timeout(Duration::from_secs(5), listener.accept()).await??;

            let data = stream(accessor, b"hello".to_vec())?;
            let sent = tcp.call_send(accessor, socket, data).await?;
            let result = timeout(Duration::from_secs(5), resolve(accessor, sent)).await??;

            let mut buf = [0; 16];
            assert!(
                timeout(Duration::from_millis(200), peer.read(&mut buf))
                    .await
                    .is_err(),
                "no data should reach the peer"
            );
            Ok((result, local_address))
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.send SOCKET={local_address}<->{}",
                listener.local_addr()?
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_latch_error() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::new(|auth| {
            if auth.operation == "tcp-socket.send" {
                Err(LatchErrorCode::Other(Some("boom".to_string())))
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
            tcp.call_connect(accessor, socket, address)
                .await?
                .expect("connect");
            let data = stream(accessor, b"hello".to_vec())?;
            let sent = tcp.call_send(accessor, socket, data).await?;
            Ok(timeout(Duration::from_secs(5), resolve(accessor, sent)).await??)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: boom")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_deferred() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types").build().await?;
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
            peer.write_all(b"hello").await?;
            peer.shutdown().await?;

            // the future comes straight from the host socket, see `resolve`
            let (data, _done) = tcp.call_receive(accessor, socket).await?;
            let mut data = collect(accessor, data)?;
            let mut received = vec![];
            while let Some(byte) = timeout(Duration::from_secs(5), data.recv()).await? {
                received.push(byte);
            }
            Ok(received)
        })
        .await?;
    assert_eq!(received, b"hello");
    assert_eq!(
        gate.recorder().operations(),
        vec![
            "tcp-socket.create",
            "tcp-socket.connect",
            "tcp-socket.receive"
        ]
    );
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_denied() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.receive"]))
        .build()
        .await?;
    let (received, result, local_address) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_connect(accessor, socket, address)
                .await?
                .expect("connect");
            let (mut peer, local_address) =
                timeout(Duration::from_secs(5), listener.accept()).await??;
            peer.write_all(b"hello").await?;

            let (data, done) = tcp.call_receive(accessor, socket).await?;
            let mut data = collect(accessor, data)?;
            let mut received = vec![];
            while let Some(byte) = timeout(Duration::from_secs(5), data.recv()).await? {
                received.push(byte);
            }
            let result = timeout(Duration::from_secs(5), resolve(accessor, done)).await??;
            Ok((received, result, local_address))
        })
        .await?;
    assert_eq!(received, Vec::<u8>::new());
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            format!(
                "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.receive SOCKET={local_address}<->{}",
                listener.local_addr()?
            )
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn decisions_are_observed() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::deny(&["tcp-socket.bind"]))
        .build()
        .await?;
    let bound = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(matches!(bound, Err(ErrorCode::AccessDenied)));
    // both deferred and denied decisions are passed back to the latch
    assert_eq!(
        gate.recorder().observations(),
        vec![
            Observation {
                operation: "tcp-socket.create".to_string(),
                denied: false,
            },
            Observation {
                operation: "tcp-socket.bind".to_string(),
                denied: true,
            },
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_failure_fails_the_operation() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .host_latch(HostLatch::defer().fail_observe())
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    // the latch could not act on the decision, so the operation is not allowed
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: observation-failed<host>")
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "componentized-gate",
            "Latch error CODE=observation-failed<host> OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}
