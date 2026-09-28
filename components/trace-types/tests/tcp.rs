use std::time::Duration;

use test_harness::{
    Harness, IpAddressFamily, LogEntry, collect, ip_socket_address, loopback, socket_addr,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
async fn create_traced() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(trace.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        trace.recorder().logs(),
        vec![LogEntry::trace(
            "componentized-trace",
            "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_traced() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    // the upstream error is passed through
    assert!(result.is_ok());
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_traced() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
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
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#tcp-socket.connect SOCKET=--- REMOTE-ADDRESS={}",
                    listener.local_addr()?
                )
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_forwards_connections() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-types").build().await?;
    let (local_address, remote_address) = trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
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
            let accepted = timeout(Duration::from_secs(5), connections.recv()).await?;
            assert!(accepted.is_some(), "connection should be forwarded");
            // the accepted connection is local to the listener, and remote to the client
            Ok((socket_addr(address), client.local_addr()?))
        })
        .await?;
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
            ),
            LogEntry::trace(
                "componentized-trace",
                format!("OPERATION=wasi:sockets/types#tcp-socket.listen SOCKET={local_address}<--")
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#tcp-socket.get-local-address SOCKET={local_address}<--"
                )
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#tcp-socket.listen SOCKET={local_address}<->{remote_address}"
                )
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn listen_forwards_connections_from_multiple_listeners() -> wasmtime::Result<()> {
    let peer = TcpListener::bind("127.0.0.1:0").await?;
    let peer_address = ip_socket_address(peer.local_addr()?);

    let mut trace = Harness::new("trace-types").build().await?;
    let accepted = trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
            let mut accepted = vec![];

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
            let client = TcpStream::connect(socket_addr(first_address)).await?;
            let connection = timeout(Duration::from_secs(5), first_connections.recv()).await?;
            assert!(connection.is_some(), "first listener should forward");
            accepted.push((socket_addr(first_address), client.local_addr()?));

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
            let client = TcpStream::connect(socket_addr(second_address)).await?;
            let connection = timeout(Duration::from_secs(5), second_connections.recv()).await?;
            assert!(connection.is_some(), "second listener should forward");
            accepted.push((socket_addr(second_address), client.local_addr()?));

            // the first listener keeps forwarding
            let client = TcpStream::connect(socket_addr(first_address)).await?;
            let connection = timeout(Duration::from_secs(5), first_connections.recv()).await?;
            assert!(
                connection.is_some(),
                "first listener should keep forwarding"
            );
            accepted.push((socket_addr(first_address), client.local_addr()?));
            Ok(accepted)
        })
        .await?;
    let connections: Vec<String> = trace
        .recorder()
        .logs()
        .into_iter()
        .map(|log| log.message)
        .filter(|message| {
            message.starts_with("OPERATION=wasi:sockets/types#tcp-socket.listen")
                && message.contains("<->")
        })
        .collect();
    let expected: Vec<String> = accepted
        .iter()
        .map(|(local_address, remote_address)| {
            format!("OPERATION=wasi:sockets/types#tcp-socket.listen SOCKET={local_address}<->{remote_address}")
        })
        .collect();
    assert_eq!(connections, expected);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn options_traced() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-types").build().await?;
    trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            tcp.call_set_keep_alive_enabled(accessor, socket, true)
                .await?
                .expect("set keep alive enabled");
            let enabled = tcp
                .call_get_keep_alive_enabled(accessor, socket)
                .await?
                .expect("get keep alive enabled");
            assert!(enabled);
            let family = tcp.call_get_address_family(accessor, socket).await?;
            assert_eq!(family, IpAddressFamily::Ipv4);
            Ok(())
        })
        .await?;
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.set-keep-alive-enabled SOCKET=--- VALUE=true"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.get-keep-alive-enabled SOCKET=---"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.get-address-family SOCKET=---"
            ),
        ]
    );
    Ok(())
}
