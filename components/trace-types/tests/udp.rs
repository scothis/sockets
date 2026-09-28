use std::time::Duration;

use test_harness::{Harness, IpAddressFamily, LogEntry, ip_socket_address, loopback, socket_addr};
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
async fn create_traced() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let udp = trace.wasi_sockets_types().udp_socket();
            Ok(udp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(trace.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        trace.recorder().logs(),
        vec![LogEntry::trace(
            "componentized-trace",
            "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_traced() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let udp = trace.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(udp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(result.is_ok());
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_traced() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let udp = trace.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_connect(accessor, socket, address)
                .await?
                .expect("connect");
            let remote_address = udp.call_get_remote_address(accessor, socket).await?;
            // connect implicitly binds the socket to an ephemeral local address
            let local_address = udp
                .call_get_local_address(accessor, socket)
                .await?
                .expect("local address");
            udp.call_disconnect(accessor, socket)
                .await?
                .expect("disconnect");
            Ok((remote_address, socket_addr(local_address)))
        })
        .await?;
    let (remote_address, local_address) = result;
    let remote_address = socket_addr(remote_address.expect("remote address"));
    assert_eq!(remote_address, peer.local_addr()?);
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.connect SOCKET=--- REMOTE-ADDRESS={}",
                    peer.local_addr()?
                )
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.get-remote-address SOCKET={local_address}<->{remote_address}"
                )
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.get-local-address SOCKET={local_address}<->{remote_address}"
                )
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.disconnect SOCKET={local_address}<->{remote_address}"
                )
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_traced() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut trace = Harness::new("trace-types").build().await?;
    let (result, local_address) = trace
        .run(async |accessor, trace| {
            let udp = trace.wasi_sockets_types().udp_socket();
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
            Ok((result, local_address))
        })
        .await?;
    assert!(result.is_ok());
    let local_address = socket_addr(local_address);

    let mut buf = [0; 16];
    let (len, from) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(from, local_address);

    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.get-local-address SOCKET={local_address}<--"
                )
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.send SOCKET={local_address}<-- DATA-LENGTH=5 REMOTE-ADDRESS=some<{}>",
                    peer.local_addr()?
                )
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_connected_traced() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut trace = Harness::new("trace-types").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let udp = trace.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_connect(accessor, socket, address)
                .await?
                .expect("connect");
            let result = udp
                .call_send(accessor, socket, b"hello".to_vec(), None)
                .await?;
            Ok(result)
        })
        .await?;
    assert!(result.is_ok());

    let mut buf = [0; 16];
    // connect implicitly binds the socket to an ephemeral local address
    let (len, local_address) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");

    assert_eq!(
        trace.recorder().logs().last(),
        Some(&LogEntry::trace(
            "componentized-trace",
            format!(
                "OPERATION=wasi:sockets/types#udp-socket.send SOCKET={local_address}<->{} DATA-LENGTH=5 REMOTE-ADDRESS=none",
                peer.local_addr()?
            )
        ))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_traced() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;

    let mut trace = Harness::new("trace-types").build().await?;
    let (result, local_address) = trace
        .run(async |accessor, trace| {
            let udp = trace.wasi_sockets_types().udp_socket();
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
            let result =
                timeout(Duration::from_secs(5), udp.call_receive(accessor, socket)).await??;
            Ok((result, socket_addr(local_address)))
        })
        .await?;
    let (data, remote_address) = result.expect("receive");
    assert_eq!(data, b"hello");
    assert_eq!(socket_addr(remote_address), peer.local_addr()?);
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#udp-socket.bind SOCKET=--- LOCAL-ADDRESS=127.0.0.1:0"
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.get-local-address SOCKET={local_address}<--"
                )
            ),
            LogEntry::trace(
                "componentized-trace",
                format!(
                    "OPERATION=wasi:sockets/types#udp-socket.receive SOCKET={local_address}<--"
                )
            ),
        ]
    );
    Ok(())
}
