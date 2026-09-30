//! The latch tracks the addresses returned by ip-name-lookup and denies connecting to any other
//! address. It is tested against the composed `gate` so lookups and connects share one latch
//! instance.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use test_harness::bindings::componentized::sockets::latch::{
    Decision, ErrorCode as LatchErrorCode, SocketsErrorCode,
};
use test_harness::bindings::exports::wasi::sockets::ip_name_lookup::ErrorCode as LookupErrorCode;
use test_harness::bindings::wasi::sockets::types::IpAddress;
use test_harness::{
    ErrorCode, Harness, HostLatch, IpAddressFamily, LogEntry, Observation, ip_socket_address,
    loopback,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const LATCH: &str = "latch-deny-connect-unless-lookup-address";

fn has_localhost_v4(addresses: &[IpAddress]) -> bool {
    addresses
        .iter()
        .any(|address| matches!(address, IpAddress::Ipv4((127, 0, 0, 1))))
}

fn is_localhost_v4(address: IpAddr) -> bool {
    address == IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_denied_without_lookup() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    // aggregated with the host latch, which defers everything
    let mut gate = Harness::new("gate")
        .latch(LATCH)
        .host_latch(HostLatch::defer())
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
    // latch-n stops at the first denial, the host latch is not asked about the connect but
    // observes the final decision
    assert_eq!(gate.recorder().operations(), vec!["tcp-socket.create"]);
    assert_eq!(
        gate.recorder().observations(),
        vec![
            Observation {
                operation: "tcp-socket.create".to_string(),
                denied: false,
            },
            Observation {
                operation: "tcp-socket.connect".to_string(),
                denied: true,
            },
        ]
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
async fn tcp_connect_deferred_after_lookup() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate").latch(LATCH).build().await?;
    let (addresses, result) = gate
        .run(async |accessor, gate| {
            let addresses = gate
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?
                .expect("resolve addresses");
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let result = tcp.call_connect(accessor, socket, address).await?;
            timeout(Duration::from_secs(5), listener.accept()).await??;
            Ok((addresses, result))
        })
        .await?;
    assert!(
        has_localhost_v4(&addresses),
        "localhost should resolve to 127.0.0.1, got {addresses:?}"
    );
    assert!(result.is_ok());
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_denied_to_address_filtered_from_lookup() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    // the aggregated latch removes the IPv4 addresses from the lookup, so they are never granted
    let mut gate = Harness::new("gate")
        .latch(LATCH)
        .host_latch(HostLatch::new(|auth| {
            if auth.operation == "ip-name-lookup.resolve-addresses.return"
                && auth.args.contains("Ipv4")
            {
                Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
            } else {
                Ok(Decision::Deferred)
            }
        }))
        .build()
        .await?;
    let (addresses, result) = gate
        .run(async |accessor, gate| {
            let addresses = gate
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?
                .expect("resolve addresses");
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok((
                addresses,
                tcp.call_connect(accessor, socket, address).await?,
            ))
        })
        .await?;
    assert!(!has_localhost_v4(&addresses));
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn aggregated_latch_denial_passes_through() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    // a distinct reason shows the aggregated latch's decision is returned, even for a granted address
    let mut gate = Harness::new("gate")
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
            gate.wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?
                .expect("resolve addresses");
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
    let mut gate = Harness::new("gate")
        .latch(LATCH)
        .host_latch(HostLatch::new(|auth| {
            if auth.operation == "ip-name-lookup.resolve-addresses" {
                Err(LatchErrorCode::Other(Some("boom".to_string())))
            } else {
                Ok(Decision::Deferred)
            }
        }))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            Ok(gate
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?)
        })
        .await?;
    assert!(
        matches!(result, Err(LookupErrorCode::Other(Some(ref message))) if message == "latch-error: boom")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_decided_by_aggregated_latch_component() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate")
        .latch(LATCH)
        .latch("latch-ip-name-lookup-glob")
        .config("default", "deny")
        .config("defer", "localhost")
        .build()
        .await?;
    let (denied, addresses, result) = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            let denied = lookup
                .call_resolve_addresses(accessor, "www.example.com".to_string())
                .await?;
            let addresses = lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?
                .expect("resolve addresses");
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let result = tcp.call_connect(accessor, socket, address).await?;
            timeout(Duration::from_secs(5), listener.accept()).await??;
            Ok((denied, addresses, result))
        })
        .await?;
    assert!(matches!(denied, Err(LookupErrorCode::AccessDenied)));
    assert!(has_localhost_v4(&addresses));
    assert!(result.is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_connect_denied_when_lookup_denied_by_aggregated_latch_component()
-> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(listener.local_addr()?);

    let mut gate = Harness::new("gate")
        .latch(LATCH)
        .latch("latch-ip-name-lookup-glob")
        .config("deny", "localhost")
        .build()
        .await?;
    let (lookup, result) = gate
        .run(async |accessor, gate| {
            let lookup = gate
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok((lookup, tcp.call_connect(accessor, socket, address).await?))
        })
        .await?;
    assert!(matches!(lookup, Err(LookupErrorCode::AccessDenied)));
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_connect_denied_without_lookup() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate").latch(LATCH).build().await?;
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
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_connect_and_send_deferred_after_lookup() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate").latch(LATCH).build().await?;
    let (connected, sent) = gate
        .run(async |accessor, gate| {
            gate.wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?
                .expect("resolve addresses");
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let connected = udp.call_connect(accessor, socket, address).await?;
            // a connected socket sends without a remote address
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), None)
                .await?;
            Ok((connected, sent))
        })
        .await?;
    assert!(connected.is_ok());
    assert!(sent.is_ok());

    let mut buf = [0; 16];
    let (len, from) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    assert!(is_localhost_v4(from.ip()));
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_send_denied_without_lookup() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate").latch(LATCH).build().await?;
    let (bound, sent) = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            // bind is not a connect, it does not need a looked up address
            let bound = udp.call_bind(accessor, socket, loopback(0)).await?;
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(address))
                .await?;
            Ok((bound, sent))
        })
        .await?;
    assert!(bound.is_ok());
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
async fn udp_send_deferred_after_lookup() -> wasmtime::Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate").latch(LATCH).build().await?;
    let sent = gate
        .run(async |accessor, gate| {
            gate.wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?
                .expect("resolve addresses");
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
    assert!(sent.is_ok());

    let mut buf = [0; 16];
    let (len, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..len], b"hello");
    Ok(())
}
