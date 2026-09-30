//! Tests for the ranges in `latch-deny-private-networks-cidr-config`, directly and through the
//! `test-latch-deny-private-networks` component, composed from
//! `test-latch-deny-private-networks.wac`.

use std::time::Duration;

use latch_cidr::{Action, Ranges};
use test_harness::{ErrorCode, Harness, IpAddressFamily, ip_socket_address, loopback};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const LATCH: &str = "test-latch-deny-private-networks";

/// The ranges from the config component's properties file.
fn preset() -> Ranges {
    let properties = include_str!(
        "../../latch-deny-private-networks-cidr-config/latch-deny-private-networks-cidr-config.properties"
    );
    let config = properties
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line.split_once('=').expect("key=value");
            (key.to_string(), value.to_string())
        });
    let ranges = Ranges::parse(config).expect("valid config");
    assert!(ranges.warnings().is_empty(), "{:?}", ranges.warnings());
    ranges
}

#[test]
fn denies_addresses_that_are_not_globally_reachable() {
    let ranges = preset();
    for address in [
        "0.0.0.0",
        "0.255.255.255",
        "10.1.2.3",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "127.255.255.254",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",
        "2001:db8::1",
        "2002:a00:1::1",
        "3fff::1",
        "fc00::1",
        "fd00:ec2::254",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ] {
        for port in [0, 80, 443, 65535] {
            assert_eq!(
                ranges.action(address.parse().unwrap(), port),
                Action::Deny,
                "{address} port {port}"
            );
        }
    }
}

#[test]
fn defers_for_globally_reachable_addresses() {
    let ranges = preset();
    for address in [
        "1.1.1.1",
        "8.8.8.8",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "::ffff:8.8.8.8",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
        "2a00:1450::1",
    ] {
        assert_eq!(
            ranges.action(address.parse().unwrap(), 443),
            Action::Defer,
            "{address}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn denies_loopback() -> wasmtime::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_address = ip_socket_address(listener.local_addr()?);
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_address = ip_socket_address(peer.local_addr()?);

    let mut gate = Harness::new("gate-types").latch(LATCH).build().await?;
    let (connected, sent) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            let connected = tcp.call_connect(accessor, socket, tcp_address).await?;

            let udp = gate.wasi_sockets_types().udp_socket();
            let socket = udp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            udp.call_bind(accessor, socket, loopback(0))
                .await?
                .expect("bind");
            let sent = udp
                .call_send(accessor, socket, b"hello".to_vec(), Some(udp_address))
                .await?;
            Ok((connected, sent))
        })
        .await?;
    assert!(matches!(connected, Err(ErrorCode::AccessDenied)));
    assert!(matches!(sent, Err(ErrorCode::AccessDenied)));
    assert!(
        timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "no connection should reach the listener"
    );
    // the preset has no config issues
    assert!(
        gate.recorder()
            .logs()
            .iter()
            .all(|log| log.context != "componentized-latch"),
        "{:?}",
        gate.recorder().logs()
    );
    Ok(())
}
