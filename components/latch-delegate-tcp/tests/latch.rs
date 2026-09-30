use test_harness::bindings::componentized::sockets::latch::{Decision, SocketsErrorCode};
use test_harness::{Harness, HostLatch, IpAddressFamily, Observation};

const LATCH: &str = "latch-delegate-tcp";

#[tokio::test(flavor = "multi_thread")]
async fn delegates_only_tcp_operations() -> wasmtime::Result<()> {
    // the wrapped latch denies everything it is asked about
    let mut gate = Harness::new("gate")
        .latch(LATCH)
        .host_latch(HostLatch::new(|_| {
            Ok(Decision::Denied(SocketsErrorCode::AccessDenied))
        }))
        .build()
        .await?;
    let (tcp, udp, ip) = gate
        .run(async |accessor, gate| {
            let tcp = gate
                .wasi_sockets_types()
                .tcp_socket()
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?;
            let udp = gate
                .wasi_sockets_types()
                .udp_socket()
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?;
            let ip = gate
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            Ok((tcp.is_ok(), udp.is_ok(), ip.is_ok()))
        })
        .await?;
    assert!(!tcp, "tcp operations are delegated to the wrapped latch");
    assert!(udp, "other operations are deferred without delegation");
    assert!(ip, "other operations are deferred without delegation");
    // the wrapped latch neither authorizes nor observes the other operations
    assert_eq!(gate.recorder().operations(), vec!["tcp-socket.create"]);
    assert_eq!(
        gate.recorder().observations(),
        vec![Observation {
            operation: "tcp-socket.create".to_string(),
            denied: true,
        }]
    );
    Ok(())
}
