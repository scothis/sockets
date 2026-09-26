//! Tests for the composed `gate` component, which has no crate of its own. Tests for the
//! individual gates live with each gate component.

use gate_tests::{Harness, HostLatch, IpAddressFamily};

#[tokio::test(flavor = "multi_thread")]
async fn exports_gated_types_and_ip_name_lookup() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate")
        .host_latch(HostLatch::deny(&["tcp-socket.create"]))
        .build()
        .await?;
    let (created, resolved) = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let created = tcp.call_create(accessor, IpAddressFamily::Ipv4).await?;
            let resolved = gate
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            Ok((created.is_ok(), resolved.is_ok()))
        })
        .await?;
    assert!(!created, "tcp-socket.create should be denied");
    assert!(resolved, "resolve-addresses should be abstained");
    // both gates consult the same latch
    assert_eq!(
        gate.recorder().operations()[..2],
        ["tcp-socket.create", "ip-name-lookup.resolve-addresses"]
    );
    Ok(())
}
