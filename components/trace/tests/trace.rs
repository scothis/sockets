//! Tests for the `trace` component, composed from `trace.wac`. Tests for the
//! individual interfaces live with each trace component.

use test_harness::{Harness, IpAddressFamily, LogEntry};

#[tokio::test(flavor = "multi_thread")]
async fn exports_traced_types_and_ip_name_lookup() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace").build().await?;
    let (created, resolved) = trace
        .run(async |accessor, trace| {
            let tcp = trace.wasi_sockets_types().tcp_socket();
            let created = tcp.call_create(accessor, IpAddressFamily::Ipv4).await?;
            let resolved = trace
                .wasi_sockets_ip_name_lookup()
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            Ok((created.is_ok(), resolved.is_ok()))
        })
        .await?;
    assert!(created);
    assert!(resolved);
    assert_eq!(
        trace.recorder().logs(),
        vec![
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-trace",
                "OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
            ),
        ]
    );
    Ok(())
}
