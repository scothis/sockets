use gate_tests::{Harness, HostLatch, LogEntry};

#[tokio::test(flavor = "multi_thread")]
async fn resolve_addresses_abstained() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup").build().await?;
    let result = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            Ok(lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?)
        })
        .await?;
    let addresses = result.expect("resolve addresses");
    assert!(!addresses.is_empty());
    let operations = gate.recorder().operations();
    assert_eq!(operations[0], "ip-name-lookup.resolve-addresses");
    assert!(operations[1..]
        .iter()
        .all(|op| op == "ip-name-lookup.resolve-addresses.return"));
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_addresses_denied() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .host_latch(HostLatch::deny(&["ip-name-lookup.resolve-addresses"]))
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            Ok(lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?)
        })
        .await?;
    assert!(result.is_err());
    assert_eq!(
        gate.recorder().operations(),
        vec!["ip-name-lookup.resolve-addresses"]
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "Denied REASON=access-denied OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
        )]
    );
    Ok(())
}
