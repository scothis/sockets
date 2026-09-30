use test_harness::bindings::exports::wasi::sockets::ip_name_lookup::ErrorCode;
use test_harness::{Harness, HostLatch, LogEntry, Observation};

#[tokio::test(flavor = "multi_thread")]
async fn resolve_addresses_deferred() -> wasmtime::Result<()> {
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
    assert!(
        operations[1..]
            .iter()
            .all(|op| op == "ip-name-lookup.resolve-addresses.return")
    );
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
            "componentized-gate",
            "Denied REASON=access-denied OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_addresses_latch_invalid_config() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .host_latch(HostLatch::invalid_config("my-latch"))
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
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<my-latch>")
    );
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "componentized-gate",
            "Latch error CODE=invalid-config<my-latch> OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_addresses_decisions_are_observed() -> wasmtime::Result<()> {
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
    // the lookup and every returned address are observed
    let observations = gate.recorder().observations();
    assert_eq!(observations.len(), 1 + addresses.len());
    assert_eq!(
        observations[0],
        Observation {
            operation: "ip-name-lookup.resolve-addresses".to_string(),
            denied: false,
        }
    );
    assert!(
        observations[1..]
            .iter()
            .all(|o| o.operation == "ip-name-lookup.resolve-addresses.return" && !o.denied)
    );
    Ok(())
}
