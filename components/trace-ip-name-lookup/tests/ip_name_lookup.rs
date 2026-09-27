use test_harness::{Harness, LogEntry};

#[tokio::test(flavor = "multi_thread")]
async fn resolve_addresses_traced() -> wasmtime::Result<()> {
    let mut trace = Harness::new("trace-ip-name-lookup").build().await?;
    let result = trace
        .run(async |accessor, trace| {
            let lookup = trace.wasi_sockets_ip_name_lookup();
            Ok(lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?)
        })
        .await?;
    let addresses = result.expect("resolve addresses");
    assert!(!addresses.is_empty());
    assert_eq!(trace.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        trace.recorder().logs(),
        vec![LogEntry::trace(
            "componentized-trace",
            "OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
        )]
    );
    Ok(())
}
