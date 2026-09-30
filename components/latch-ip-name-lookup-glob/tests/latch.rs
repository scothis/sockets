use test_harness::bindings::exports::wasi::sockets::ip_name_lookup::ErrorCode;
use test_harness::{Harness, LogEntry};

#[tokio::test(flavor = "multi_thread")]
async fn denies_matching_name() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .latch("latch-ip-name-lookup-glob")
        .config("deny", "**.example.com")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            Ok(lookup
                .call_resolve_addresses(accessor, "www.example.com".to_string())
                .await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    // latch-ip-name-lookup-glob decides every operation itself, the host latch is never consulted
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            "Denied REASON=access-denied OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=www.example.com"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn defers_for_unmatched_name() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .latch("latch-ip-name-lookup-glob")
        .config("deny", "**.example.com")
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
    let addresses = result.expect("resolve addresses");
    assert!(!addresses.is_empty());
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    assert_eq!(gate.recorder().logs(), vec![]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn denies_with_configured_reason() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .latch("latch-ip-name-lookup-glob")
        .config("reason", "invalid-argument")
        .config("deny", "localhost")
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
    assert!(matches!(result, Err(ErrorCode::InvalidArgument)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            "Denied REASON=invalid-argument OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn default_deny_defers_for_matching_name() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .latch("latch-ip-name-lookup-glob")
        .config("default", "deny")
        .config("defer", "localhost")
        .build()
        .await?;
    let (deferred, denied) = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            let deferred = lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            let denied = lookup
                .call_resolve_addresses(accessor, "www.example.com".to_string())
                .await?;
            Ok((deferred, denied))
        })
        .await?;
    assert!(!deferred.expect("resolve addresses").is_empty());
    assert!(matches!(denied, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            "Denied REASON=access-denied OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=www.example.com"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn more_specific_pattern_decides() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .latch("latch-ip-name-lookup-glob")
        .config("defer", "localhost")
        .config("deny", "**")
        .build()
        .await?;
    let (deferred, denied) = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            let deferred = lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            let denied = lookup
                .call_resolve_addresses(accessor, "www.example.com".to_string())
                .await?;
            Ok((deferred, denied))
        })
        .await?;
    assert!(!deferred.expect("resolve addresses").is_empty());
    assert!(matches!(denied, Err(ErrorCode::AccessDenied)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_config_fails_every_lookup() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-ip-name-lookup")
        .latch("latch-ip-name-lookup-glob")
        .config("default", "grant")
        .build()
        .await?;
    let (first, second) = gate
        .run(async |accessor, gate| {
            let lookup = gate.wasi_sockets_ip_name_lookup();
            let first = lookup
                .call_resolve_addresses(accessor, "localhost".to_string())
                .await?;
            let second = lookup
                .call_resolve_addresses(accessor, "www.example.com".to_string())
                .await?;
            Ok((first, second))
        })
        .await?;
    for result in [first, second] {
        assert!(
            matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<latch-ip-name-lookup-glob>")
        );
    }
    // the cause is logged once when the config is loaded, the gate logs each failed lookup
    assert_eq!(
        gate.recorder().logs(),
        vec![
            LogEntry::critical(
                "componentized-latch",
                "Invalid config LATCH=latch-ip-name-lookup-glob KEY=default VALUE=grant ERROR=expected 'deny' or 'defer'"
            ),
            LogEntry::error(
                "componentized-gate",
                "Latch error CODE=invalid-config<latch-ip-name-lookup-glob> OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=localhost"
            ),
            LogEntry::error(
                "componentized-gate",
                "Latch error CODE=invalid-config<latch-ip-name-lookup-glob> OPERATION=wasi:sockets/ip-name-lookup#resolve-addresses NAME=www.example.com"
            ),
        ]
    );
    Ok(())
}
