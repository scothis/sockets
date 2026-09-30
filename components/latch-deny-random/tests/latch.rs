use test_harness::{ErrorCode, Harness, IpAddressFamily, Level, LogEntry, TestSubject};

const LATCH: &str = "latch-deny-random";

/// A gate with the latch, configured with the entries.
async fn gate(config: &[(&str, &str)]) -> wasmtime::Result<TestSubject> {
    let mut harness = Harness::new("gate-types").latch(LATCH);
    for (key, value) in config {
        harness = harness.config(key, value);
    }
    harness.build().await
}

/// Create tcp sockets, whether each create was denied.
async fn creates(gate: &mut TestSubject, count: usize) -> wasmtime::Result<Vec<bool>> {
    gate.run(async move |accessor, gate| {
        let tcp = gate.wasi_sockets_types().tcp_socket();
        let mut denied = vec![];
        for _ in 0..count {
            let result = tcp.call_create(accessor, IpAddressFamily::Ipv4).await?;
            denied.push(matches!(result, Err(ErrorCode::AccessDenied)));
        }
        Ok(denied)
    })
    .await
}

/// The messages the latch logged.
fn latch_logs(gate: &TestSubject) -> Vec<LogEntry> {
    gate.recorder()
        .logs()
        .into_iter()
        .filter(|entry| entry.context == "componentized-latch")
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn always_denies() -> wasmtime::Result<()> {
    let mut gate = gate(&[("probability", "1"), ("seed", "7")]).await?;
    assert_eq!(creates(&mut gate, 3).await?, vec![true, true, true]);
    assert_eq!(
        latch_logs(&gate),
        vec![LogEntry::warn(
            "componentized-latch",
            "Randomly denying wasi:sockets operations PROBABILITY=1 SEED=7"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn never_denies() -> wasmtime::Result<()> {
    let mut gate = gate(&[("probability", "0")]).await?;
    assert_eq!(creates(&mut gate, 3).await?, vec![false, false, false]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn same_seed_denies_the_same_operations() -> wasmtime::Result<()> {
    let config = [("probability", "0.5"), ("seed", "1234")];
    let first = creates(&mut gate(&config).await?, 32).await?;
    let again = creates(&mut gate(&config).await?, 32).await?;
    assert_eq!(first, again);
    // some of each, a coin flip for 32 operations
    assert!(first.contains(&true) && first.contains(&false), "{first:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn random_seed_is_logged() -> wasmtime::Result<()> {
    let seeds = [gate(&[]).await?, gate(&[]).await?]
        .into_iter()
        .map(async |mut gate| {
            creates(&mut gate, 1).await?;
            let logs = latch_logs(&gate);
            assert_eq!(logs.len(), 1);
            assert_eq!(logs[0].level, Level::Warn);
            let seed = logs[0]
                .message
                .strip_prefix("Randomly denying wasi:sockets operations PROBABILITY=0.1 SEED=")
                .expect("seed is logged")
                .parse::<u64>()?;
            wasmtime::Result::<u64>::Ok(seed)
        });
    let mut logged = vec![];
    for seed in seeds {
        logged.push(seed.await?);
    }
    // each instance draws its own seed
    assert_ne!(logged[0], logged[1]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_config_fails_operations() -> wasmtime::Result<()> {
    let mut gate = gate(&[("probability", "often")]).await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(
        matches!(result, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<latch-deny-random>")
    );
    assert_eq!(
        latch_logs(&gate),
        vec![LogEntry::critical(
            "componentized-latch",
            "Invalid config LATCH=latch-deny-random KEY=probability VALUE=often ERROR=expected a number from 0 to 1"
        )]
    );
    Ok(())
}
