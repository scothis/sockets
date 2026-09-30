use test_harness::{
    ErrorCode, Harness, HostLatch, IpAddressFamily, Level, LogEntry, Observation, TestSubject,
    loopback,
};

const LATCH: &str = "latch-trace";

/// Messages traced by the latch, in order.
fn traces(gate: &TestSubject) -> Vec<LogEntry> {
    gate.recorder()
        .logs()
        .into_iter()
        .filter(|entry| entry.level == Level::Trace)
        .collect()
}

/// Create a tcp socket and bind it to the loopback address.
async fn create_and_bind(gate: &mut TestSubject) -> wasmtime::Result<Result<(), ErrorCode>> {
    gate.run(async |accessor, gate| {
        let tcp = gate.wasi_sockets_types().tcp_socket();
        let socket = match tcp.call_create(accessor, IpAddressFamily::Ipv4).await? {
            Ok(socket) => socket,
            Err(err) => return Ok(Err(err)),
        };
        Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn deferrals_are_traced() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::defer())
        .build()
        .await?;
    assert!(create_and_bind(&mut gate).await?.is_ok());
    assert_eq!(
        traces(&gate),
        vec![
            LogEntry::trace(
                "componentized-latch",
                "Authorization DECISION=deferred OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
            ),
            LogEntry::trace(
                "componentized-latch",
                "Authorization DECISION=deferred OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS=127.0.0.1:0"
            ),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn denials_are_traced_and_enforced() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::deny(&["tcp-socket.bind"]))
        .build()
        .await?;
    let bound = create_and_bind(&mut gate).await?;
    assert!(matches!(bound, Err(ErrorCode::AccessDenied)));
    assert_eq!(
        traces(&gate)[1..],
        [LogEntry::trace(
            "componentized-latch",
            "Authorization DECISION=denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS=127.0.0.1:0"
        ),]
    );
    // the wrapped latch observes the final decision
    assert_eq!(
        gate.recorder().observations()[1],
        Observation {
            operation: "tcp-socket.bind".to_string(),
            denied: true,
        }
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn latch_errors_are_traced_and_returned() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::invalid_config("my-latch"))
        .build()
        .await?;
    let created = create_and_bind(&mut gate).await?;
    // the gate fails the operation, as it would without tracing
    assert!(
        matches!(created, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: invalid-config<my-latch>")
    );
    assert_eq!(
        traces(&gate),
        vec![LogEntry::trace(
            "componentized-latch",
            "Authorization ERROR=invalid-config<my-latch> OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_errors_are_returned() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::defer().fail_observe())
        .build()
        .await?;
    let created = create_and_bind(&mut gate).await?;
    assert!(
        matches!(created, Err(ErrorCode::Other(Some(ref message))) if message == "latch-error: observation-failed<host>")
    );
    assert_eq!(
        traces(&gate),
        vec![LogEntry::trace(
            "componentized-latch",
            "Authorization DECISION=deferred OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        ),]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn final_decisions_of_aggregated_latches_are_not_traced() -> wasmtime::Result<()> {
    // latch-deny-all denies first, the traced latch, and the host latch it wraps, only observe
    let mut gate = Harness::new("gate-types")
        .latch("latch-deny-all")
        .latch(LATCH)
        .build()
        .await?;
    let created = create_and_bind(&mut gate).await?;
    assert!(matches!(created, Err(ErrorCode::AccessDenied)));
    assert_eq!(traces(&gate), vec![]);
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    Ok(())
}
