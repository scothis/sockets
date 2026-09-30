use test_harness::{
    ErrorCode, Harness, HostLatch, IpAddressFamily, LogEntry, Observation, loopback,
};

const LATCH: &str = "latch-dry-run";

#[tokio::test(flavor = "multi_thread")]
async fn denials_are_logged_not_enforced() -> wasmtime::Result<()> {
    // the wrapped latch denies binding
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::deny(&["tcp-socket.bind"]))
        .build()
        .await?;
    let bound = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(bound.is_ok());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-latch",
            "Dry run, would deny REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.bind LOCAL-ADDRESS=127.0.0.1:0"
        )]
    );
    // the wrapped latch observes the final decision, the bind was not denied
    assert_eq!(
        gate.recorder().observations(),
        vec![
            Observation {
                operation: "tcp-socket.create".to_string(),
                denied: false,
            },
            Observation {
                operation: "tcp-socket.bind".to_string(),
                denied: false,
            },
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn latch_errors_are_logged_not_enforced() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::invalid_config("my-latch"))
        .build()
        .await?;
    let created = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(created.is_ok());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "componentized-latch",
            "Dry run, latch error CODE=invalid-config<my-latch> OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_errors_are_logged_not_enforced() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::defer().fail_observe())
        .build()
        .await?;
    let created: Result<_, ErrorCode> = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(created.is_ok());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::error(
            "componentized-latch",
            "Dry run, latch error CODE=observation-failed<host> OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn deferrals_are_not_logged() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch(LATCH)
        .host_latch(HostLatch::defer())
        .build()
        .await?;
    let bound = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            let socket = tcp
                .call_create(accessor, IpAddressFamily::Ipv4)
                .await?
                .expect("create");
            Ok(tcp.call_bind(accessor, socket, loopback(0)).await?)
        })
        .await?;
    assert!(bound.is_ok());
    assert_eq!(gate.recorder().logs(), vec![]);
    assert_eq!(
        gate.recorder().operations(),
        vec!["tcp-socket.create", "tcp-socket.bind"]
    );
    Ok(())
}
