use test_harness::{ErrorCode, Harness, IpAddressFamily, LogEntry};

#[tokio::test(flavor = "multi_thread")]
async fn denies_tcp_socket_create() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch("latch-deny-all")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let tcp = gate.wasi_sockets_types().tcp_socket();
            Ok(tcp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    // latch-deny-all decides every operation itself, the host latch is never consulted
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    assert_eq!(
        gate.recorder().logs(),
        vec![LogEntry::warn(
            "componentized-gate",
            "Denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4"
        )]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn denies_udp_socket_create() -> wasmtime::Result<()> {
    let mut gate = Harness::new("gate-types")
        .latch("latch-deny-all")
        .build()
        .await?;
    let result = gate
        .run(async |accessor, gate| {
            let udp = gate.wasi_sockets_types().udp_socket();
            Ok(udp.call_create(accessor, IpAddressFamily::Ipv4).await?)
        })
        .await?;
    assert!(matches!(result, Err(ErrorCode::AccessDenied)));
    assert_eq!(gate.recorder().operations(), Vec::<String>::new());
    Ok(())
}
