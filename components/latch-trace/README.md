# `latch-trace`

Sockets latch that wraps another latch, logging each decision it makes without changing it.

Use it to debug a policy: wrap a latch, or an aggregate of latches, and watch the logs to see how each operation is decided. Every operation is authorized by the wrapped latch and its decision, or error, is returned unchanged. The log describes the operation the same way the gates do.

```
Authorization DECISION=denied REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.connect REMOTE-ADDRESS=10.1.2.3:443
```

Latch errors from the wrapped latch, for example an invalid config, are logged and returned unchanged, so the gate fails the operation as it would without tracing.

```
Authorization ERROR=invalid-config<latch-cidr-egress> OPERATION=wasi:sockets/types#tcp-socket.create ADDRESS-FAMILY=IPv4
```

Messages are logged at the `trace` level. For example, to trace `latch-deny-private-networks`:

```
package example:latch;

export new local:latch-trace {
    latch: new local:latch-deny-private-networks { ... }.latch,
    ...
}...;
```

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs the decisions of the wrapped latch
- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized
- `componentized:sockets/latch@0.1.0-dev`: the wrapped latch

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
