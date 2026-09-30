# `latch-dry-run`

Sockets latch that wraps another latch, logging the operations it would deny without denying them.

Use it to roll out a policy: wrap the latch, watch the logs for operations it would deny, and adjust the policy before enforcing it by removing the wrapper. Every operation is authorized by the wrapped latch, a denial is logged as a warning and the operation is deferred. The log describes the operation the same way the gates do.

```
Dry run, would deny REASON=access-denied OPERATION=wasi:sockets/types#tcp-socket.connect REMOTE-ADDRESS=10.1.2.3:443
```

A latch error from the wrapped latch, for example an invalid config, is logged as an error and the operation is deferred as well, a dry run never fails an operation.

The wrapped latch observes the final decision with `observe-decision`, which is deferred for operations it would have denied. Stateful latches therefore act on what actually happened, for example `latch-cidr-egress` remembers peers that sent datagrams it would have denied receiving, the same as when it is not enforced. A failure to observe the decision is logged as an error and does not fail the operation.

For example, to evaluate `latch-deny-private-networks`:

```
package example:latch;

export new local:latch-dry-run {
    latch: new local:latch-deny-private-networks { ... }.latch,
    ...
}...;
```

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs the operations the wrapped latch would deny, and its errors
- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized
- `componentized:sockets/latch@0.1.0-dev`: the wrapped latch

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
