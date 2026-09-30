# `latch-delegate-tcp`

Sockets latch that wraps another latch, delegating only tcp socket operations to it. Udp socket and ip-name-lookup operations are deferred without consulting the wrapped latch, it neither authorizes nor observes them.

Wrapping lets latches that apply to several kinds of operations be configured separately for each. For example, `latch-cidr-egress` restricts both tcp and udp traffic, to use different ranges for each, wrap one instance with `latch-delegate-tcp` and another with `latch-delegate-udp`, give each its own config, and aggregate them with `latch-n2`:

```
package example:latch;

let tcp = new local:latch-cidr-egress {
    store: new local:tcp-config {}.store,
    ...
};
let udp = new local:latch-cidr-egress {
    store: new local:udp-config {}.store,
    ...
};

export new local:latch-n2 {
    latch0: new local:latch-delegate-tcp { latch: tcp.latch }.latch,
    latch1: new local:latch-delegate-udp { latch: udp.latch }.latch,
    ...
}...;
```

## Interfaces

Imports:

- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized
- `componentized:sockets/latch@0.1.0-dev`: the wrapped latch, consulted for tcp socket operations

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
