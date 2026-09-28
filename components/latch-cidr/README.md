# `latch-cidr`

Socket latch that uses CIDR ranges to grant or deny traffic originating in either direction based on the remote address. Return traffic is not restricted.

A composition of `latch-cidr-egress` and `latch-cidr-ingress`, aggregated with `latch-n2`. Both latches read the same wasi:config/store, so the same ranges, `default` and `reason` apply to outbound traffic the guest originates and inbound traffic remote peers originate. See the component READMEs for the config format and how each direction is checked.

```
default=deny
abstain=192.168.0.0/16

connect to 192.168.1.1 -> ABSTAINED
connection from 192.168.1.1 -> ABSTAINED
connect to 10.1.2.3 -> DENIED
connection from 10.1.2.3 -> DENIED
```

Both latches remember udp peers from the final decision passed to `observe-decision`, so a peer is only remembered when neither direction denied the traffic.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs an invalid config
- `wasi:config/store@0.2.0-rc.1`: the CIDR ranges, shared by both directions
- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
