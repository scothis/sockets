# `latch-deny-bind`

Sockets latch that implicitly denies explicitly binding tcp and udp sockets to a local address.

Only `bind` is denied. Sockets are still bound implicitly to an ephemeral port by operations that require a local address, like tcp `listen` or udp `send` on an unbound socket, so this does not prevent a guest from accepting inbound connections or receiving datagrams. To restrict inbound traffic, see `latch-cidr-ingress`.

## Interfaces

Imports:

- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
