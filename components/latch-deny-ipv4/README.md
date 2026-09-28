# `latch-deny-ipv4`

Sockets latch that implicitly denies all IPv4 operations.

## Interfaces

Imports:

- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
