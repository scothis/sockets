# `gate-ip-name-lookup`

Socket gate access control for wasi:sockets/ip-name-lookup.

## Interfaces

Imports:

- `wasi:sockets/types@0.3.0`: the ip-address type returned by the name lookup
- `componentized:sockets/latch@0.1.0-dev`: decides whether each operation may proceed
- `wasi:logging/logging@0.1.0-draft`: logs denials and latch errors
- `wasi:sockets/ip-name-lookup@0.3.0`: the name lookup the gated lookup wraps

Exports:

- `wasi:sockets/ip-name-lookup@0.3.0`: name lookup gated by the latch
