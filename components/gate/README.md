# `gate`

Socket gate access control.

A union of `gate-ip-name-lookup` and `gate-types`.

## Interfaces

Imports:

- `wasi:clocks/types@0.3.0`: types used by wasi:sockets/types
- `wasi:sockets/types@0.3.0`: the sockets the gated sockets wrap
- `componentized:sockets/latch@0.1.0-dev`: decides whether each operation may proceed
- `wasi:logging/logging@0.1.0-draft`: logs denials and latch errors
- `wasi:sockets/ip-name-lookup@0.3.0`: the name lookup the gated lookup wraps

Exports:

- `wasi:sockets/ip-name-lookup@0.3.0`: name lookup gated by the latch
- `wasi:sockets/types@0.3.0`: sockets gated by the latch
