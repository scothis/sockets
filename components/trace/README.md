# `trace`

Trace wasi:sockets calls using a logger.

A union of `trace-ip-name-lookup`, `trace-tcp`, and `trace-udp`.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs each operation
- `wasi:clocks/types@0.3.0`: types used by wasi:sockets/types
- `wasi:sockets/types@0.3.0`: the sockets the traced sockets wrap
- `wasi:sockets/ip-name-lookup@0.3.0`: the name lookup the traced lookup wraps

Exports:

- `wasi:sockets/ip-name-lookup@0.3.0`: name lookup that logs each operation
- `wasi:sockets/types@0.3.0`: sockets that log each operation
