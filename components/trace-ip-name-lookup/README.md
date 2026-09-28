# `trace-ip-name-lookup`

Trace wasi:sockets/ip-name-lookup calls using a logger.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs each operation
- `wasi:sockets/types@0.3.0`: the ip-address type returned by the name lookup
- `wasi:sockets/ip-name-lookup@0.3.0`: the name lookup the traced lookup wraps

Exports:

- `wasi:sockets/ip-name-lookup@0.3.0`: name lookup that logs each operation
