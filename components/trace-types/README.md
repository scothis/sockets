# `trace-types`

Trace wasi:sockets/types calls using a logger.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs each operation
- `wasi:clocks/types@0.3.0`: types used by wasi:sockets/types
- `wasi:sockets/types@0.3.0`: the sockets the traced sockets wrap

Exports:

- `wasi:sockets/types@0.3.0`: sockets that log each operation
