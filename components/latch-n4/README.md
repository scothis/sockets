# `latch-n4`

Sockets latch that aggregates four other sockets latches.

## Interfaces

Imports:

- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized
- `latch0: componentized:sockets/latch@0.1.0-dev`: an aggregated latch, consulted in order
- `latch1: componentized:sockets/latch@0.1.0-dev`: an aggregated latch, consulted in order
- `latch2: componentized:sockets/latch@0.1.0-dev`: an aggregated latch, consulted in order
- `latch3: componentized:sockets/latch@0.1.0-dev`: an aggregated latch, consulted in order

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch, aggregating the imported latches
