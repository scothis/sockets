# `gate-types`

Socket gate access control for tcp and udp sockets.

Each operation is authorized by the imported latch before it reaches the socket. How a denial is enforced depends on the operation:

- Most operations fail with the error code the latch denied them with.
- tcp `send` and `receive` are authorized once per socket, since each can be called at most once. A denied `send` drops the data stream and its future resolves to the error. A denied `receive` returns a closed stream and its future resolves to the error.
- tcp connections accepted by a listening socket are authorized individually. A denied connection is closed and never reaches the guest, the listening socket keeps accepting other connections.
- udp `receive` is authorized after a datagram arrives. A denied datagram is dropped and the receive continues with the next datagram, so unsolicited datagrams cannot fail the guest's receive.

Denials are logged as warnings. Latch errors are logged as errors and fail the operation with `other`, prefixed with `latch-error:`, except for accepted tcp connections, which are closed the same as a denial.

## Interfaces

Imports:

- `wasi:clocks/types@0.3.0`: types used by wasi:sockets/types
- `wasi:sockets/types@0.3.0`: the sockets the gated sockets wrap
- `componentized:sockets/latch@0.1.0-dev`: decides whether each operation may proceed
- `wasi:logging/logging@0.1.0-draft`: logs denials and latch errors

Exports:

- `wasi:sockets/types@0.3.0`: sockets gated by the latch
