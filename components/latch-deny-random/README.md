# `latch-deny-random`

Sockets latch that randomly denies operations, to prove a component is resilient to failures.

Every operation is at risk: creating and binding sockets, connecting, listening, sending and receiving, and name lookups. A denied operation fails with `access-denied`, while denied inbound traffic is dropped, an accepted connection is closed and a received datagram or looked up address is discarded. Wrap it with [`latch-delegate-tcp`](../latch-delegate-tcp/) or [`latch-delegate-udp`](../latch-delegate-udp/) to put only some of the traffic at risk.

The latch is configured with a wasi:config/store:

- `probability`: the fraction of operations denied, from `0` to `1`, defaults to `0.1`
- `seed`: an unsigned 64 bit integer, the same seed denies the same operations, defaults to a random seed from `wasi:random`
- `reason`: the error denied operations fail with, `access-denied` (the default), `invalid-argument` or `other`, any other value is reported as `other` with the value as the message

The seed is logged as a warning when the latch starts, set it in the config to reproduce a failure.

```
Randomly denying wasi:sockets operations PROBABILITY=0.1 SEED=9383211634937261427
```

The decision for an operation depends only on the seed and the number of operations observed before it. Operations another latch denies first still count, so aggregating the latch with others does not change which operations it denies.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs the seed, and an invalid config
- `wasi:config/store@0.2.0-rc.1`: the latch config
- `wasi:random/insecure@0.3.0`: seeds the decisions when no `seed` is configured

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
