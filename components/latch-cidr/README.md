# `latch-cidr`

Socket latch that uses CIDR ranges to grant or deny traffic originating in either direction based on the remote address. Return traffic is not restricted.

A composition of `latch-cidr-egress` and `latch-cidr-ingress`, with egress wrapping ingress. Both latches read the same wasi:config/store, so the same ranges, `default` and `reason` apply to outbound traffic the guest originates and inbound traffic remote peers originate. See the component READMEs for the config format and how each direction is checked.

```
default=deny
abstain=192.168.0.0/16

connect to 192.168.1.1 -> ABSTAINED
connection from 192.168.1.1 -> ABSTAINED
connect to 10.1.2.3 -> DENIED
connection from 10.1.2.3 -> DENIED
```

## Known limitation

Each latch remembers udp peers when its own check passes, without knowing whether the latch wrapping it denies the operation. When the guest attempts a udp send that egress denies, ingress has already remembered the peer, so a datagram from that peer to the sending socket is accepted as return traffic, after which egress treats the peer as return traffic too and allows sending to it. Opening this path requires the guest to first attempt a denied send, and the peer to then send to the guest's socket without having received anything from it. Tcp is not affected, neither latch remembers tcp peers.

Wrapping in the other order would be weaker, a denied peer could open a path by sending a single unsolicited datagram, without any action from the guest.
