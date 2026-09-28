# `latch-cidr-ingress`

Socket latch that uses CIDR ranges to grant or deny inbound tcp/udp traffic originating from remote peers based on the remote address. Return traffic from peers the guest reached first is not restricted. This is the complement of `latch-cidr-egress`.

The ranges are defined in a wasi:config/store. Keys starting with `deny` are parsed as CIDR ranges with inbound traffic from matching remote addresses being denied. Multiple ranges are allowed by defining unique config keys (e.g. `deny-1`, `deny-2`, etc). Keys starting with `abstain` are parsed as CIDR ranges with inbound traffic from matching remote addresses abstaining from the decision.

Ranges are written as an address and prefix length, e.g. `10.0.0.0/8` or `fd00::/8`. A bare address without a prefix length (e.g. `10.1.2.3`) matches only that address. Bits set in the address beyond the prefix length are ignored, `10.1.2.3/8` is the same as `10.0.0.0/8`. IPv4 addresses are treated as their IPv4-mapped IPv6 form. `::ffff:10.1.2.3` is the same as `10.1.2.3`, and `::ffff:10.0.0.0/104` is the same as `10.0.0.0/8` (the prefix length of an IPv6 range counts all 128 bits). IPv4 ranges only match IPv4 addresses, while IPv6 ranges that contain `::ffff:0:0/96`, like `::/0`, match every IPv4 address as well. To restrict all traffic for an address family, use `latch-deny-ipv4` or `latch-deny-ipv6`.

When several ranges match a remote address, the most specific range decides, regardless of whether it is a `deny` or `abstain` range or the order the keys are defined in. The range with the longest prefix is the most specific, IPv4 ranges are compared as their IPv4-mapped IPv6 range (`10.0.0.0/8` is more specific than `::/80`). When the matching ranges are equally specific, `deny` wins.

```
deny-1=10.0.0.0/8
abstain-1=10.1.0.0/16
deny-2=10.1.2.3

10.2.0.1 -> DENIED (deny-1)
10.1.0.1 -> ABSTAINED (abstain-1)
10.1.2.3 -> DENIED (deny-2)
```

Remote addresses that do not match any range use the `default` decision, either `abstain` (the default) or `deny`.

Denials are reported with `access-denied` unless the `reason` key is set. The gate drops denied inbound traffic rather than failing a guest operation, so the reason is only visible in the gate's log, see `gate-types`. Supported values are `access-denied`, `invalid-argument` and `other`, any other value is reported as `other` with the value as the message. The reason applies to both matching `deny` ranges and a `deny` default, and does not change the default decision.

```
default=deny
reason=invalid-argument
abstain=192.168.0.0/16

192.168.1.1 -> ABSTAINED
10.1.2.3 -> DENIED (invalid-argument)
```

Inbound traffic is checked where it originates:

- tcp: each connection accepted by a listening socket is checked against the connecting peer's address. If the peer's address cannot be determined, the connection is denied. Receiving on a connection the guest opened with `connect` is return traffic and is not restricted.
- udp: `receive` is checked against the address the datagram was sent from. After a socket sends a datagram to, or connects to, a peer, datagrams from that peer (the same address and port) to the same socket are return traffic and are not restricted. A socket that sends or connects before it is bound has no local address yet, the peer is then remembered for datagrams to any socket. Peers are remembered for the life of the component instance. UDP source addresses are not authenticated, a datagram with a forged source address that matches a remembered peer is return traffic.

All other operations are abstained. Outbound traffic is not restricted, see `latch-cidr-egress`.

Peers are remembered from the final decision passed to `observe-decision`, not while authorizing. When this latch is aggregated with other latches, a send or connect any of them denies never reaches the peer, so datagrams from that peer are not return traffic. To restrict both directions, see `latch-cidr`.

If the config is invalid (a value that does not parse as a CIDR range or address, or an unknown `default` value), the cause is logged when the config is loaded and every checked operation, including return traffic, fails with an `invalid-config` latch error.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs an invalid config
- `wasi:config/store@0.2.0-rc.1`: the CIDR ranges
- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
