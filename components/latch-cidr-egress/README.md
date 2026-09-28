# `latch-cidr-egress`

Socket latch that uses CIDR ranges to grant or deny originating outbound tcp/udp traffic based on the remote address. Return traffic to peers that reached the guest first is not restricted.

The ranges are defined in a wasi:config/store. Keys starting with `deny` are parsed as CIDR ranges with outbound traffic to matching remote addresses being denied. Multiple ranges are allowed by defining unique config keys (e.g. `deny-1`, `deny-2`, etc). Keys starting with `abstain` are parsed as CIDR ranges with outbound traffic to matching remote addresses abstaining from the decision.

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

Denied operations fail with `access-denied` unless the `reason` key is set. Supported values are `access-denied`, `invalid-argument` and `other`, any other value is reported as `other` with the value as the message. The reason applies to both matching `deny` ranges and a `deny` default, and does not change the default decision.

```
default=deny
reason=invalid-argument
abstain=192.168.0.0/16

192.168.1.1 -> ABSTAINED
10.1.2.3 -> DENIED (invalid-argument)
```

Outbound traffic is checked where it originates:

- tcp: `connect` is checked against the remote address. Connections accepted from a listening socket are inbound, sending on them is return traffic and is not restricted.
- udp: `send` is checked against the remote address, or the socket's remote address for a connected socket sending without a remote address. If the remote address cannot be determined, the send is denied. After a socket receives a datagram, sending back to that peer (the same address and port) from the same socket is return traffic and is not restricted. Received peers are remembered for the life of the component instance. UDP source addresses are not authenticated, a datagram with a forged source address opens a return path to that address and port. Restricting who may send to the guest requires a latch for inbound traffic, like `latch-cidr-ingress`, see `latch-cidr`.

All other operations are abstained. Inbound traffic is not restricted, see `latch-cidr-ingress`.

Peers are remembered from the final decision passed to `observe-decision`, not while authorizing. When this latch is aggregated with other latches, a datagram any of them denies never reaches the guest, so replying to its sender is not return traffic.

If the config is invalid (a value that does not parse as a CIDR range or address, or an unknown `default` value), the cause is logged when the config is loaded and every checked operation, including return traffic, fails with an `invalid-config` latch error.
