# `latch-cidr-egress`

Socket latch that uses CIDR ranges to grant or deny originating outbound tcp/udp traffic based on the remote address. Return traffic to peers that reached the guest first is not restricted.

The ranges are defined in a wasi:config/store. Keys starting with `deny` are parsed as CIDR ranges with outbound traffic to matching remote addresses being denied. Multiple ranges are allowed by defining unique config keys (e.g. `deny-1`, `deny-2`, etc). Keys starting with `defer` are parsed as CIDR ranges with outbound traffic to matching remote addresses deferring the decision.

Ranges are written as an address and prefix length, e.g. `10.0.0.0/8` or `fd00::/8`. A bare address without a prefix length (e.g. `10.1.2.3`) matches only that address. Bits set in the address beyond the prefix length are ignored, `10.1.2.3/8` is the same as `10.0.0.0/8`. IPv4 addresses are treated as their IPv4-mapped IPv6 form. `::ffff:10.1.2.3` is the same as `10.1.2.3`, and `::ffff:10.0.0.0/104` is the same as `10.0.0.0/8` (the prefix length of an IPv6 range counts all 128 bits). IPv4 ranges only match IPv4 addresses, while IPv6 ranges that contain `::ffff:0:0/96`, like `::/0`, match every IPv4 address as well. To restrict all traffic for an address family, use `latch-deny-ipv4` or `latch-deny-ipv6`.

A range may be followed by a comma separated list of ports and inclusive port ranges, e.g. `10.0.0.0/8:443` or `10.1.2.3:80,443,8000-8999`. An IPv6 range with ports must be in brackets, e.g. `[fd00::/8]:80,443`. A range without ports matches every port. Ports without an address, e.g. `:22` or `:80,443`, match every IPv4 and IPv6 address, as the least specific address range. Each entry in the list is a separate range with the same address, as specific as its own ports. For outbound traffic the port is the remote port the traffic is sent to, `deny=10.0.0.0/8:22` denies connecting to ssh on any address in `10.0.0.0/8`.

## Rule precedence

Each `deny*` and `defer*` value becomes one or more rules, one for each entry in its port list, or a single rule matching every port when it has no ports. For each operation, the rules that match the remote address and port are compared and the most specific decides. When no rule matches, `default` decides. The decision does not depend on the order of the config keys.

Rules are compared by, in order:

1. Address prefix length, longest first. Prefix lengths are compared in the 128 bit IPv6 address space, an IPv4 range counts as its IPv4-mapped IPv6 range, its prefix length plus 96. `10.0.0.0/8` is a /104, so it is more specific than `::/80` and `0.0.0.0/0` (a /96), and less specific than `10.1.0.0/16` (a /112). A bare address is a /128. Ports without an address are `::/0`, the least specific.
2. Number of ports, fewest first. A single port counts as 1, a port range counts every port in it, and a rule without ports counts all 65536.
3. `deny` before `defer`.

This has consequences that are easy to overlook:

- The address decides before the ports. A rule for a narrower address wins even when it covers more ports, with `defer=10.1.0.0/16` and `deny=10.0.0.0/8:443`, port 443 is allowed for `10.1.0.0/16`. To deny a port within an allowed range, give the deny rule an address range at least as specific, `deny=10.1.0.0/16:443`.
- Ports without an address have the lowest priority. `deny=:22` only applies to addresses that no range with an address matches, with `defer=0.0.0.0/0` it only applies to IPv6 addresses.
- The action only breaks exact ties. A broad `defer` never overrides a narrower `deny`, and a narrower `defer` always overrides a broader `deny`, carving an exception out of it.

```
defer-1=0.0.0.0/0:443
deny-1=10.0.0.0/8
defer-2=10.1.0.0/16
deny-2=10.1.2.3:22
deny-3=:25

192.0.2.1 port 443       -> DEFERRED (defer-1)
192.0.2.1 port 25        -> DENIED (deny-3)
192.0.2.1 port 80        -> DEFERRED (default)
10.2.0.1 port 443        -> DENIED (deny-1, a /104 beats the /96 of defer-1)
10.1.0.1 port 25         -> DEFERRED (defer-2, a /112 beats the /0 of deny-3)
10.1.2.3 port 22         -> DENIED (deny-2)
10.1.2.3 port 80         -> DEFERRED (defer-2)
2001:db8::1 port 25      -> DENIED (deny-3)
2001:db8::1 port 443     -> DEFERRED (default, IPv4 ranges do not match IPv6 addresses)
::ffff:10.2.0.1 port 443 -> DENIED (deny-1, matched as 10.2.0.1)
```

For this latch the port is the remote port the traffic is sent to.

## Default decision and reason

Remote addresses that do not match any range use the `default` decision, either `defer` (the default) or `deny`.

Denied operations fail with `access-denied` unless the `reason` key is set. Supported values are `access-denied`, `invalid-argument` and `other`, any other value is reported as `other` with the value as the message. The reason applies to both matching `deny` ranges and a `deny` default, and does not change the default decision.

```
default=deny
reason=invalid-argument
defer=192.168.0.0/16

192.168.1.1 -> DEFERRED
10.1.2.3 -> DENIED (invalid-argument)
```

## Checked operations

Outbound traffic is checked where it originates:

- tcp: `connect` is checked against the remote address. Connections accepted from a listening socket are inbound, sending on them is return traffic and is not restricted.
- udp: `send` is checked against the remote address, or the socket's remote address for a connected socket sending without a remote address. If the remote address cannot be determined, the send is denied. After a socket receives a datagram, sending back to that peer (the same address and port) from the same socket is return traffic and is not restricted. Received peers are remembered for the life of the component instance. UDP source addresses are not authenticated, a datagram with a forged source address opens a return path to that address and port. Restricting who may send to the guest requires a latch for inbound traffic, like `latch-cidr-ingress`, see `latch-cidr`.

All other operations are deferred. Inbound traffic is not restricted, see `latch-cidr-ingress`.

Peers are remembered from the final decision passed to `observe-decision`, not while authorizing. When this latch is aggregated with other latches, a datagram any of them denies never reaches the guest, so replying to its sender is not return traffic.

If the config is invalid (a value that does not parse as a CIDR range or address, or an unknown `default` value), the cause is logged when the config is loaded and every checked operation, including return traffic, fails with an `invalid-config` latch error.

## Security considerations

- Config keys are matched by prefix and are case sensitive. Keys that do not start with `deny` or `defer`, and are not `default` or `reason`, are ignored, a misspelled key like `deni-1` or `Deny-1` has no effect. A warning is logged for each ignored key when the config is loaded. When a key is set more than once, including `deny` and `defer` keys, only its last value is used, and a warning is logged for each ignored value.
- Bits set in an address beyond its prefix length are ignored, `10.1.2.3/8` is `10.0.0.0/8`, not the single address `10.1.2.3`. A warning is logged for each such range when the config is loaded.
- With the default `default=defer`, anything not matched is allowed. To allow only known destinations, use `default=deny` with `defer` ranges for the exceptions.
- Only IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are matched as IPv4. Other IPv6 addresses that reach IPv4 hosts through translation or tunneling, like NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) or deprecated IPv4-compatible addresses (`::a.b.c.d`), are matched as IPv6 and are not covered by IPv4 ranges. Deny those IPv6 ranges explicitly, or use `default=deny`, when they may be routable.
- Rules match addresses, not names. Which names resolve to which addresses is decided by name lookups, see `latch-ip-name-lookup-glob` and `latch-deny-connect-unless-lookup-address`.
- Only the operations described above are checked, traffic the guest did not originate, including return traffic to peers that reached the guest first, is not restricted by this latch.
- An operation whose addresses cannot be determined is denied, and an invalid config fails every checked operation, so errors fail closed.

## Interfaces

Imports:

- `wasi:logging/logging@0.1.0-draft`: logs an invalid config
- `wasi:config/store@0.2.0-rc.1`: the CIDR ranges
- `wasi:sockets/types@0.3.0`: the socket types of the operations being authorized

Exports:

- `componentized:sockets/latch@0.1.0-dev`: the latch
