# `latch-deny-private-networks-cidr-config`

Static config for `latch-cidr-egress` that denies originating outbound traffic to addresses that are not globally reachable, like private networks, loopback, link local and cloud metadata endpoints.

The ranges are a baseline for protecting against server side request forgery (SSRF), a guest being used to reach internal services, the host itself, or the cloud metadata endpoint that serves instance credentials. `latch-cidr-egress` checks addresses when the guest connects or sends, after any name is resolved, so a name that resolves to a denied address is denied as well.

## Ranges

Each range is a `deny-*` key, named for its purpose. The ranges come from the IANA IPv4 and IPv6 special-purpose address registries, and include IPv6 ranges that reach IPv4 hosts through translation or tunneling.

IPv4:

- `deny-ipv4-this-network`: `0.0.0.0/8`, connecting to `0.0.0.0` may reach the local host
- `deny-ipv4-private-10`, `deny-ipv4-private-172`, `deny-ipv4-private-192`: private use `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`
- `deny-ipv4-shared`: shared address space for carrier grade NAT, `100.64.0.0/10`
- `deny-ipv4-loopback`: `127.0.0.0/8`
- `deny-ipv4-link-local`: `169.254.0.0/16`, including cloud metadata endpoints like `169.254.169.254`
- `deny-ipv4-ietf`: IETF protocol assignments, `192.0.0.0/24`
- `deny-ipv4-documentation-1`, `-2`, `-3`: `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`
- `deny-ipv4-6to4-relay`: deprecated 6to4 relay anycast, `192.88.99.0/24`
- `deny-ipv4-benchmarking`: `198.18.0.0/15`
- `deny-ipv4-multicast`: `224.0.0.0/4`
- `deny-ipv4-reserved`: `240.0.0.0/4`, including the limited broadcast address `255.255.255.255`

IPv6, IPv4-mapped addresses (`::ffff:0:0/96`) are matched by the IPv4 ranges:

- `deny-ipv6-ipv4-compatible`: `::/96`, the unspecified address `::`, loopback `::1` and deprecated IPv4-compatible addresses
- `deny-ipv6-nat64`, `deny-ipv6-nat64-local`: NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, which reach IPv4 hosts
- `deny-ipv6-discard`: `100::/64`
- `deny-ipv6-ietf`: IETF protocol assignments, `2001::/23`, including Teredo `2001::/32` which reaches IPv4 hosts
- `deny-ipv6-documentation-1`, `-2`: `2001:db8::/32` and `3fff::/20`
- `deny-ipv6-6to4`: `2002::/16`, which reaches IPv4 hosts
- `deny-ipv6-unique-local`: `fc00::/7`, including cloud metadata endpoints like `fd00:ec2::254`
- `deny-ipv6-link-local`: `fe80::/10`
- `deny-ipv6-site-local`: deprecated site local, `fec0::/10`
- `deny-ipv6-multicast`: `ff00::/8`

Every other address is deferred, `default` and `reason` are not set.

## Usage

Give the config to `latch-cidr-egress` as its store:

```
package example:latch;

export new local:latch-cidr-egress {
    store: new local:latch-deny-private-networks-cidr-config {}.store,
    ...
}...;
```

Since any latch that denies an operation denies it, another latch cannot allow an address these ranges deny. Refine the ranges in the config instead, before it is given to `latch-cidr-egress`. The `overlay` component from [componentized/config](https://github.com/componentized/config) merges a second store over this one, with its values replacing values for the same key:

```
package example:latch;

export new local:latch-cidr-egress {
    store: new local:overlay {
        store: new local:latch-deny-private-networks-cidr-config {}.store,
        overlay: new local:my-network-policy {}.store,
    }.store,
    ...
}...;
```

With the overlay config:

- an `defer` range more specific than a denied range allows it, `defer-db=10.1.2.3:5432` allows connecting to a database while the rest of `10.0.0.0/8` is denied, see the rule precedence of `latch-cidr-egress`
- a key with the same name replaces a range, `deny-ipv4-private-10=10.0.0.0/9` narrows the denied private range
- `default=deny` denies everything that is not deferred, turning the config into an allow list
- `reason` sets the error code denied operations fail with

## Limitations

- `overlay` replaces values, it cannot remove a key. To stop denying a range, replace its value with a narrower range, or allow parts of it with more specific `defer` ranges. An `defer` range with the same prefix and ports as a denied range ties with it, and ties are decided by `deny`, so it needs a longer prefix or fewer ports to take effect.
- `deny-ipv6-ietf` denies `2001::/23` as a whole to cover Teredo, it also covers a few small IETF assignments that are globally reachable.
- The ranges are for outbound traffic the guest originates. Binding and inbound traffic are restricted by `latch-cidr-bind` and `latch-cidr-ingress`, which read the same config format.

## Interfaces

Exports:

- `wasi:config/store@0.2.0-rc.1`: static config for `latch-cidr-egress`
