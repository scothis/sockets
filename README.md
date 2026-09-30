# Socket components <!-- omit in toc -->

A collection of utility components that remix wasi:sockets types and interfaces.

- [Components](#components)
  - [Gates](#gates)
  - [Latches](#latches)
    - [Blanket restrictions](#blanket-restrictions)
    - [Name lookups](#name-lookups)
    - [Network ranges](#network-ranges)
    - [Combining latches](#combining-latches)
    - [Fault injection](#fault-injection)
  - [Tracing](#tracing)
- [Build](#build)
- [Community](#community)
  - [Code of Conduct](#code-of-conduct)
  - [Communication](#communication)
  - [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)


## Components

Access control for wasi:sockets is split between gates and latches. A gate wraps the sockets interfaces and consults a latch before each operation, a latch decides whether the operation may proceed. Latches are small and single purpose, combine them to build a policy. Tracing components log socket activity without changing it.

### Gates

Put wasi:sockets behind a latch. Each operation is authorized before it reaches the underlying socket, denied operations fail, and denied inbound traffic is dropped before it reaches the guest.

- [`gate`](./components/gate/): gates both tcp/udp sockets and ip-name-lookup
- [`gate-types`](./components/gate-types/): gates tcp and udp sockets
- [`gate-ip-name-lookup`](./components/gate-ip-name-lookup/): gates ip-name-lookup

> [!CAUTION]
> Interfering with network sockets can have dramatic, unintended consequences. A denied operation surfaces to the guest as a network failure, and dropped inbound traffic looks like a peer that never answers, which can trigger retries, timeouts and fallbacks far from the operation that was denied. A policy that looks correct can still cut off traffic a component depends on, for example name lookups or return traffic. Install new latches, and new configurations of existing latches, cautiously and monitor the result: roll out with [`latch-dry-run`](./components/latch-dry-run/), watch decisions with [`latch-trace`](./components/latch-trace/), and review the denials the gate logs.

### Latches

Decide which socket operations are allowed. A latch defers or denies, an operation proceeds unless a latch denies it.

#### Blanket restrictions

Deny a whole category of operations, without configuration.

- [`latch-defer-all`](./components/latch-defer-all/): defers everything, allowing all operations
- [`latch-deny-all`](./components/latch-deny-all/): denies every operation
- [`latch-deny-tcp`](./components/latch-deny-tcp/) / [`latch-deny-udp`](./components/latch-deny-udp/): denies all tcp or all udp operations
- [`latch-deny-ipv4`](./components/latch-deny-ipv4/) / [`latch-deny-ipv6`](./components/latch-deny-ipv6/): denies all IPv4 or all IPv6 operations
- [`latch-deny-bind`](./components/latch-deny-bind/): denies explicitly binding tcp and udp sockets to a local address
- [`latch-deny-connect`](./components/latch-deny-connect/): denies outbound connections
- [`latch-deny-ip-name-lookup`](./components/latch-deny-ip-name-lookup/): denies all ip-name lookups, uses the internal [`latch-deny-ip-name-lookup-config`](./components/latch-deny-ip-name-lookup-config/)

#### Name lookups

Control which host names can be resolved, and tie connections to names that were resolved.

- [`latch-ip-name-lookup-glob`](./components/latch-ip-name-lookup-glob/): grants or denies lookups by host name glob patterns
- [`latch-deny-connect-unless-lookup-address`](./components/latch-deny-connect-unless-lookup-address/): denies connecting to addresses that were not returned by an allowed lookup

#### Network ranges

Restrict which remote addresses traffic can originate from or be sent to, by CIDR range and optionally port range, while allowing return traffic.

- [`latch-cidr`](./components/latch-cidr/): restricts traffic originating in either direction
- [`latch-cidr-bind`](./components/latch-cidr-bind/): restricts which local addresses and ports sockets are bound to
- [`latch-cidr-egress`](./components/latch-cidr-egress/): restricts outbound traffic the guest originates
- [`latch-cidr-ingress`](./components/latch-cidr-ingress/): restricts inbound traffic remote peers originate
- [`latch-deny-private-networks-cidr-config`](./components/latch-deny-private-networks-cidr-config/): config for `latch-cidr-egress` denying outbound traffic to private, loopback, link local and other addresses that are not globally reachable, a baseline against server side request forgery that can be refined before use

#### Combining latches

Build a policy from several latches, apply a latch to only part of the traffic, for example to configure tcp and udp differently, or try a policy before enforcing it.

- [`latch-n2`](./components/latch-n2/), [`latch-n3`](./components/latch-n3/), [`latch-n4`](./components/latch-n4/), [`latch-n5`](./components/latch-n5/): aggregate two to five latches, any latch can deny an operation
- [`latch-delegate-tcp`](./components/latch-delegate-tcp/) / [`latch-delegate-udp`](./components/latch-delegate-udp/): apply a wrapped latch to only tcp or only udp operations
- [`latch-dry-run`](./components/latch-dry-run/): log what a wrapped latch would deny without enforcing it, to roll out a policy

#### Fault injection

Deny operations on purpose, to prove a component is resilient to failures in a hostile environment.

- [`latch-deny-random`](./components/latch-deny-random/): randomly denies a configurable fraction of operations, reproducible with a seed

### Tracing

Log wasi:sockets calls and latch decisions, for debugging or auditing, without affecting them.

- [`trace`](./components/trace/): traces both tcp/udp sockets and ip-name-lookup
- [`trace-types`](./components/trace-types/): traces tcp and udp sockets
- [`trace-ip-name-lookup`](./components/trace-ip-name-lookup/): traces ip-name-lookup
- [`latch-trace`](./components/latch-trace/): traces the decisions of a wrapped latch

## Build

Prereqs:
- a rust toolchain
- [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall), optional, to download prebuilt tools instead of building them

```sh
make components
```

The cli tools the build uses, [`static-config`](https://github.com/componentized/static-config), [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools), [`wac`](https://github.com/bytecodealliance/wac) and [`wkg`](https://github.com/bytecodealliance/wasm-pkg-tools), are pinned in [`tools/Cargo.toml`](./tools/Cargo.toml) and installed into `target/tools` as needed, or ahead of time with `make tools`. Dependabot bumps the pinned versions.

## Community

### Code of Conduct

The Componentized project follow the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). In short, be kind and treat others with respect.

### Communication

General discussion and questions about the project can occur in the project's [GitHub discussions](https://github.com/orgs/componentized/discussions).

### Contributing

The Componentized project team welcomes contributions from the community. A contributor license agreement (CLA) is not required. You own full rights to your contribution and agree to license the work to the community under the Apache License v2.0, via a [Developer Certificate of Origin (DCO)](https://developercertificate.org). For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## Acknowledgements

This project was conceived in discussion between [Mark Fisher](https://github.com/markfisher) and [Scott Andrews](https://github.com/scothis).

## License

Apache License v2.0: see [LICENSE](./LICENSE) for details.
