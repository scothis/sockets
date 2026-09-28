# Socket components <!-- omit in toc -->

A collection of utility components that remix wasi:sockets types and interfaces.

- [Components](#components)
  - [Gates](#gates)
  - [Latches](#latches)
    - [Blanket restrictions](#blanket-restrictions)
    - [Name lookups](#name-lookups)
    - [Network ranges](#network-ranges)
    - [Combining latches](#combining-latches)
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

### Latches

Decide which socket operations are allowed. A latch abstains or denies, an operation proceeds unless a latch denies it.

#### Blanket restrictions

Deny a whole category of operations, without configuration.

- [`latch-abstain-all`](./components/latch-abstain-all/): abstains from everything, allowing all operations
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
- [`latch-cidr-egress`](./components/latch-cidr-egress/): restricts outbound traffic the guest originates
- [`latch-cidr-ingress`](./components/latch-cidr-ingress/): restricts inbound traffic remote peers originate

#### Combining latches

Build a policy from several latches, or apply a latch to only part of the traffic, for example to configure tcp and udp differently.

- [`latch-n2`](./components/latch-n2/), [`latch-n3`](./components/latch-n3/), [`latch-n4`](./components/latch-n4/), [`latch-n5`](./components/latch-n5/): aggregate two to five latches, any latch can deny an operation
- [`latch-delegate-tcp`](./components/latch-delegate-tcp/) / [`latch-delegate-udp`](./components/latch-delegate-udp/): apply a wrapped latch to only tcp or only udp operations

### Tracing

Log wasi:sockets calls, for debugging or auditing, without affecting them.

- [`trace`](./components/trace/): traces both tcp/udp sockets and ip-name-lookup
- [`trace-types`](./components/trace-types/): traces tcp and udp sockets
- [`trace-ip-name-lookup`](./components/trace-ip-name-lookup/): traces ip-name-lookup

## Build

Prereqs:
- a rust toolchain
- [`static-config`](https://github.com/componentized/static-config)
- [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools)
- [`wac`](https://github.com/bytecodealliance/wac)
- [`wkg`](https://github.com/bytecodealliance/wasm-pkg-tools)

```sh
make components
```

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
