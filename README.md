# Socket components <!-- omit in toc -->

A collection of utility components that remix wasi:socket types and interfaces.

- [Components](#components)
- [Build](#build)
- [Community](#community)
  - [Code of Conduct](#code-of-conduct)
  - [Communication](#communication)
  - [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)


## Components

- [`gate`](./components/gate/)
- [`gate-ip-name-lookp`](./components/gate-ip-name-lookp/)
- [`gate-tcp`](./components/gate-tcp/)
- [`gate-udp`](./components/gate-udp/)
- [`latch-n2`](./components/latch-n2/)
- [`latch-n3`](./components/latch-n3/)
- [`latch-n4`](./components/latch-n4/)
- [`latch-deny-all`](./components/latch-deny-all/)
- [`latch-deny-bind`](./components/latch-deny-bind/)
- [`latch-deny-connect`](./components/latch-deny-connect/)
- [`latch-deny-ipv4`](./components/latch-deny-ipv4/)
- [`latch-deny-ipv6`](./components/latch-deny-ipv6/)
- [`latch-grant-all`](./components/latch-grant-all/)
- [`latch-ip-name-lookup-glob`](./components/latch-ip-name-lookup-glob/)

## Build

Prereqs:
- a rust toolchain
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
