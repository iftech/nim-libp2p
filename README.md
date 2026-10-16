<h1 align="center">
  <a href="https://libp2p.io"><img width="250" src="./.assets/full-logo.svg?raw=true" alt="nim-libp2p logo" /></a>
</h1>

<h3 align="center">The <a href="https://nim-lang.org/">Nim</a> implementation of the <a href="https://libp2p.io/">libp2p</a> Networking Stack.</h3>

<p align="center">
<a href="https://github.com/iftech/nim-libp2p/actions"><img src="https://github.com/iftech/nim-libp2p/actions/workflows/test_all.yml/badge.svg" /></a>

</p>

<p align="center">
<a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" /></a>
</p>

## Background

libp2p is a [Peer-to-Peer](https://en.wikipedia.org/wiki/Peer-to-peer) networking stack, with [implementations](https://github.com/libp2p/libp2p#implementations) in multiple languages derived from the same [specifications.](https://github.com/libp2p/specs)

Building large scale peer-to-peer systems has been complex and difficult in the last 15 years and libp2p is a way to fix that. It strives to be a modular stack with secure defaults and useful protocols, while remaining open and extensible.
This is a native Nim implementation, using [chronos](https://github.com/status-im/nim-chronos) for asynchronous execution. It's used in production by a few [projects](#users).

Learn more about libp2p at [**libp2p.io**](https://libp2p.io) and follow libp2p's documentation [**libp2p.io/docs**](https://libp2p.io/docs).

## Contribute

nim-libp2p is a great place to contribute. Your contribution will help drive thousands of decentralized nodes across networks worldwide.

The best part is that nim-libp2p has **good first issues** that are especially suited for newcomers. Your contributions will be guided by core maintainers, just like an **internship experience** but decentralized.

Jump into the [contributing](docs/contributing.md) page to get started, `nim-libp2p` is expecting your contribution!

## Install

The currently supported Nim versions are v2.2.4 and v2.2.10.

```
nimble install libp2p
```

You'll find the nim-libp2p documentation [here](https://iftech.github.io/nim-libp2p/). See [examples](./examples) for simple usage patterns.

## Development

For local development:

```sh
git clone --recurse-submodules https://github.com/iftech/nim-libp2p
cd nim-libp2p
make
make test
```

`make` sets up local Nimble dependencies for the library and tests. See the [development guide](docs/development.md) for details.
For more details, refer to the [documentation](docs/README.md).

## Contributors

Thanks to everyone who has contributed to nim-libp2p. Your support and efforts are greatly appreciated.

<a href="https://github.com/iftech/nim-libp2p/graphs/contributors"><img src="https://contrib.rocks/image?repo=iftech/nim-libp2p" alt="nim-libp2p contributors"></a>

## Join the Conversation

Connect with other contributors in our [community channel](https://discord.com/channels/1204447718093750272/1351621032263417946). Ask questions, share ideas, get support, and stay informed about the latest updates from the maintainers.

## Users

nim-libp2p is used by:

- [Nimbus](https://github.com/status-im/nimbus-eth2), an Ethereum client
- [logos-delivery](https://github.com/logos-messaging/logos-delivery), a decentralized messaging protocols
- [logos-storage](https://github.com/logos-storage/logos-storage-nim), a decentralized storage protocols
- [Mix Protocol](https://github.com/logos-co/nim-libp2p-mix), a decentralized anonymous message routing layer for libp2p networks
- (open a pull request if you want to be included here)

## Stability

nim-libp2p has been used in production for many years in high-stake scenarios, so its core is considered stable.
Some modules are more recent and less stable.

Versioning follows [Semantic Versioning](https://semver.org/):
 - Releases within the same `MAJOR` version are backwards compatible.
 - `MINOR` releases may introduce new features and other non-breaking changes.
 - `PATCH` releases are reserved for backwards-compatible bug fixes.

## License

Licensed under either of:

- Apache License 2.0 ([LICENSE-APACHEv2](LICENSE-APACHEv2))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Modules

List of packages modules implemented in nim-libp2p:

| Name | Description |
| ---- | ----------- |
| **Libp2p** | |
| [libp2p](nim-libp2p/libp2p/switch.nim) | The core Switch orchestrating transports, connections, and protocols |
| [builders](nim-libp2p/libp2p/builders.nim) | SwitchBuilder fluent API for configuring and instantiating nodes |
| [connmanager](nim-libp2p/libp2p/connmanager.nim) | Connection manager |
| [identify / push identify](nim-libp2p/libp2p/protocols/identify.nim) | [Identify](https://libp2p.io/docs/protocols/#identify) protocol |
| [ping](nim-libp2p/libp2p/protocols/ping.nim) | [Ping](https://libp2p.io/docs/protocols/#ping) protocol |
| [rendezvous](nim-libp2p/libp2p/protocols/rendezvous.nim) | [Rendezvous](https://github.com/libp2p/specs/blob/master/rendezvous/README.md) peer discovery protocol |
| **Transports** | |
| [tcp](nim-libp2p/libp2p/transports/tcptransport.nim) | TCP transport |
| [ws](nim-libp2p/libp2p/transports/wstransport.nim) | WebSocket & WebSocket Secure transport |
| [quic](nim-libp2p/libp2p/transports/quictransport.nim) | QUIC transport |
| [tor](nim-libp2p/libp2p/transports/tortransport.nim) | Tor transport |
| [memory](nim-libp2p/libp2p/transports/memorytransport.nim) | In-memory transport for testing |
| **Secure Channels** | |
| [noise](nim-libp2p/libp2p/protocols/secure/noise.nim) | [Noise](https://libp2p.io/docs/noise/) secure channel |
| [plaintext](nim-libp2p/libp2p/protocols/secure/plaintext.nim) | Plain text for development purposes |
| **Stream Multiplexers** | |
| [mplex](nim-libp2p/libp2p/muxers/mplex/mplex.nim) | [MPlex](https://github.com/libp2p/specs/tree/master/mplex) multiplexer |
| [yamux](nim-libp2p/libp2p/muxers/yamux/yamux.nim) | [Yamux](https://github.com/libp2p/specs/tree/master/yamux) multiplexer |
| **Data Types** | |
| [peer-id](nim-libp2p/libp2p/peerid.nim) | [Cryptographic peer identifiers](https://libp2p.io/docs/peers/#peer-id) |
| [peer-store](nim-libp2p/libp2p/peerstore.nim) | [Address book of known peers](https://libp2p.io/docs/peers/#peer-store) |
| [multiaddress](nim-libp2p/libp2p/multiaddress.nim) | [Composable network addresses](https://github.com/multiformats/multiaddr) |
| [signed-envelope](nim-libp2p/libp2p/signed_envelope.nim) | [Signed generic data container](https://github.com/libp2p/specs/blob/master/RFC/0002-signed-envelopes.md) |
| [routing-record](nim-libp2p/libp2p/routing_record.nim) | [Signed peer dialing information](https://github.com/libp2p/specs/blob/master/RFC/0003-routing-records.md) |
| [discovery manager](nim-libp2p/libp2p/discovery/discoverymngr.nim) | Discovery manager |
| **Connectivity** | |
| [autonat](nim-libp2p/libp2p/protocols/connectivity/autonat/service.nim) | [AutoNAT v1](https://github.com/libp2p/specs/blob/master/autonat/README.md) - automatic NAT detection |
| [autonat-v2](nim-libp2p/libp2p/protocols/connectivity/autonatv2/service.nim) | [AutoNAT v2](https://github.com/libp2p/specs/blob/master/autonat/autonat-v2.md) - improved NAT detection |
| [relay](nim-libp2p/libp2p/protocols/connectivity/relay/relay.nim) | [Circuit Relay v2](https://libp2p.io/docs/circuit-relay/) for NAT traversal |
| [dcutr](nim-libp2p/libp2p/protocols/connectivity/dcutr/core.nim) | [Direct Connection Upgrade through Relay](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md) (hole punching) |
| [hole-punching service](nim-libp2p/libp2p/services/hpservice.nim) | Hole punching service coordinating AutoNAT, Relay, and DCUTR |
| [auto-relay service](nim-libp2p/libp2p/services/autorelayservice.nim) | Automatic relay node discovery and management |
| **Utilities** | |
| [crypto](nim-libp2p/libp2p/crypto/crypto.nim) | Cryptographic backend (RSA, Ed25519, Secp256k1, ECDSA) |
| [crypto-secp256k1](nim-libp2p/libp2p/crypto/secp.nim) | Secp256k1 elliptic curve |
| [multistream-select](nim-libp2p/libp2p/multistream.nim) | [Protocol negotiation](https://github.com/multiformats/multistream-select) |
| [autotls](nim-libp2p/libp2p/autotls/service.nim) | [Automatic TLS](https://github.com/libp2p/specs/blob/master/tls/autotls-client.md) certificate provisioning via ACME |
| [nameresolving](nim-libp2p/libp2p/nameresolving/dnsresolver.nim) | DNS name resolver for multiaddresses |
| **Pubsub** | |
| [pubsub](nim-libp2p/libp2p/protocols/pubsub/pubsub.nim) | Pub-Sub generic interface |
| [floodsub](nim-libp2p/libp2p/protocols/pubsub/floodsub.nim) | FloodSub implementation |
| [gossipsub](nim-libp2p/libp2p/protocols/pubsub/gossipsub.nim) | [GossipSub](https://github.com/libp2p/specs/tree/master/pubsub) implementation |
| **DHT** | |
| [kademlia](nim-libp2p/libp2p/protocols/kademlia.nim) | [Kademlia DHT](https://github.com/libp2p/specs/tree/master/kad-dht) for peer/value discovery |
| [kademlia-discovery](nim-libp2p/libp2p/protocols/kad_disco.nim) | Kademlia-based peer discovery |
| **Performance** | |
| [perf](nim-libp2p/libp2p/protocols/perf/core.nim) | [Perf](https://github.com/libp2p/specs/blob/master/perf/perf.md) protocol for benchmarking libp2p nodes |
