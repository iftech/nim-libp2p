# Threat model

## What this project does and where untrusted input enters
- nim-libp2p is a Nim implementation of the libp2p networking stack. It is used in production by Nimbus
  (an Ethereum consensus client), logos-delivery, logos-storage and others, so nodes built on it are
  reachable by anyone on the internet.
- Treat every byte received from a remote peer as attacker-controlled, from the first byte of a connection
  onwards. An attacker can open any number of connections, speak any protocol it advertises, and send
  malformed, truncated, oversized or out-of-order data at every layer.
- Entry points, from the wire up:
  - transports: `libp2p/transports/` (TCP, QUIC via lsquic, WebSocket, TLS certificates, Tor, memory)
  - protocol negotiation: `libp2p/multistream.nim`
  - security handshakes: `libp2p/protocols/secure/noise.nim` (plaintext.nim is for testing only)
  - stream multiplexers: `libp2p/muxers/yamux`, `libp2p/muxers/mplex`
  - application protocols: `libp2p/protocols/` (identify, ping, pubsub/gossipsub, kademlia, rendezvous,
    service discovery, autonat/autonatv2, circuit relay v2, dcutr, perf)
  - encodings parsed from peer data: varint, protobuf messages, multiaddress, multihash, multibase, CID,
    peer IDs, public keys (`libp2p/crypto/`), signed envelopes and routing records
  - local-network discovery: `libp2p/services/mdns` (multicast packets from the LAN)
  - HTTP/DNS clients: `libp2p/autotls/` (ACME), `libp2p/peeridauth/`, `libp2p/nameresolving/` (responses
    from servers and resolvers are untrusted)
- The local application calling the public API is trusted.

## Components that matter most / least
- Most important: anything that runs before or during the security handshake (transports, multistream,
  noise, TLS certificate parsing), the muxers, and the peer-facing protocols enabled by default or used by
  our main users: identify, ping, gossipsub, kademlia, circuit relay, autonat, dcutr.
- Also in scope: key and signature handling in `libp2p/crypto/` (wrappers around bearssl, secp256k1,
  boringssl), peer ID / public key decoding, signed peer records.
- Less important but in scope: rendezvous, service discovery, mdns, perf, autotls, peeridauth, the C
  bindings in `cbind/`.
- Out of scope: `libp2p/protocols/secure/plaintext.nim` (insecure by design), `tests/`, `examples/`,
  `interop/`, `simulation/`, `tools/`, and the source of third-party dependencies in `nimbledeps/` (report
  a dependency bug only if nim-libp2p calls it in an unsafe way).

## How to exercise it
- The image has the dependencies in `nimbledeps/` and `tests/nimbledeps/` and a prebuilt runner of the
  whole unit-test suite at `tests/test_all` (it takes ~45 minutes to run in full).
- To build and run only the tests whose path matches a substring: `make test test_yamux` or
  `make test tests/libp2p/muxers` (seconds to a few minutes). Add `ASAN=1` for an AddressSanitizer build
  (orc + `-d:useMalloc`).
- Tests live under `tests/libp2p/`, mirroring `libp2p/`. Helpers for in-process peers and streams are in
  `tests/tools/` (e.g. `bufferstream.nim`, `fault_stream.nim`) and the memory transport
  (`libp2p/transports/memorytransport.nim`) lets two switches talk without sockets.
- No network is available; use loopback or the memory transport.

## How you rate severity
- Critical: remote code execution, or a memory-safety bug a remote peer can trigger and control; forging
  another peer's identity or bypassing the noise/TLS handshake authentication.
- High: a remote peer crashes the node (unhandled exception escaping to the event loop, assertion,
  `Defect`, out-of-bounds access, nil dereference) with a small number of messages; reading or
  corrupting another peer's data; signature verification that accepts invalid signatures.
- Medium: resource exhaustion (unbounded memory, CPU, file descriptors, streams or timers) that a single
  peer can cause cheaply and that existing limits (connection manager, muxer and pubsub limits, peer
  scoring) do not cap; gossipsub or kademlia logic that lets one peer poison routing or bypass scoring.
- Low: issues needing many coordinated peers or unusual configuration, information leaks of non-secret
  data, spec deviations without a security impact.
- Raise the severity by one level if the bug is reachable before the security handshake completes.

## Anything to leave alone
- Do not report the plaintext security protocol as insecure.
- Do not report generic "a peer can open many connections" DoS unless a specific limit is missing or
  bypassed.
- Do not report findings that only apply to code under `tests/`, `examples/`, `interop/` or `simulation/`.
