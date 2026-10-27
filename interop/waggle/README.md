# Waggle Nim/Rust interoperability

This test runs the Nim Waggle implementation against the actual
[`sigp/waggle`](https://github.com/sigp/waggle) Rust behaviour, pinned to
`4a42568b77e703e15c954160d229af4bce98a6eb`. `Cargo.lock` also pins the transitive
Rust dependencies, including the upstream protobuf framing codec. The pinned
Rust implementation requires the atomic API available in Rust 1.98.1; its
`rust-toolchain.toml` selects that compiler.

Like `interop/partial-message`, the peers are built before they are started.
The Rust peer listens on a dynamically allocated IPv4 loopback TCP port and
writes its address and peer ID to a temporary file. The runner starts Nim once
that file is ready. Nim authenticates the Rust peer with Noise, negotiates
Yamux, and opens Waggle subscription streams. Rust opens its own subscriptions
on the same connection.

Each peer sends and verifies three distinct objects on each of two binary topic
IDs:

- Metadata only, with opaque binary object IDs and metadata.
- A 256-byte binary payload, exercising a multi-byte frame length. Nim omits
  metadata on this message; Rust's publishing API includes its current metadata.
- Present-but-empty metadata and pieces, preserving protobuf field presence.

Wire fixtures and control messages use ASCII `R` and `N` prefixes in their object
IDs to distinguish messages from the Rust and Nim peers. These prefixes are test
conventions; Waggle treats object IDs as opaque bytes. The Nim scenario names and
prefixes are defined in
[nim-peer/src/constants.nim](nim-peer/src/constants.nim), matching the Rust harness.

Both peers check topic isolation, object IDs, field presence, and payload bytes.
Rust confirms that it received all six Nim messages; Nim sends a final
acknowledgement only after checking all six Rust messages and that confirmation.
The runner requires both peers to exit successfully. Unknown messages, duplicates,
wrong contents, timeouts, and premature exits fail the test. A success on only
one peer is insufficient.

The tests exercise TCP, Noise, Yamux, multistream negotiation, subscription
handshakes, piece exchange, selective reconciliation, and duplicate suppression.
Every Nim scenario builds a Switch with TCP, Noise, and Yamux, passes it to
`Waggle.new(switch = switch, ...)`, mounts the protocol, and starts the switch.
Connections, stream negotiation, reconnects, and shutdown use the Switch APIs.
The wire scenario opens its direct subscription streams with `switch.dial`; the
other scenarios use managed subscriptions and publishing.

A second scenario uses the managed Nim API and Rust's `Shard`/`Metadata`
interfaces. Nim starts with one piece and Rust with a complementary piece of the
same object. Both reconstruct the complete object, check that only the missing
piece reached the application, and exchange final acknowledgements. Nim opens
subscriptions through the switch connection manager and publishes updated
snapshots; the wire-only APIs are used just for the final acknowledgement.

A third scenario connects two independent Nim processes only through a Rust
relay. An explicit barrier waits for both peers to subscribe to data and control
topics before Rust seeds its object. The peers start with complementary bits
(1, 2, and 4), integrate and republish missing pieces, and must all reconstruct 7. Each Nim peer confirms
completion, Rust confirms both peers completed, and both Nim peers acknowledge
that confirmation before any process reports success.

A fourth scenario keeps one Nim identity across subscription and connection
changes. Nim receives an object, unsubscribes, waits for Rust to confirm the
stream closure over a separate control topic, resubscribes and receives the next
update, then reconnects and receives a third update. Rust verifies the identity,
subscription transitions, connection closure, and final acknowledgement.

The readiness barrier accommodates the pinned Rust publisher's lack of retries
for unchanged snapshots when a subscriber arrives late. Its idle writers also
detect a remote subscription closure only on the next write, so Nim explicitly
requests a write probe over the control topic after unsubscribing. These are
constraints of this Rust revision, not guarantees established by the tests.

A fifth scenario sets Nim's connection queue budget to one message, publishes
two distinct objects synchronously, and requires the second publication to be
rejected with a queue-full event. After Rust acknowledges the first payload,
Nim republishes the unchanged second snapshot. Rust must receive both payloads
exactly once and validate the final acknowledgement.

## Run locally

From the repository root, with Nim and Rust 1.98.1 installed and local Nim dependencies
configured (`make setup`):

```sh
cargo +1.98.1 build --locked --manifest-path interop/waggle/rust-peer/Cargo.toml
nim c --threads:on -d:chronicles_log_level=WARN interop/waggle/nim-peer/src/peer.nim
python3 interop/waggle/run.py
```

The runner executes all five scenarios with separate fresh peer processes. It
waits at most 20 seconds for Rust readiness in each scenario. Each peer has a 60-second
exchange deadline; the runner also bounds the subprocess waits. Temporary files
and any surviving Rust process are cleaned up on success and failure. The Rust
log is printed before cleanup. No fixed ports, persistent identities, or startup
sleeps are needed.

The `run-waggle-interop` job in `.github/workflows/interop.yml` runs the same test.
