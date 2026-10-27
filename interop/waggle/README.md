# Waggle Nim/Rust interoperability

This suite checks that Nim and Rust peers can exchange Waggle messages and
reconcile pieces of an object. It runs five scenarios, including reconnects and
recovery from a full send queue. Both peers must complete successfully for a
scenario to pass.

The Rust peer imports the unmodified [`sigp/waggle`](https://github.com/sigp/waggle)
implementation at commit `4a42568b77e703e15c954160d229af4bce98a6eb`. The code in
this directory provides the test fixtures, coordination, and assertions.

## Run the suite

Install Nim, Rust 1.98.1, and Python 3, then configure the repository's Nim
dependencies with `make setup`. CI uses Nim 2.2.10.

From the repository root, build both peers and run them together:

```sh
cargo +1.98.1 build --locked --manifest-path interop/waggle/rust-peer/Cargo.toml
nim c --threads:on -d:chronicles_log_level=WARN interop/waggle/nim-peer/src/peer.nim
python3 interop/waggle/run.py
```

Expect a success message for each scenario: `wire`, `reconcile`, `topology`,
`lifecycle`, and `pressure`. Unknown messages, duplicates, incorrect contents,
premature exits, and timeouts fail the run.

Rust 1.98.1 provides an atomic API required by the pinned Waggle revision.
[`rust-toolchain.toml`](rust-peer/rust-toolchain.toml) selects that compiler, and
`Cargo.lock` pins the transitive dependencies, including the protobuf framing
codec.

## What each scenario verifies

| Scenario | What happens | What must pass |
| --- | --- | --- |
| `wire` | Nim and Rust each send six messages across two binary topics. | Topic isolation, object IDs, optional fields, and payload bytes match exactly. |
| `reconcile` | Nim and Rust start with complementary pieces of one object. | Both reconstruct the object, receiving only their missing piece without duplicate delivery. |
| `topology` | Two Nim peers connect through a Rust relay, with one different piece at each of the three peers. | All three reconstruct the complete object by integrating and republishing pieces. |
| `lifecycle` | Nim unsubscribes, resubscribes, then reconnects using the same identity. | Rust observes the subscription and connection changes, and Nim receives the expected update after each change. |
| `pressure` | Nim's queue holds one message. It publishes two objects, then retries the rejected second snapshot after the first is acknowledged. | The second publication reports a full queue; Rust later receives both payloads exactly once. |

Each scenario exchanges acknowledgements before reporting success. For example,
in `wire`, Rust confirms receipt of all six Nim messages. Nim then checks that
confirmation and all six Rust messages before sending the final acknowledgement.
A peer cannot pass merely by sending its own messages.

### Wire fixtures

The `wire` scenario sends three objects on each topic:

- **Metadata only:** opaque binary object IDs and metadata, with no payload.
- **Binary payload:** 256 bytes, requiring a multi-byte frame length. Nim omits
  metadata on this message; Rust's publish API includes its current metadata.
- **Empty fields:** metadata and payload are present but empty, checking that
  empty fields remain distinct from absent fields.

Wire fixtures and control messages use `R` and `N` prefixes in their object IDs
to distinguish Rust- and Nim-originated messages. These are test conventions;
Waggle treats object IDs as opaque bytes. The Nim names and byte values live in
[`constants.nim`](nim-peer/src/constants.nim) and match the Rust fixtures.

### Coordination required by the pinned Rust revision

Two behaviors of this Rust revision affect how the scenarios coordinate:

- **Late subscribers:** publishing an unchanged snapshot does not retry delivery
  to them. The `topology` scenario therefore waits until both Nim peers have
  subscribed to the data and control topics before Rust seeds its object.
- **Idle subscription closure:** Rust notices the closure on its next write.
  After unsubscribing, Nim requests a write probe over the control topic before
  waiting for confirmation and resubscribing.

These scenarios verify the coordinated exchanges described above. They do not
establish metadata-only gossip recovery under constrained payload fanout.

## How the peers run

Every Nim scenario builds a Switch with TCP, Noise, and Yamux, passes it to
`Waggle.new(switch = switch, ...)`, mounts Waggle, and starts the switch.
Connections, reconnects, and shutdown use the Switch APIs.

The `wire` scenario uses `switch.dial` to open direct subscription streams. The
other scenarios use managed subscriptions and publish updated snapshots after
integrating pieces. Control acknowledgements use direct sends.

The runner starts fresh peer processes for every scenario:

1. Rust listens on an available IPv4 loopback TCP port and writes its address and
   peer ID to a temporary file.
2. Once the address is ready, the runner starts the Nim peer, or two Nim peers for
   `topology`. Each connects to Rust and opens its subscriptions; Rust also opens
   subscriptions on the same connection.
3. The peers exchange and validate messages. The runner checks both exit codes.
4. The runner prints the Rust log, removes temporary files, and stops any
   surviving peer processes on success or failure.

Rust readiness has a 20-second deadline. Each peer has a 60-second exchange
deadline, and the runner also bounds its subprocess waits. Ports and identities
are generated for each run; no startup sleeps are required.

## Where to find the code

| File | Purpose |
| --- | --- |
| [`run.py`](run.py) | Starts peers, enforces deadlines, and collects results. |
| [`peer.nim`](nim-peer/src/peer.nim) | Nim entry point and wire fixtures. |
| [`managed.nim`](nim-peer/src/managed.nim) | Nim reconciliation scenario. |
| [`network.nim`](nim-peer/src/network.nim) | Nim topology, lifecycle, and queue-pressure scenarios. |
| [`main.rs`](rust-peer/src/main.rs) | Rust fixtures and a separate handler for each scenario, with shared swarm setup. |

The `run-waggle-interop` job in
[`.github/workflows/interop.yml`](../../.github/workflows/interop.yml) runs this
suite in CI. For the application API, see the [Waggle guide](../../docs/waggle.md).
