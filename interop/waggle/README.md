# Waggle Nim/Rust interoperability

This runner imports the pinned, unmodified Rust Waggle implementation and checks
bidirectional wire messages against a Nim Switch using TCP, Noise, and Yamux.
Both peers must validate all six messages across two topics and complete the
acknowledgement exchange. Binary payloads and absent versus empty fields are
checked.

## Run

Install Rust 1.98.1, Nim, and Python 3; configure Nim dependencies with `make setup`.
From the repository root:

```sh
(cd interop/waggle/rust-peer && cargo build --locked)
nim c --threads:on -d:chronicles_log_level=WARN interop/waggle/nim-peer/src/peer.nim
python3 interop/waggle/run.py
```

The runner creates a temporary address file, starts Rust on an available loopback
port, starts Nim after Rust is ready, checks both exit codes, and cleans up peer
processes. Each peer has a 60-second deadline. The runner requires both peers to finish successfully. Rust is pinned at `4a42568b77e703e15c954160d229af4bce98a6eb`.

Running Cargo from `rust-peer` lets `rust-toolchain.toml` select the pinned
compiler. From the repository root, Cargo needs an explicit `+1.98.1` override.

CI integration is added in [PR #3349](https://github.com/iftech/nim-libp2p/pull/3349),
after the reconciliation and lifecycle scenarios are included. This layer can be
run manually with the commands above.

The runner keeps scenario arguments for [PR #3348](https://github.com/iftech/nim-libp2p/pull/3348),
which adds reconciliation and topology peers. This layer only runs the wire
scenario through `run(None)`.
