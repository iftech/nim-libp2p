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
cargo +1.98.1 build --locked --manifest-path interop/waggle/rust-peer/Cargo.toml
nim c --threads:on -d:chronicles_log_level=WARN interop/waggle/nim-peer/src/peer.nim
python3 interop/waggle/run.py
```

The runner creates a temporary address file, starts Rust on an available loopback
port, starts Nim after Rust is ready, checks both exit codes, and cleans up peer
processes. Each peer has a 60-second deadline. The runner requires both peers to finish successfully. Rust is pinned at `4a42568b77e703e15c954160d229af4bce98a6eb`.
