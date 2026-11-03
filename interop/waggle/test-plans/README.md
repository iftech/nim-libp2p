# Waggle test-plans interoperability

This adapter runs the Waggle implementation from PR [#3349](https://github.com/iftech/nim-libp2p/pull/3349)
with the Rust and Go peers in [`sukunrt/test-plans@waggle-interop`](https://github.com/sukunrt/test-plans/tree/waggle-interop).
It implements that branch's Shadow script and eight-piece bitmap format. Every
received piece is checked against the deterministic expected payload.

## Run locally

Install [Shadow v3.3.0](https://github.com/shadow/shadow/tree/v3.3.0), uv,
Nim 2.2.10, Rust 1.98.1, and Go 1.26. Configure Nim dependencies and build all
three peers before running a simulation:

```sh
git clone --branch waggle-interop https://github.com/sukunrt/test-plans.git /tmp/test-plans
make setup
nim c --threads:on -d:chronicles_log_level=WARN \
  -d:chronicles_default_output_device=stderr \
  --warningAsError:UseBase:off --warningAsError:UnusedImport:off \
  --warningAsError:Deprecated:off --hintAsError:XCannotRaiseY:off \
  --out:build/waggle-shadow interop/waggle/test-plans/peer.nim
RUSTUP_TOOLCHAIN=1.98.1 make -C /tmp/test-plans/waggle-interop binaries
uv run --project /tmp/test-plans/waggle-interop python interop/waggle/test-plans/run.py \
  --test-plans /tmp/test-plans --nim-peer build/waggle-shadow \
  --composition nim rust go --scenario waggle --node-count 8 \
  --output-dir build/waggle-results/mixed
```

The output directory must be new. Use `--composition nim rust` or `nim go` to
isolate a pair, and `--scenario waggle-sparse` for the sparse topology. The
runner uses upstream scenario and network generation, assigning implementations
evenly (then shuffling with `--seed`, default 1) so every requested implementation
participates. It checks that every node logs reconstruction of each object in
the scenario. Node identity, TCP/9000, Noise, Yamux, and JSON output follow the
upstream implementation contract.

[The workflow](../../../.github/workflows/waggle-test-plans.yml) runs both
scenarios with Nim alone, Nim/Rust, Nim/Go, and Nim/Rust/Go, and uploads all
Shadow output. It follows the experimental branch and prints the resolved SHA
for reproducibility. Both upstream scenarios currently use default fanout;
passing them does not establish recovery with constrained fanout.

The upstream Makefile currently references a misspelled checker filename. This
runner validates structured completion events directly, including object IDs
and the expected number of nodes. It does not rely on that Makefile test target.
