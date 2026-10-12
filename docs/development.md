# Development

Clone the repository and set up local dependencies:

```sh
git clone --recurse-submodules https://github.com/iftech/nim-libp2p
cd nim-libp2p
make
```

`make` is the default local development setup target. It resolves the lowest supported dependency versions for `NIM_VERSION` using Nimble local dependency mode, then writes local dependency paths for the library and tests.

```sh
make setup                 # explicit form of the default target
make NIM_VERSION=2.2.4 setup
make build                 # explicit Nix build
```

Nimble 0.24.0 or newer is required for the min-version resolver. You can use `nix develop` to start a shell with Nim and Nimble; if that shell has an older Nimble, run `nimble install nimble` and use the newer binary, typically `~/.nimble/bin/nimble`.

## Getting Started

### Hello World example

Try to compile and run a simple example to ensure that everything is working on your machine.

```bash
nim c -r examples/helloworld.nim
```

### Chat example

Try out the chat example, where you can chat between two instances.

Run chat example (first instance):

```bash
nim c -r examples/directchat.nim
```

This will output a peer ID such as `QmbmHfVvouKammmQDJck4hz33WvVktNEe7pasxz2HgseRu` which you can use in second instance to connect to it.

Then run chat example again (second instance):

```bash
nim c -r examples/directchat.nim
```

And then use peer ID from first instance to connect to it, by typing in second instance:

```bash
/connect QmbmHfVvouKammmQDJck4hz33WvVktNEe7pasxz2HgseRu # use peer ID from first instance
```

![Chat example](https://imgur.com/caYRu8K.gif)

## Testing

Run unit tests:

```sh
# run all the unit tests
make test

# run tests matching a path substring:
# - Directory name: "transports" matches all tests in transports/
# - Partial filename: "quic" matches test_quic.nim, test_quic_stream.nim, etc.
# - Exact filename: "test_ws.nim" matches only that specific file
# - Full path: "libp2p/transports/test_tcp" matches libp2p/transports/test_tcp.nim
make test quic
make test transports/test_ws
# etc ...

# run specific test suites
make test_multiformat_exts
make test_integration
```

For faster iteration during development, you can bypass nimble overhead by compiling the test file directly:

```sh
# compile and run all tests
nim c -r tests/test_all.nim

# compile and run tests matching a path substring
nim c -r -d:path=quic tests/test_all.nim
nim c -r -d:path=transports/test_ws tests/test_all.nim
nim c -r -d:path=mix tests/test_all.nim

# compile and run specific test file
nim c -r tests/tools/test_multiaddress.nim
```

### GossipSub queue pressure

GossipSub limits both message counts and encoded RPC bytes per peer. Configure
`maxHighPriorityQueueBytes`, `maxMediumPriorityQueueBytes`, and
`maxLowPriorityQueueBytes` through `GossipSubParams.init`; defaults are 16, 32,
and 64 MiB, respectively. Each limit must be positive. High-priority overflow
disconnects the peer; medium/low overflow drops the incoming message and applies
the existing slow-peer penalty. When all queues are empty, a message of any
priority is sent immediately using the high-priority limits.

Bytes remain charged while a message waits for a stream or a transport write to
finish, including a medium/low message already removed from its deque by the
worker. `peer.queuedBytes(priority)` exposes this accounting. The budget excludes
transport framing, allocator overhead, and additional transport-owned copies;
it is not a bound on total process memory.

Run the queue pressure benchmark with:

```sh
nim c -r -d:release -d:chronicles_log_level=ERROR tests/benchmarks/bench_pubsub_queues.nim
# Raise the byte budget so the existing 512-message count limit binds instead:
nim c -r -d:release -d:chronicles_log_level=ERROR -d:queueBenchBytes=2147483647 tests/benchmarks/bench_pubsub_queues.nim
```

The benchmark measures 100,000 synchronous 256-byte sends and a burst cycling
through 256-byte, 4-KiB, and 64-KiB messages behind a stalled write. It reports CPU
time per send, occupied-heap growth after collection, dropped messages, accounted
bytes, and heap growth after cleanup. The default benchmark byte budget is 1 MiB
to make the difference from count-only limiting visible. Heap measurements omit
reserved GC pages and transport buffering; timing is a local microbenchmark,
not a network throughput measurement.

A sample comparison against `c58f7f997` on Linux x86-64, Intel Core Ultra 7
155H, Nim 2.2.6/refc (`-d:release`), using medians of nine interleaved runs:

| Version / medium byte budget | Synchronous send (ns) | Stalled burst send (ns) | Retained occupied heap (bytes) |
| --- | ---: | ---: | ---: |
| Before byte accounting | 331.5 | 617.0 | 13,322,304 |
| Byte accounting, count limit binds | 368.9 | 654.3 | 13,322,304 |
| Byte accounting, 1 MiB budget | 338.3 | 542.6 | 1,174,912 |

The 1 MiB run accounted for exactly 1,048,576 payload bytes and dropped 99,954
messages, versus 99,488 drops when count-limited. Its occupied heap fell to
1,568 bytes above the starting measurement after cleanup (the empty peer and
stream were still alive). CPU timing ranges overlapped; rerun on deployment
hardware before choosing budgets or drawing throughput conclusions.

## Formatting code

nim-libp2p uses [nph](https://github.com/arnetheduck/nph) to format code.

Do `nimble install nph@v0.7.0` once to install nph, then `nimble format` (or `nph ./. *.nim`) to format code.

## Logs

nim-libp2p uses [chronicles](https://github.com/status-im/nim-chronicles) library for structured logging.

Use the [logging policy](logging.md) when adding or reviewing log calls. It
defines severity by operational impact and user action; this section only
describes configuring Chronicles.

chronicles is configured at compile time. You can adjust the log detail level using compile time flags like this:

```bash
nim c -r -d:chronicles_log_level=error examples/helloworld.nim
```

where `chronicles_log_level` can have following values: `none`, `error`, `warn`, `info`, `debug` and `trace` (values are case-insensitive).

If you are overwhelmed with logs, you can disable topics that aren’t relevant and increase the logging level for the ones that matter most:

`-d:chronicles_enabled_topics:switch:TRACE,quic:INFO`

---

[← Back to README](../README.md)
