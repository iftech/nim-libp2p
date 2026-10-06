# nim-libp2p Coding Agent Instructions

## Project Overview

**nim-libp2p** is a native Nim implementation of the [libp2p](https://libp2p.io) peer-to-peer networking stack. It is used in production by [Nimbus (Ethereum client)](https://github.com/status-im/nimbus-eth2) and other projects.

- **Language**: Nim ( see `libp2p.nimble` and `.github/workflows/ci.yml` for currently supported versions)
- **License**: Apache 2.0 OR MIT
- **Version**: 1.15.3
- **Author**: Status Research & Development GmbH

---

## Repository Layout

```
nim-libp2p/
├── libp2p/           # Main source code
│   ├── switch.nim              # Core: manages connections, protocols, transports
│   ├── standard_switch.nim     # Default switch implementation
│   ├── builders.nim            # Builder pattern for switches
│   ├── peerid.nim / peerinfo.nim / peerstore.nim
│   ├── peeridauth/                 # Peer ID HTTP authentication (client/server)
│   ├── multiaddress.nim / multistream.nim
│   ├── crypto/                 # Cryptographic primitives
│   ├── muxers/                 # Stream multiplexers (mplex, yamux)
│   ├── protocols/              # P2P protocols
│   │   ├── connectivity/       # AutoNAT, DCUtR, Circuit Relay
│   │   ├── pubsub/             # GossipSub, FloodSub
│   │   ├── kademlia/           # Kademlia DHT
│   │   ├── perf/               # Performance measurement protocol
│   │   └── secure/             # Noise, Plaintext
│   ├── transports/             # TCP, QUIC, WebSocket, Tor, Memory
│   ├── stream/                 # Stream abstractions
│   ├── autotls/                # Automatic TLS certificate management (ACME)
│   ├── services/               # Auto-relay, hole punching, wildcard resolver
│   └── utils/                  # Utilities
├── tests/
│   ├── test_all.nim            # Main test runner
│   ├── libp2p/                 # Unit tests mirroring source structure
│   ├── integration/            # Integration tests (WebSocket, AutoTLS, peer ID auth)
│   └── interop/                # Cross-implementation interoperability tests
├── examples/                   # Tutorial and example applications
├── cbind/                      # C/CDDL FFI bindings (generated via nim-ffi)
├── docs/                       # Documentation
│   ├── README.md               # Documentation index
│   ├── development.md          # Setup and testing guide
│   ├── contributing.md         # Contribution guidelines
│   ├── compile_time_flags.md   # All compile-time flags documented
│   ├── common_hurdles.md       # Known issues and fixes
│   └── interop_hole_punching.md  # Hole punching interop test guide
├── tools/                      # Developer tools (dependency pinner, markdown runner, etc.)
├── libp2p.nim                  # Main entry point (re-exports public APIs)
├── libp2p.nimble               # Package manifest and build tasks
├── config.nims                 # Compiler configuration (warnings, style, memory)
└── Makefile                    # Top-level build targets
```

---

## Build & Test

### Setup
```sh
git clone https://github.com/vacp2p/nim-libp2p
cd nim-libp2p
make                 # Set up lowest supported dependency set
# Or: nix develop     # Nix-based dev environment
```

> **Note**: nimble 0.24.0+ is required for the min-version resolver. If using `nix develop`, the nix environment may not have a sufficiently recent nimble — in that case, run `nimble install nimble` inside the nix shell to get a newer version (typically installed to `~/.nimble/bin/nimble`).

### Running Tests
```sh
# Run all unit tests
make test

# Run tests matching a path substring
make test quic                         # all quic tests
make test transports/test_ws           # specific test file

# Run specific test suites
make test_multiformat_exts             # MultiFormat extension tests
make test_integration                  # Integration tests
```

### Faster Iteration (bypass nimble overhead)
```sh
nim c -r tests/test_all.nim
nim c -r -d:path=quic tests/test_all.nim
nim c -r tests/tools/test_multiaddress.nim
```

### Code Formatting
```sh
nimble install nph@v0.7.0   # Install formatter (once)
nimble format               # Format all code
```

### Logging / Debug
```sh
nim c -r -d:chronicles_log_level=debug examples/helloworld.nim
nim c -r -d:chronicles_enabled_topics:switch:TRACE,quic:INFO examples/helloworld.nim
```

---

## Compiler Configuration (`config.nims`)

Warnings are treated as errors. All of the following must pass cleanly:

```nim
switch("warningAsError", "BareExcept:on")
switch("warningAsError", "CaseTransition:on")
switch("warningAsError", "CStringConv:on")
switch("warningAsError", "ImplicitDefaultValue:on")
switch("warningAsError", "LockLevel:on")
switch("warningAsError", "ObservableStores:on")
switch("warningAsError", "ResultShadowed:on")
switch("warningAsError", "UnreachableCode:on")
switch("warningAsError", "UnreachableElse:on")
switch("warningAsError", "UnusedImport:on")
switch("warningAsError", "UseBase:on")
switch("hintAsError", "ConvFromXtoItselfNotNeeded:on")
switch("hintAsError", "DuplicateModuleImport:on")
--styleCheck: usages
--styleCheck: error
--mm: refc          # Reference counting (not ORC yet)
```

**Important**: The style checker enforces consistent identifier casing. Identifier names must match their declaration exactly.

---

## Compile-Time Feature Flags

These flags are used in CI and tests:

| Flag | Purpose |
|------|---------|
| `-d:libp2p_expensive_metrics` | Per-peer cardinality metrics |
| `-d:libp2p_agents_metrics -d:KnownLibP2PAgents=nimbus,...` | Known agent metrics |
| `-d:KnownLibP2PTopics=topic1,topic2` | GossipSub topic metrics |
| `-d:libp2p_multicodec_exts=<path>` | MultiCodec extensions file |
| `-d:libp2p_multihash_exts=<path>` | MultiHash extensions file |
| `-d:libp2p_multiaddress_exts=<path>` | MultiAddress extensions file |
| `-d:libp2p_multibase_exts=<path>` | MultiBase extensions file |
| `-d:libp2p_contentids_exts=<path>` | ContentIds extensions file |

---

## Key Dependencies

- **chronos** (`>= 4.2.2`) — Async I/O framework (core dependency, used everywhere)
- **chronicles** (`>= 0.11.0`) — Structured logging
- **stew** (`>= 0.4.2`) — Utility library
- **results** — Result/Option types for error handling
- **nimcrypto** — Cryptographic algorithms
- **secp256k1** — Secp256k1 curve operations
- **bearssl** — TLS/SSL
- **dnsclient** (`>= 0.3.0, < 0.4.0`) — DNS client (used by AutoTLS)
- **websock** (`>= 0.4.0`) — WebSocket transport (GitHub dependency; see `libp2p.nimble`)
- **lsquic** (`>= 0.4.1`) — QUIC transport
- **nim-jwt** — JWT library for AutoTLS/ACME (pinned to a specific GitHub commit; see `libp2p.nimble` for the exact pin)
- **unittest2** — Testing framework

---

## Code Conventions

#### `result` return
- DO NOT USE `result` for returning values.
- Use expression-based return or explicit return keyword with a value

### Async Model
- All async code uses **chronos** (`import chronos`)
- Use `async` / `await` / `Future[T]` patterns
- Async procedures return `Future[T]` or `Future[void]`
- Manually created `Futures` should specify the exceptions they raise: `Future[someType].Raising([ListOfExceptionsHere]).init()`
- `init()` procedure should always be called with identifier of future that explains purpose of future or where it was created. For example `init("Stream.readOnce")`
- `cancel()` procedure of `Future` type is deprecated, code should either call `cancelSoon()` for non-blocking call or `cancelAndWait()` for blocking call until the future is canceled/has been canceled.
- Give suggestions if  `cancelSoon()` or `cancelAndWait()` should be called.
- Do not use `asyncSpawn` unless the future reference is explicitly tracked. Running a future with `asyncSpawn` without tracking its reference risks the future being freed/deallocated when it becomes unreferenced.
- Usage of `AsyncLock` must always be documented. Provide a clear explanation of why the lock is required in that context. This ensures that locking decisions are transparent, justified, and maintainable.

### Avoid `sleepAsync`
- `sleepAsync` should be avoided when is used to fix race condition, or to wait on condition, becasue it is always source of flakyness.
- Remaind developer that:
  - if `sleepAsync` is used in tests, then `checkUntilTimeout` might be use to wait for condition
  - if it is necessery to use `sleepAsync`, comment with reasoning why it was used must be added next to it

### Error Handling
- Use the **results** library: `Result[T, E]`, `?`, `valueOr`, `isOk`, `isErr`
- Custom error types are in `libp2p/errors.nim` (derive from `LPError`)
- Use `valueOr` over `tryGet()` when catching errors — `tryGet()` raises `ResultError[string]` which is NOT a subtype of `LPError`
- Example: use `let ma = maResult.valueOr: return err(...)` not `let ma = maResult.tryGet()`

### Logging
- Choose log levels by operational impact and the action required from the library user:
  - `error`: an enabled component or background operation has stopped working and requires investigation.
  - `warn`: the library remains usable, but the user should correct configuration, API use, a callback, or a resource constraint.
  - `info`: a low-frequency normal lifecycle milestone, such as a component starting or stopping.
- Do not use `warn` or `error` for expected peer-controlled failures such as malformed input, handshake failures, or timeouts. Use `trace`, or `debug` for a bounded operation-level summary.
- Every project-defined type used as a log field must define `shortLog` and register `chronicles.formatIt` to delegate to it. `shortLog` must return a safe, bounded representation for large strings, byte sequences, messages, collections, and other potentially large types.
- Always define `logScope` in files
- Never log secrets or sensitive information at any log level. Omit or redact private keys, credentials, tokens, sensitive payloads, and sensitive exception text

### Memory Management
- Memory model: `--mm:refc` (reference counting)
- For C bindings (`cbind/`): the FFI runtime (threads, request channel, shared
  memory, CBOR codec) is provided by `nim-ffi`; annotate procs/types instead

### Style

#### General
- Nim identifier naming: `camelCase` for variables/procedures, `PascalCase` for types
- Style check is **strict** — naming must match declaration exactly
- No bare `except` clauses (use typed exceptions)
- No unused imports
- Use runtime feature flags or configs for experimental features. Use compile-time flags ONLY when the code must not exist in the binary due to security, compliance, platform, ABI, or substantial size/performance constraints.

#### Detecting unused symbols
- Always check for unused identifiers. Flag any variable, parameter, procedure, function, iterator, template, or macro that meets any of these conditions:
  - Declared but never referenced anywhere in the module or project
  - A proc/func/iterator that is never called
  - A template or macro that is never expanded
  - A variable that is shadowed and the outer declaration is unused
  - A parameter that is never used inside its body
  - A let/var/const that is only assigned but never read
  - A symbol that is exported (*) but never used internally or externally
- For each unused identifier, report:
  - The name of the symbol, file and line number
  - Why it is considered unused
- Do not warn about:
  - Symbols marked with `{.used.}`
  - Symbols required by an interface, callback, or external API
  - Compile‑time only symbols used via `static`, `when`, or macro expansion

#### Leverage the Type System
- Enforce strong typing: Always prefer explicit, well-defined types over loosely typed or primitive representations.
- Use `chronos.Duration` for durations
  - All duration values must be represented using `chronos.Duration`.
  - Do not use primitive types (`float`, `int`, etc.) for storing or passing durations. Replace them with `chronos.Duration`.
- Avoid tuples in public interfaces
  - Public APIs must not expose tuples.
  - Instead, define a named type (e.g., object) with clear field names to ensure readability and maintainability.
  - Exception: Tuples may be used only in functions that are internal to a single file and invoked in one place. They must never leak into shared or public APIs.

#### Exceptions
- For new or significantly modified public `*` functions, add an explicit `{.raises.}` annotation; existing public APIs may not yet follow this consistently.
- If you must use exceptions, use specific exception types. Avoid raising or capturing `CatchableError`. Catching `CatchableError` implies that all errors are funnelled through the same exception handler.
- Do not catch `CancelledError`. By not catching, it is propagated by default. Sometimes this exception is captured and re-raised which is fine.
- Use `e` as error variable name in `except` clause like `except LPStreamEOFError as e`
- In `except` blocks, preserve the original error message unless the exception is `CancelledError`.
  - If the code logs the error, include `e.msg` or `getCurrentExceptionMsg()` in the log message.
  - If the code raises a new error, append the original message (`e.msg` or `getCurrentExceptionMsg()`) to the new error so the triggering reason is preserved.
  - Do not do this for `CancelledError`, because those messages do not add value.

#### Result
- Use explicit error-signalling types (`bool`, `Opt`, `Result`) over implicit mechanisms like exceptions or status codes
- For optional values, use `Opt[T]` from `results` (import `results` and use the unqualified `Opt[T]` type).
- Do not use other option-like types such as `options.Option`.

#### Status codes
- Avoid status codes

#### Binary data
- Use `byte` to denote binary data. Use `seq[byte]` for dynamic byte arrays.
- Avoid `string` for binary data. If stdlib returns strings, [convert](https://github.com/status-im/nim-stew/blob/76beeb769e30adc912d648c014fd95bf748fef24/stew/byteutils.nim#L141) to `seq[byte]` as early as possible

#### Converters
- Avoid using converters.

#### Finalizers
- Don't use finalizers.

#### Import, export
- Use specific imports. Avoid `include`.

#### Inline functions
- Avoid using explicit {.inline.} functions.

#### Integers
- Use signed integers for counting, lengths, array indexing etc.
- Use unsigned integers of specified size for interfacing with binary data, bit manipulation, low-level hardware access and similar contexts.
- Don't cast `pointer` to `int`.
- Avoid `Natural` - implicit conversion from `int` to `Natural` can raise a `Defect`

#### Macros
- Be judicious in macro usage - use more simple constructs.
- Avoid generating public API functions with macros.
- Write as much code as possible in templates, and glue together using macros

#### Memory allocation
- Prefer to use stack-based and statically sized data types in core/low-level libraries.
- Use heap allocation in glue layers.
- Avoid `alloca`.

#### Object construction
- Use `Xxx(x: 42, y: Yyy(z: 54))` style, or if type has an `init` or `new` function, `Type.init(a, b, c)`.
- Prefer that the default 0-initialization is a valid state for the type.
- Avoid using `var instance: Type` which disable several compiler diagnostics
- If a function creates a stack object, it should be called `init`. If it returns a heap object `new`

#### Functions and procedures
- Use `func` when possible. Use `proc` when side effects cannot conveniently be avoided.
- Avoid public functions and variables (`*`) that don't make up an intended part of public API.
- Use `openArray` as argument type over `seq` for traversals

#### Callbacks, closures and forward declarations
- Annotate proc type definitions and forward declarations with `{.raises: [], gcsafe.}` or specific exception types.

#### `range`
- Avoid range types.

#### `ref object` types
- Avoid ref object types, except:
- Use explicit `ref MyType` where reference semantics are needed, allowing the caller to choose where possible.

#### Variable declaration
- Use the most restrictive of `const`, `let` and `var` that the situation allows.

#### Variable initialization
- Prefer expressions to initialize variables and return values

#### Hex output
- Print hex output in lowercase. Accept upper and lower case.

#### Standard library usage
- Use the Nim standard library judiciously. Prefer smaller, separate packages that implement similar functionality, where available.
- Use the following stdlib replacements that offer safer API (allowing more issues to be detected at compile time):
```
    async -> chronos
    bitops -> stew/bitops2
    endians -> stew/endians2
    exceptions -> results
    io -> stew/io2
    sqlite -> nim-sqlite3-abi
    streams -> nim-faststreams
```

#### `stew`
- stew contains small utilities and replacements for std libraries.
- If similar libraries exist in `std` and `stew`, use [stew](https://github.com/status-im/nim-stew).

#### `discard`
- `discard` should not be used for empty body statements in tests: if used in try-except block when error is expected it is better to use `expect` instead. For callbacks, they should either raise an error because they should not be called, or, if it is indeed a noop callback, it should be written once then reused always.

#### RNG
- Do not use `newRng()` as a default value for arguments in object constructors or initializers, because the entropy seed could be exhausted. Random arguments must always be passed down.
- Do not use `newRng()` in the nim-libp2p test files. Instead use `rng` template from `tests/tools/crypto.nim`.
- Ignore `nim-libp2p/tests/tools/crypto.nim` (that's the definition file)

### API Stability
- Treat the intended public API surface, especially modules re-exported from `libp2p.nim`, as backward-compatible within a MAJOR version.
- If a PR introduces a breaking change to that public API surface, add a comment in the PR description that clearly documents the breaking change, the affected modules or APIs, and any required migration notes.
- Do not warn about breaking changes in the following modules, because they are not yet considered stable and remain under active development: `kademlia`, `service_discovery`.
- Internal procedures and other non-public implementation details may change in MINOR versions.

### Experimental GossipSub Extensions
- Must use protobuf field numbers `> 0x200000` to force ≥4-byte tags
  (see `libp2p/protocols/pubsub/rpc/protobuf.nim`)

### Code Formatting
- After making any code changes, run `nph` on all modified files. If `nph` produces changes, include them in the same change or PR.

---

## Source Module Guide

### Core Modules
| Module | Purpose |
|--------|---------|
| `switch.nim` | Central hub: manages peers, protocols, transports |
| `standard_switch.nim` | Pre-configured Switch with sensible defaults |
| `builders.nim` | Builder API for constructing Switch instances |
| `peerid.nim` | Peer identity (cryptographic key-based) |
| `peerinfo.nim` | Metadata about a peer (addresses, protocols) |
| `peerstore.nim` | Storage and lookup of peer information |
| `multiaddress.nim` | Composable multi-protocol network addresses |
| `multistream.nim` | Protocol negotiation over streams |
| `errors.nim` | Base error type `LPError` |

### Transport Layer (`transports/`)
| Transport | File |
|-----------|------|
| TCP | `tcptransport.nim` |
| QUIC | `quictransport.nim` |
| WebSocket | `wstransport.nim` |
| Tor | `tortransport.nim` |
| In-memory (testing) | `memorytransport.nim` |

### Muxers (`muxers/`)
- `mplex/mplex.nim` — Mplex multiplexer
- `yamux/yamux.nim` — Yamux multiplexer

### Security (`protocols/secure/`)
- `noise.nim` — Noise protocol (primary)
- `plaintext.nim` — No encryption (testing only)

### Pub/Sub (`protocols/pubsub/`)
- `gossipsub.nim` — GossipSub (primary pub/sub, used in production)
- `floodsub.nim` — FloodSub (simpler, for compatibility)
- `gossipsub/` — Extensions: scoring, behavior, partial messages, ping-pong

### Connectivity (`protocols/connectivity/`)
- `autonat/` — AutoNAT v1 (NAT detection)
- `autonatv2/` — AutoNAT v2 (enhanced dial-back NAT detection)
- `dcutr/` — Direct Connection Upgrade Through Relay (hole punching)
- `relay/` — Circuit Relay v1/v2

### Identify (`protocols/`)
- `identify.nim` — Identify and Identify Push protocols (peer metadata exchange)

### Performance (`protocols/perf/`)
- `core.nim`, `client.nim`, `server.nim` — libp2p perf protocol for measuring throughput between peers

### Discovery (`protocols/`)
- `kademlia.nim` + `kademlia/` — Kademlia DHT
- `rendezvous.nim` + `rendezvous/` — Rendezvous server protocol
- `service_discovery.nim` + `service_discovery/` — Service discovery (random find, routing table manager)

### Services (`services/`)
- `autorelayservice.nim` — Automatic relay selection and connection
- `hpservice.nim` — Hole punching service
- `wildcardresolverservice.nim` — DNS wildcard resolver

### AutoTLS (`autotls/`)
- Automatic TLS certificate management using the ACME protocol
- `service.nim` — AutoTLS service
- `acme/` — ACME client and API for certificate issuance

### Peer ID Authentication (`peeridauth/`)
- HTTP-based Peer ID authentication protocol (client and server)
- `client.nim` — HTTP client for authenticating with remote peers
- `mockclient.nim` — Mock client for testing

---

## Test Conventions

- Tests are in `tests/libp2p/` mirroring source structure
- Test files named `test_*.nim`
- Main runner: `tests/test_all.nim`
- Uses the `importTests` macro (from `tests/imports.nim`) to recursively discover and import all `test_*.nim` files; supports path filtering via `-d:path=<substring>`
- Use `unittest2` framework
- Tests can be compiled and run directly: `nim c -r tests/libp2p/test_switch.nim`
- Path filtering: `-d:path=<substring>` selects test files whose path contains the substring
- Integration tests are in `tests/integration/` (run with `make test_integration`)
- Interoperability tests are in `tests/interop/`

### Test Stubs and Utilities
- `tests/stubs/` — Mock objects
- `tests/stublogger.nim` — Logger stub for tests
- `tests/imports.nim` — Common test imports; defines `importTests` macro for recursive test discovery

---

## C/CDDL Bindings (`cbind/`)

The `cbind/` directory exposes nim-libp2p to C via the [`nim-ffi`](https://github.com/logos-messaging/nim-ffi)
framework. nim-ffi provides the worker thread, request channel, shared memory,
CBOR codec and event queue, and *generates* the C/CDDL bindings from the
annotations in `libp2p.nim`:

- `libp2p.nim` — the top-level FFI module: `declareLibrary` + `{.ffi.}` /
  `{.ffiCtor.}` / `{.ffiDtor.}` / `{.ffiStatic.}` / `{.ffiEvent.}` /
  `{.ffiConst.}` annotations and the ported libp2p logic; `genBindings()` emits
  the bindings.
- `libp2p/config.nim` — config types and parsing, `include`d into `libp2p.nim`.
- `c_bindings/` — generated C header (`libp2p.h`), consumed by
  `logos-co/logos-libp2p-module`.
- `cddl_bindings/` — generated CDDL schema for the CBOR wire format.

```sh
cd cbind
nimble setup --localdeps -y
nimble buildffi         # Build ../build/liblibp2p.{so,dylib,dll}
nimble genbindings_c    # Generate c_bindings/libp2p.h
nimble genbindings_cddl # Generate the CDDL schema
```

**cbind conventions**:
- Requests/responses are CBOR; declare `{.ffi.}` object types for them — never
  raw `ptr`/`pointer` across the boundary.
- A `##` doc comment on an annotated proc is propagated into the generated
  bindings, so document the exported API there and nowhere else.
- Closed value sets are `{.ffi.}` enums (they emit a native C enum and cross the
  wire as text), not `int` ordinals the host has to hardcode.
- A proc that needs no node takes no `lib` param and is `{.ffiStatic.}`; its
  wrapper is `libp2p_static_<name>` and takes no ctx.
- Stream handles are plain `uint64` ids tracked in `LibP2P` state (nim-ffi has
  no handle type for incoming streams).
- Convert config-parsing failures to `return err(...)`; never `raiseAssert` on
  host-supplied input (the constructor returns a `Result`).
- Protocol/pubsub handlers are `{.ffiEvent.}` — host code subscribes via the
  generated `libp2p_add_event_listener`.

---

## CI Workflows (`.github/workflows/`)

| Workflow | Description |
|----------|-------------|
| `test_all.yml` | Main CI: Linux (amd64), macOS (arm64), Windows (amd64); Nim v2.2.4 & v2.2.10 |
| `daily_test_all_latest_deps.yml` | Daily tests that run using latest dependencies |
| `daily_test_all_no_flags.yml` | Tests without experimental flags |
| `daily_ci_report.yml` | Daily CI failure reporting: opens/updates GitHub issues for failed daily CI runs |
| `daily_nimbus.yml` | Nimbus-specific test matrix |
| `daily_runnable_examples.yml` | Daily runnable examples checks |
| `cbindings.yml` | FFI library build + C/CDDL binding generation |
| `coverage.yml` | Code coverage (uploads to codecov) |
| `linters.yml` | nph (Nim) + clang-format (cbind C/H) formatting checks |
| `pr_lint.yml` | PR title/description linting |
| `auto_assign_pr.yml` | Automatically assigns reviewers to PRs |
| `update_copilot_instructions.yml` | Weekly automated update of copilot-instructions.md |
| `examples.yml` | Example compilation/execution |
| `interop.yml` | Cross-implementation interoperability |
| `performance.yml` | Performance benchmarks |
| `documentation.yml` | Docs generation and deployment |
| `dependencies.yml` | Dependency update automation |

---

## Common Issues and Fixes

### `Error: undeclared identifier` when compiling
This usually means stale nimble packages. Fix:
1. Remove `~/.nimble`
2. Re-install Nim freshly
3. `nimble install nimble` (get latest nimble)
4. `nimble setup --localdeps -y` in the project

### Formatting errors in CI
Run `nimble format` locally before pushing. The `linters.yml` CI workflow checks formatting with `nph`.

### Windows-specific
`--define:nimRawSetjmp` is set on Windows (non-MSVC) to avoid stack corruption with SEH and exceptions.

### QUIC transport
Uses `lsquic` (`>= 0.4.1`). May require extra system dependencies for building.

---

## Documentation

- **API docs**: https://vacp2p.github.io/nim-libp2p/docs/
- **libp2p spec**: https://github.com/libp2p/specs
- **Chronos async**: https://github.com/status-im/nim-chronos
- **Chronicles logging**: https://github.com/status-im/nim-chronicles
- **Community Discord**: https://discord.com/channels/1204447718093750272/1351621032263417946

---

## Quick Reference

```sh
# Build (check compilation)
nim c libp2p.nim

# Run all tests
make test

# Run specific test
make test switch                # tests matching "switch"
make test protocols/pubsub

# Format code (required before PR)
nimble format

# Set up/lock dependencies
make setup                           # explicit setup target; also the default `make`
make lock                            # update app/tool lockfiles
```
