# Compile time flags

Enable expensive metrics (ie, metrics with per-peer cardinality):

```bash
nim c -d:libp2p_expensive_metrics some_file.nim
```

Set list of known libp2p agents for metrics:

```bash
nim c -d:libp2p_agents_metrics -d:KnownLibP2PAgents=nimbus,lighthouse,lodestar,prysm,teku some_file.nim
```

Specify gossipsub specific topics to measure in the metrics:

```bash
nim c -d:KnownLibP2PTopics=topic1,topic2,topic3 some_file.nim
```

The compile-time flag `libp2p_testing` is used in test builds to expose code to tests without making it available to end users.
It is by default added to `tests/config.nims`.
```bash
-d:libp2p_testing
```

Use the compile-time flag `libp2p_testing_slow` for test environments that run substantially slower than normal, such as the coverage workflow. It increases the default test timeouts to account for coverage instrumentation, which makes tests approximately twice as slow.

```bash
-d:libp2p_testing_slow
```

## Flags that extend `MultiFormats`

| Multi format   | Compiler flag<br>(path to extensions file) | Expected definition in extension file |
| -------------- | ------------------------------------------ | ------------------------------------- |
| `MultiCodec`   | `-d:libp2p_multicodec_exts`                | `const CodecExts = []`                |
| `MultiHash`    | `-d:libp2p_multihash_exts`                 | `const HashExts = []`                 |
| `MultiAddress` | `-d:libp2p_multiaddress_exts`              | `const AddressExts = []`              |
| `MultiBase`    | `-d:libp2p_multibase_exts`                 | `const BaseExts = []`                 |
| `ContentIds`   | `-d:libp2p_contentids_exts`                | `const ContentIdsExts = []`           |

For example, a file called `multihash_exts.nim` could be created and contain `MultiHash` extensions:

```nim
proc coder1(data: openArray[byte], output: var openArray[byte]) =
  copyMem(addr output[0], addr data[0], len(output))

proc coder2(data: openArray[byte], output: var openArray[byte]) =
  copyMem(addr output[0], addr data[0], len(output))

proc sha2_256_override(data: openArray[byte], output: var openArray[byte]) =
  copyMem(addr output[0], addr data[0], len(output))

const HashExts = [
  MHash(mcodec: multiCodec("codec_mc1"), size: 0, coder: coder1),
  MHash(mcodec: multiCodec("codec_mc2"), size: 6, coder: coder2),
  MHash(mcodec: multiCodec("sha2-256"), size: 6, coder: sha2_256_override),
]
```

These `MultiHashes` will be available at compile time when the binary is compiled with `-d:libp2p_multihash_exts=multihash_exts.nim`.

---

[← Back to README](../README.md)
