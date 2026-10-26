# Topic streams interoperability

Checks that Nim and Go can exchange GossipSub messages using topic streams
over QUIC v1. The Go peer uses the topic-streams implementation from
[go-libp2p-pubsub PR #725](https://github.com/libp2p/go-libp2p-pubsub/pull/725),
pinned in [go.mod](go-peer/go.mod).

The Go peer sends signed messages to a local Nim echo peer on two topics:
one with 32-byte payloads and one with 256 KiB payloads. Each topic makes two
round trips. The test verifies the sender, topic, payload, and signatures,
and checks that each topic reuses its own stream in both directions.
TCP and ordinary GossipSub fallback cannot satisfy the test.

To run it, install Go 1.25+, Nim 2.2.10, and the repository's Nim dependencies
(`nimble setup`). Then run these commands from the repository root:

```sh
mkdir -p build
(cd interop/topic-streams/go-peer && go build -o ../../../build/topic-streams-go .)
nim c --nimcache:build/topic-streams-nimcache -d:chronicles_log_level=TRACE \
  --warningAsError:UseBase:off --warningAsError:UnusedImport:off \
  --hintAsError:XCannotRaiseY:off --out:build/topic-streams-nim \
  interop/topic-streams/nim-peer/src/peer.nim
bash interop/topic-streams/run.sh
```

On success, the runner prints:

```text
Topic streams interop passed over QUIC v1: two signed round trips per topic, two streams per direction
```

A nonzero exit means the test failed. The runner prints Nim logs for diagnosis,
stops the background peer, and removes its temporary files automatically.
No port configuration is needed.
