# Topic streams interoperability

Checks signed GossipSub messages over QUIC v1 against go-libp2p-pubsub
[PR #725](https://github.com/libp2p/go-libp2p-pubsub/pull/725), pinned in
[go.mod](go-peer/go.mod).

The Nim peer drives two round trips on each of two topics, with 32-byte and
256 KiB payloads. It verifies the echoed sender, topic, and payload after
signature validation. It requires one topic stream per topic in each direction
and checks that the same streams remain open across rounds. Ordinary GossipSub
fallback cannot pass.

The scenario and verdict live in `tests/interop/topic_streams.nim`. Component
tests in `tests/interop/test_topic_streams.nim` run that same helper against a
Nim echo peer, covering success, incorrect payloads and topics, missing echoes,
and a peer without topic-stream support. The standalone Nim executable calls
the helper and reports its result through its exit status.

The Go peer only subscribes and echoes. It stays alive until Nim disconnects,
so publishing the final echo cannot race shutdown or Nim's stream checks.

From the repository root, with Go 1.25+, Nim 2.2.10, and the repository's
Nim dependencies installed (`nimble setup`):

```sh
mkdir -p build
nim c -r --out:build/test-topic-streams tests/interop/test_topic_streams.nim
(cd interop/topic-streams/go-peer && go build -o ../../../build/topic-streams-go .)
nim c --nimcache:build/topic-streams-nimcache \
  --warningAsError:UseBase:off --warningAsError:UnusedImport:off \
  --hintAsError:XCannotRaiseY:off --out:build/topic-streams-nim \
  interop/topic-streams/nim-peer/src/peer.nim
bash interop/topic-streams/run.sh
```

On success, the Nim peer prints:

```text
Topic streams interop passed over QUIC v1: two signed round trips per topic, two streams per direction
```

The runner starts Go first, waits for its address file, then runs Nim. It bounds
startup and test time, prints Go logs, and cleans up the background peer and
temporary files. A nonzero exit means the test failed.
