# Topic streams interoperability

Tests the local Nim implementation against go-libp2p-pubsub
[PR #725](https://github.com/libp2p/go-libp2p-pubsub/pull/725), pinned to
`eb94b22f78a2db2626c60dcd86bc9bf7fc849f2a` in `go-peer/go.mod`.

The Go peer connects to a Nim echo peer over loopback TCP, Noise, and Yamux.
It sends two rounds of signed messages on two topics (32 bytes and 256 KiB)
and checks each echo's sender, topic, and exact payload. Both peers retain
signature verification, exercising reconstruction of the topic omitted on
topic streams. The Go peer also requires exactly two `/gsts/v0beta` streams
in each direction after both rounds, checking topic separation and reuse
and preventing an ordinary GossipSub fallback from passing.

From the repository root, with Go 1.25+, Nim 2.2.10, and the repository's
Nim dependencies installed (`nimble setup`):

```sh
mkdir -p build
(cd interop/topic-streams/go-peer && go build -o ../../../build/topic-streams-go .)
nim c --nimcache:build/topic-streams-nimcache \
  --warningAsError:UseBase:off --warningAsError:UnusedImport:off \
  --hintAsError:XCannotRaiseY:off --out:build/topic-streams-nim \
  interop/topic-streams/nim-peer/src/peer.nim
bash interop/topic-streams/run.sh
```

The compiler flags leave existing `UseBase`, `UnusedImport`, and `XCannotRaiseY`
diagnostics in imported repository modules visible without treating them as
errors for this standalone peer. They do not change protocol behavior.

The runner uses an ephemeral port and a temporary address file, bounds startup
and test time, prints Nim logs, and cleans up the background peer on failure
or success. A nonzero exit means the test failed.
