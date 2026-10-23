# Experimental Waggle dissemination

`libp2p/protocols/waggle` implements topic streams and incremental object
dissemination from [specs#732](https://github.com/libp2p/specs/pull/732), pinned to
revision `9328b68`. The experimental implementation follows the pinned Rust behaviour,
with application-defined object semantics and an API that may still change.

## Wire contract

The protocol negotiates `/waggle/1.0`. Each frame has an unsigned varint byte
length followed by a protobuf message. The subscriber opens the stream and
writes exactly one `TopicSubscription` (required bytes field 1). The remote
then sends `ObjectPieces` messages on the reverse direction of that stream:

- Required object ID: bytes field 2.
- Optional piece metadata: bytes field 3.
- Optional pieces: bytes field 4.

Absent optional fields and present empty byte strings remain distinct. Topic
and object IDs are opaque bytes; empty IDs are permitted. Unknown protobuf
fields are ignored, and missing required fields or malformed messages are
rejected.

This stream direction follows the current
[sigp/waggle Rust implementation](https://github.com/sigp/waggle/blob/master/src/handler.rs).
The draft does not yet settle directionality or framing. Two peers wanting
mutual delivery each open their own subscription stream. The subscriber sends
no further bytes after its handshake. Closing or cancelling that subscription
removes it; reopening requires a new stream and handshake. Each registered connection has independent subscriptions and peer views;
multiple connections to the same peer are supported.
The [Nim/Rust interop harness](../interop/waggle/README.md) verifies this
contract against a pinned Rust implementation.

## Managed usage

Implement `WaggleShard.objectId`, `metadata`, and `actionFromMetadata`, plus
`WaggleMetadata.clone`, `bytes`, and `update`. Metadata snapshots and clones must
be independent of mutable application state. `update` merges peer metadata and
returns whether it changed, or rejects invalid input. The action selects missing
pieces and the peer metadata expected after sending them; `need` controls whether
an incoming message is surfaced to the application.

The [bit-set fixture](../tests/libp2p/protocols/waggle_utils.nim) is a small example.
A shard passed to `publish` must describe the entire current object snapshot,
including pieces the application has already integrated. Do not mutate published
snapshots. Publish a replacement when the object's state changes.

For a Switch, create the protocol with `Waggle.new(onEvent = handler, rng = rng)`,
call `protocol.attach(switch.connManager)`, and mount it before starting the switch.
`attach` discovers existing and future connections; it does not dial new peers.
For a manually upgraded stack, register each running muxer with
`protocol.addConnection(muxer)`, as the interop peer does. Its stream handler must
route incoming streams through a multistream selector containing the protocol.

```nim
# Subscribe on all registered connections, including connections added later.
discard protocol.subscribe(topic).get()

# Queue selective transmissions to a random subset of subscribers.
let sent = protocol.publish(topic, currentObjectSnapshot)
if sent.isErr:
  # Handle absent subscribers, invalid local state, or saturated queues.
  discard

# Close our receive streams and discard cached state for this topic.
discard await protocol.unsubscribe(topic)
```

The synchronous `onEvent` callback receives `Received`, `Subscribed`,
`Unsubscribed`, `InvalidData`, `FullQueue`, and `StreamFailed` events, with the peer,
connection ID, and topic. `Received` includes the opaque wire message. Validate
and integrate its payload in the application, then publish a new snapshot. A
metadata-only event carries knowledge about the peer, not pieces to integrate.
Callbacks must not block; synchronous calls to `publish` from the callback are
supported. Peer scoring and penalties remain application decisions.

## Direct stream API

The original `subscribe(stream, topic, handler)`, `subscribers(topic)`, and
`send(peer, topic, message)` operations are still available for wire-level users.
They bypass the managed receive path and reconciliation policy. Use managed
publishing for cached objects, rather than mixing direct sends with tracked state.

`subscribe` takes ownership of an already-negotiated stream and runs until EOF,
cancellation, or error. The caller owns its future and must cancel and await it
when unsubscribing. Incoming subscriptions are handled by the mounted protocol.
`subscribers(topic)` lists peers eligible to receive messages. `send` returns
false when the target peer has no subscription; stream errors and cancellation
propagate to the caller. Receiving messages calls the supplied handler in wire
order, applying backpressure while it runs.

Concurrent sends are serialized per stream without an internal message queue.
Applications must bound the number of outstanding send calls and apply their
own write deadlines. Failed or cancelled writes reset the stream, since the
remote might have received a partial frame. Cancellation while waiting for a
write lock does not reset a stream another caller is using.

## Dissemination and resource limits

`publish` stores an object snapshot in a per-topic LRU cache and selects subscribed
connections in random order, up to the topic's publish fanout. It compares local
state with each connection's metadata to send only missing pieces and changed
metadata. Repeating an unchanged snapshot returns zero when nothing is needed;
a new connection can still receive it. If a queue rejected the previous attempt,
republishing the unchanged snapshot retries the unsent transmission.

Receiving data updates the connection's partial view, emits needed data, and
queues any selective reply. It also advertises cached object metadata to other
subscribers, up to the gossip fanout. Gossip is triggered by received messages;
there is no periodic heartbeat in the pinned Rust implementation. Applications
must integrate newly received pieces and publish the resulting snapshot before
those pieces can be served to other peers.

Peer views advance only after a message enters its bounded queue. Metadata-only
gossip does not mark omitted pieces as delivered. Unsubscribe/resubscribe and
connection closure clear the relevant views, allowing a renewed subscription
to synchronize again. Local unsubscribe also removes that topic's cache.

Defaults are 64 KiB protobuf payloads, 1024-byte topic IDs, 128 streams and
registered connections, 16 streams per peer, 64 local topics/configurations, and
100 cached objects per topic. Remote object views are separately bounded to 100
per topic and connection. Pending stream opens and incoming handshakes count
against stream limits. Each connection has a shared budget of 5000 queued
messages, with a separate writer for each topic stream. Set constructor arguments
to tune these limits. `setTopicConfig` sets positive publish/gossip fanouts per
topic; both default to 50. An optional topic whitelist rejects disallowed local
and remote subscriptions.

The object cache is an LRU, without a protocol-owned TTL. The application owns
object validity and lifetime, as in the pinned Rust cache. The limits bound entry
and queue counts, not the size of application-owned shard objects; applications
must also bound their snapshots and handler work.

`stop` unregisters connection handlers, closes protocol streams, drains owned
tasks, and clears caches/views without closing shared muxers. Local topic choices
are retained. `start` discovers existing connections again when attached to a
connection manager. A remote whose receive stream was closed must renew its
subscription. Direct-stream callers must still cancel and await their own
subscription tasks. Failed protocol stream opens are surfaced through
`StreamFailed`; there is no automatic retry loop.

## Verification and remaining scope

The unit tests cover selective replies, duplicate suppression, queue-full retry,
LRU eviction, remote view bounds, fanout, topic isolation, three-peer convergence,
multiple connections to one peer, reconnect, unsubscribe/resubscribe, and stopping
without disrupting shared connections. The interop harness exercises both wire
exchange and managed reconciliation against the pinned Rust implementation.

The draft's framing and stream-direction choices remain provisional. Discovery,
application validation/reconstruction, signing, peer scoring, and retries after
failed stream opens are outside the engine. Standalone Switch compilation
encounters baseline `UseBase` diagnostics in `switch.nim`; connection-manager
attachment is tested directly, and interop uses
the TCP/Noise/Yamux upgrade stack.
