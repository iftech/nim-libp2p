# Experimental Waggle dissemination

`libp2p/protocols/waggle` implements topic streams and incremental object
dissemination from [specs#732](https://github.com/libp2p/specs/pull/732), pinned to
revision `9328b68`. The experimental implementation interoperates with the
pinned Rust behaviour, with application-defined object semantics and an API
that may still change.

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

For a Switch, create the protocol with
`Waggle.new(switch = switch, onEvent = handler, rng = rng)` and mount it before
starting the switch. The constructor attaches to the switch's connection manager
to discover existing and future connections; it does not dial new peers.
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
Malformed subscription/object messages and unexpected subscriber writes produce
`InvalidData`, closing the offending stream. Normal protocol negotiation
rejection produces `StreamFailed`. Callbacks must not block; synchronous calls
to `publish` from the callback are supported. Peer scoring and penalties remain application decisions.

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

`publish` stores an object snapshot in a per-topic LRU cache. Initial publication
seeds randomly selected subscribers up to `publishFanout`. Updating an existing
snapshot forwards missing pieces to connections whose object state is known, up
to `forwardFanout`. Unchanged snapshots can retry rejected transmissions and
seed newly connected subscribers. The initial fanout bounds all initial
transmissions; the forwarding fanout bounds payload transmissions. Existing observers may also receive changed
metadata without a payload.

Changed metadata is advertised to every connection previously sent our metadata.
Up to `gossipFanout` additional connections with unknown object state receive
metadata-only discovery messages. A zero gossip fanout disables new discovery,
while existing observers continue receiving updates. Receiving a message also
triggers metadata advertisements to other subscribers. There is no periodic
heartbeat. Applications must validate and integrate received pieces, then
publish the resulting snapshot before those pieces can be forwarded. For an
unknown object advertised only through metadata, the application can publish an
empty snapshot to advertise what it needs and initiate reconciliation.

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
to tune these limits. `setTopicConfig` sets publish, forwarding, and gossip
fanouts per topic; all default to 50. Publish and forwarding must be positive;
gossip may be zero. An optional topic whitelist rejects disallowed local and
remote subscriptions.

The constructor's positive `objectLifetime` defaults to five minutes. Local
snapshots expire from their last publication, and peer views expire from their
creation or last received message. Expired entries are discarded lazily when
that topic is accessed; expired snapshots are unavailable for reconciliation. Idle topics retain
bounded expired allocations until their next access or protocol stop. Cache
reads and outgoing advertisements do not renew lifetime.

`removeObject(topic, objectId)` explicitly forgets a snapshot and its peer views;
it returns whether any state existed. Expiry and removal retain already queued
or in-flight transmissions; neither is a recall operation. Neither expiry nor removal prevents
an application from publishing the object again. Applications define object
validity and must bound snapshot sizes and handler work; the protocol's other
limits bound entry and queue counts.

`stop` unregisters connection handlers, closes protocol streams, drains owned
tasks, and clears caches/views without closing shared muxers. Local topic choices
are retained. `start` discovers existing connections again when attached to a
connection manager. A remote whose receive stream was closed must renew its
subscription. Direct-stream callers must still cancel and await their own
subscription tasks. Failed protocol stream opens are surfaced through
`StreamFailed`; there is no automatic retry loop.

## Verification and remaining scope

The unit tests cover selective replies, duplicate suppression, queue-full retry,
LRU eviction, expiry, explicit removal, remote view bounds, forwarding/discovery
fanouts, observer updates, protocol-violation events, topic isolation, three-peer
convergence, multiple connections to one peer, reconnect, unsubscribe/resubscribe, and stopping
without disrupting shared connections. The interop harness exercises wire
exchange, managed reconciliation, three-peer convergence, subscription renewal,
reconnect, and queue-full recovery against the pinned Rust implementation.

The draft's framing and stream-direction choices remain provisional. Discovery,
application validation/reconstruction, signing, peer scoring, and retries after
failed stream opens are outside the engine. Switch integration is covered by a
TCP/Noise/Mplex exchange test, alongside direct connection-manager coverage.
Interop uses the TCP/Noise/Yamux upgrade stack.
