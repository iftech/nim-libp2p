# Experimental Waggle dissemination

Waggle exchanges pieces of an object between peers subscribed to a topic. Each
peer advertises which pieces it has or needs, so other peers can send useful
pieces instead of repeatedly sending the whole object.

Applications define what an object and its pieces mean. Waggle manages topic
streams, tracks peer state, and queues pieces for transmission. Your application
validates received pieces, combines them, and publishes its updated state.
Erasure coding, signing, peer discovery, and peer scoring are application
responsibilities.

Waggle is optional: import and mount it to enable it on a switch. The protocol
and API are experimental and may change. This implementation follows
[specs#732](https://github.com/libp2p/specs/pull/732) at revision `9328b68` and is
tested against a [pinned Rust implementation](../interop/waggle/README.md).

## Get started

### Create and mount the protocol

Given an existing `switch`, random number generator `rng`, and event handler
`handleEvent`, create Waggle before starting the switch:

```nim
import libp2p/protocols/waggle

let protocol = Waggle.new(switch = switch, onEvent = handleEvent, rng = rng)
switch.mount(protocol)
await switch.start()
```

The constructor tracks existing and future connections through the switch's
connection manager. Connect to peers through your switch as usual; Waggle does
not discover or dial peers for you.

### Subscribe and publish

Topics are opaque byte sequences chosen by the application. Subscribing opens
receive streams on registered connections, including connections added later:

```nim
let topic = @[byte 1]
discard protocol.subscribe(topic).get()
```

To send an object, publish a `WaggleShard` describing its current state:

```nim
let sent = protocol.publish(topic, currentObjectSnapshot)
```

Handle the returned result: publication can fail when there are no subscribers,
the local state is invalid, or queues are full. A successful publication queues
transmissions; it does not confirm delivery to remote applications.

A published snapshot must include all pieces your application currently holds,
including pieces received from other peers. Keep that snapshot immutable. When
your state changes, publish a replacement.

To stop receiving a topic and discard its cached state:

```nim
discard await protocol.unsubscribe(topic)
```

### Define your object format

Waggle needs an application-defined `WaggleShard` and `WaggleMetadata` to decide
what to exchange. The [bit-set example](../tests/libp2p/protocols/waggle_utils.nim)
is a small implementation of both interfaces.

Implement these methods:

| Type | Method | Purpose |
| --- | --- | --- |
| `WaggleShard` | `objectId` | Identify the object the pieces belong to. |
| `WaggleShard` | `metadata` | Describe the object's available or wanted pieces. |
| `WaggleShard` | `actionFromMetadata` | Decide which pieces to send based on a peer's metadata. |
| `WaggleMetadata` | `clone` | Make an independent copy of the metadata. |
| `WaggleMetadata` | `bytes` | Encode metadata for transmission. |
| `WaggleMetadata` | `update` | Merge peer metadata, reporting whether it changed or rejecting invalid input. |

Metadata snapshots and clones must be independent of mutable application state.
The action returned by `actionFromMetadata` includes the pieces to send and the
peer metadata expected after sending them. Its `need` flag controls whether an
incoming message is passed to your application.

### Handle received pieces

The `onEvent` handler has this signature:

```nim
proc handleEvent(event: WaggleEvent) {.gcsafe, raises: [].}
```

For a `Received` event, validate the payload, integrate any useful pieces, then
publish a new snapshot. Waggle can only forward newly received pieces after your
application has integrated and republished them. A metadata-only event describes
the peer's state; it has no pieces to integrate. If it advertises an unknown
object, you can publish an empty snapshot to express what you need and begin
reconciliation.

The callback is synchronous and must not block. Calling `publish` from within
it is supported. Events identify the peer, connection, and topic:

| Event | Meaning |
| --- | --- |
| `Received` | A message is available for the application to process. |
| `Subscribed` / `Unsubscribed` | A remote subscription opened or ended. |
| `InvalidData` | A malformed message or unexpected subscriber write closed the offending stream. |
| `FullQueue` | A transmission could not enter a bounded queue. |
| `StreamFailed` | A stream operation failed, including protocol negotiation rejection. |

Failed stream opens are reported, but are not retried automatically. Peer
penalties and retry policy belong to the application.

## How objects spread

`publish` keeps a snapshot in a per-topic LRU cache. For a new object, it sends to
a random subset of subscribers. For an updated object, it forwards missing pieces
to connections whose object state is already known.

Three settings control this work. Set them per topic with `setTopicConfig`:

| Setting | Default | Controls |
| --- | --- | --- |
| `publishFanout` | 50 | Initial transmissions to subscribers. Must be positive. |
| `forwardFanout` | 50 | Payload transmissions when forwarding updates to known peers. Must be positive. |
| `gossipFanout` | 50 | Additional metadata-only advertisements to connections with unknown object state. May be zero. |

Connections previously sent our metadata also receive changed metadata. These
observer updates continue even when `gossipFanout` is zero, and may carry no
payload. Receiving a message also triggers metadata advertisements to other
subscribers. There is no periodic heartbeat.

Publishing an unchanged snapshot can retry rejected transmissions or seed newly
connected subscribers. Peer state advances only after a message enters its
queue; advertising metadata alone does not mark omitted pieces as delivered.
Each connection has its own subscriptions and peer state, including when several
connections belong to the same peer.

## Cache lifetime and cleanup

The `objectLifetime` constructor argument defaults to five minutes and must be
positive. Local snapshots expire from their last publication. Peer views expire
from their creation or last received message. Reading a cache entry or sending
an advertisement does not renew its lifetime.

Expiry is lazy: entries are removed when their topic is accessed. An idle topic
may retain bounded expired allocations until its next access or protocol stop,
but expired snapshots are unavailable for reconciliation.

Use `removeObject(topic, objectId)` to forget a snapshot and its peer views
explicitly. It returns whether any state existed. Expiry and removal leave
already queued or in-flight transmissions alone and allow later republication.

Unsubscribe/resubscribe and connection closure clear the relevant peer views,
allowing a renewed subscription to synchronize again. Local unsubscribe also
removes the topic's cache.

Stopping Waggle unregisters its connection handlers, closes protocol streams,
waits for its tasks, and clears caches and peer views. Shared muxers stay open.
Local topic choices are retained; on restart, an attached protocol discovers
existing connections again. Remote peers must renew receive subscriptions that
were closed by the stop.

## Resource limits

Constructor arguments configure the following defaults:

| Resource | Default limit |
| --- | --- |
| Protobuf payload | 64 KiB |
| Topic ID | 1024 bytes |
| Streams and registered connections | 128 each |
| Streams per peer | 16 |
| Local topics and topic configurations | 64 each |
| Cached objects per topic | 100 |
| Remote object views per topic and connection | 100 |
| Queued messages per connection, shared by its topic writers | 5000 |

Pending stream opens and incoming handshakes count against stream limits. An
optional topic whitelist rejects disallowed local and remote subscriptions.

These limits bound entry and queue counts. Your application must also bound
snapshot sizes and the work done by callbacks.

## Using Waggle without a Switch

For a manually upgraded transport stack, construct Waggle without `switch` and
register each running muxer with `protocol.addConnection(muxer)`. Route incoming
streams through a multistream selector containing the protocol.

The [managed protocol tests](../tests/libp2p/protocols/test_waggle_managed.nim)
include examples of registering connections directly. Most applications should
use the Switch constructor path shown above.

## Direct stream API

Use the direct API when your application needs to manage negotiated streams and
wire messages itself:

| Operation | Behavior |
| --- | --- |
| `subscribe(stream, topic, handler)` | Owns an already-negotiated receive stream and runs until EOF, cancellation, or error. |
| `subscribers(topic)` | Lists peers eligible to receive messages. |
| `send(peer, topic, message)` | Sends a wire message; returns false if the peer has no subscription. Stream errors and cancellation propagate. |

The mounted protocol handles incoming subscriptions. Your application owns each
direct subscription's future and must cancel and await it when unsubscribing,
even when the protocol is stopped.

Direct subscriptions call their handler in wire order, applying backpressure
while it runs. Concurrent sends are serialized per stream without an internal
message queue. Bound outstanding send calls and apply your own write deadlines.
Failed or cancelled writes reset the stream because a partial frame may have
reached the peer. Cancellation while waiting for a write lock leaves another
caller's active write alone.

Direct sends bypass managed reconciliation. Use managed publishing for cached
objects rather than mixing direct sends with tracked state.

## Wire format and interoperability

The protocol negotiates `/waggle/1.0`. Each frame contains an unsigned varint
length followed by a protobuf message. The subscriber opens a stream and sends
one `TopicSubscription` with the topic in required bytes field 1. The remote
then sends `ObjectPieces` messages back on that stream:

| Field | Contents | Required? |
| --- | --- | --- |
| 2 | Object ID bytes | Yes |
| 3 | Piece metadata bytes | No |
| 4 | Piece payload bytes | No |

Absent optional fields differ from present, empty byte strings. Topic and object
IDs are opaque bytes and may be empty. Unknown protobuf fields are ignored;
missing required fields and malformed messages are rejected.

The subscriber sends no more bytes after the handshake. Closing or cancelling
its subscription ends it; reopening requires a new stream and handshake. Two
peers wanting mutual delivery each open their own subscription stream.

Framing and stream direction remain provisional in the draft. This
implementation follows the pinned Rust implementation described in the
[interop guide](../interop/waggle/README.md), which also explains how to run the
five cross-language scenarios.

Nim tests cover reconciliation, duplicate suppression, queue pressure, cache
bounds and expiry, topic isolation, malformed messages, connection changes,
subscription renewal, and cleanup. A TCP/Noise/Mplex exchange test covers the
Switch constructor path. Rust interop covers wire exchange, managed
reconciliation, three-peer convergence, subscription renewal, reconnect, and
queue-full recovery through switches configured with TCP, Noise, and Yamux.
