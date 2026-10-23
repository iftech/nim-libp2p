# Experimental Waggle topic streams

`libp2p/protocols/waggle` implements the wire messages and topic stream
lifecycle from [specs#732](https://github.com/libp2p/specs/pull/732), pinned to
revision `9328b68`. This is an experimental foundation for application-driven
piece dissemination, not a complete dissemination algorithm or a stable API.

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
removes it; reopening requires a new stream and handshake. Multiple connections
to a peer share one subscription per topic and direction in this implementation.
The [Nim/Rust interop harness](../interop/waggle/README.md) verifies this
contract against a pinned Rust implementation.

## Usage

Mount a `Waggle` instance on each switch before starting it:

```nim
import chronos
import libp2p/[switch, protocols/waggle]

proc receive(peer: PeerId, topic: seq[byte], msg: ObjectPieces) {.
    async: (raises: [CancelledError])
.} =
  # Validate pieces and interpret metadata before choosing what to forward.
  discard

proc exchange(a, b: Switch, sender, receiver: Waggle) {.async.} =
  # a.mount(sender) and b.mount(receiver) must happen before starting the switches.
  await b.connect(a.peerInfo.peerId, a.peerInfo.addrs)
  let topic = @[byte 1]
  let stream = await b.dial(a.peerInfo.peerId, WaggleCodec)
  let receiving = receiver.subscribe(stream, topic, receive)
  try:
    # A real application schedules sends when its peer subscription is available.
    while b.peerInfo.peerId notin sender.subscribers(topic):
      await sleepAsync(10.milliseconds)
    discard await sender.send(
      b.peerInfo.peerId, topic,
      ObjectPieces(objectId: @[byte 42], pieces: Opt.some(@[byte 99])),
    )
  finally:
    await receiving.cancelAndWait()
```

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

Defaults bound protobuf payloads to 1 MiB, topic IDs to 1024 bytes, active streams
to 128, and streams per peer to 16. The stream counts include both directions
and incomplete incoming handshakes. The `Waggle.new` arguments override these
local resource limits. Stream failures do not trigger automatic retries.
`stop` resets owned streams; callers must also finish their subscription tasks,
including cancelling any application handlers that are still running. Call
`start` before opening fresh subscriptions after a stop.

## Application responsibilities and open decisions

The application owns validation, metadata encoding and merging, object storage
and eviction, peer scoring, and recipient selection. It can send metadata-only
messages and use received metadata to choose missing pieces and recipients.
There is no automatic cache, duplicate suppression, forwarding, periodic gossip,
peer discovery, or subscription propagation to newly connected peers.

Before adding an automatic dissemination algorithm, agree on metadata meaning,
advertisement response rules, retry scheduling, and eviction recovery. A
three-peer synchronization test with a peer initially unaware of the object
should demonstrate those rules. The present tests cover protobuf wire vectors,
negotiated TCP delivery, topic isolation, concurrent sends, subscription limits,
malformed input, cancellation, and stream cleanup.
