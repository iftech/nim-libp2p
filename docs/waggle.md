# Experimental Waggle dissemination

Waggle exchanges opaque object pieces over topic-specific streams. Applications
choose object IDs, interpret metadata, and validate received pieces. The protocol
is optional and experimental, following [specs#732](https://github.com/libp2p/specs/pull/732)
at revision `9328b68` and the pinned Rust wire format.

## Direct streams

Mount `Waggle.new()` on a switch to accept `/waggle/1.0` subscriptions. To receive,
open a stream with `await switch.dial(peerId, WaggleCodec)` and pass it to
`subscribe(stream, topic, handler)`. The returned future lasts for the subscription's
lifetime; cancel and await it to unsubscribe and complete stream cleanup.
`send(peer, topic, message)` sends to a peer subscribed to that topic; it returns
`ok(false)` if no writable subscription exists.

Messages carry opaque bytes for the object ID and optional metadata and pieces.
Absent fields differ from present empty fields. The subscriber sends one topic
handshake; object messages travel back from the remote publisher on that stream.
Two peers wanting mutual delivery each open a subscription stream.

## Stream safety

- Message size, topic size, total streams, and streams per peer are bounded.
- Pending handshakes count against stream limits.
- Sends are serialized per stream.
- Failed or cancelled active writes reset the stream.
- Cancelling a send while it waits for the write lock leaves the active writer intact.
- Stopping Waggle closes its owned streams.

## Connection events

Call `addConnection(muxer)` for each running muxer to receive `Subscribed`,
`Unsubscribed`, and `InvalidData` through `onEvent`. Events identify a registered
connection with a nonzero `ConnectionId` and carry the topic as `topicId`
(`TopicId`, an alias for opaque bytes). Direct streams without registration
use their message handler and returned Results; malformed subscriptions are
also logged at trace level.

Register new muxers as they connect. After stopping and restarting Waggle,
re-register live muxers. `maxStreams` caps both streams and registered
connections separately.

## Object model contract

`WaggleShard.metadata` and `WaggleMetadata.clone` must return independent,
non-nil snapshots, even when no pieces are available. `PieceSend.peerMetadata`
must be non-nil and describe the peer's state after sending.

Leave `WaggleAction.send` unset when there is no payload to send. A present empty
`pieces` payload remains present on the wire; its meaning belongs to the
application.
