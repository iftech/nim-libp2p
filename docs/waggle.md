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

Events require a registered connection. Passing a switch to `Waggle.new`
registers connections automatically when the protocol starts. Mount it before
starting the switch. Managed topics subscribed before start are opened at start.
Repeating `subscribe(topic)` reopens finished receivers; failures are not retried
automatically. `subscribers(topic)` lists each peer once even when it has multiple
connections.

`subscribe(topic)` returns a `SubscriptionAttempt`. Its `added` field says whether
this call registered a new local topic. `blockedConnections` lists the connection
IDs denied by local stream limits. The topic remains registered, and other current
and future connections are still attempted. Validation failures return an error
without changing registration.

A failure handler can retry and check whether its event's `connectionId` remains
in `blockedConnections`. A connection absent from that list may still be opening;
negotiation and later stream failures arrive through events. Explicit admission
failures only appear in the report; automatic admission failures on new connections
or background reopening emit `StreamFailed`. This avoids recursive failure events
when a handler retries against an unchanged limit.

Events identify the peer, a nonzero `ConnectionId`, and the topic as `topicId`
(`TopicId`, an alias for opaque bytes). Direct streams without registration use their message handler and
returned Results.


`maxStreams` caps streams and registered connections separately.
## Object model contract

`WaggleShard.metadata` and `WaggleMetadata.clone` must return independent,
non-nil snapshots, even when no pieces are available. `PieceSend.peerMetadata`
must be non-nil and describe the peer's state after sending.

Leave `WaggleAction.send` unset when there is no payload to send. A present empty
`pieces` payload remains present on the wire; its meaning belongs to the
application.
