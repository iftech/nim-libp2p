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
