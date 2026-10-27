# Experimental Waggle dissemination

Waggle exchanges opaque object pieces over topic-specific streams. Applications
choose object IDs, interpret metadata, and validate received pieces. The protocol
is optional and experimental, following [specs#732](https://github.com/libp2p/specs/pull/732)
at revision `9328b68` and the pinned Rust wire format.

## Direct streams

Mount `Waggle.new()` on a switch to accept `/waggle/1.0` subscriptions. To receive,
open a negotiated stream and call `subscribe(stream, topic, handler)`. Keep its
future and cancel and await it when finished. `send(peer, topic, message)` sends
to a peer subscribed to that topic; it returns a Result containing false when no subscription exists.

Messages carry opaque bytes for the object ID and optional metadata and pieces.
Absent fields differ from present empty fields. The subscriber sends one topic
handshake; object messages travel back from the remote publisher on that stream.
Two peers wanting mutual delivery each open a subscription stream.
