# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Status Research & Development GmbH

## Experimental Waggle topic streams. Applications own object semantics and routing.

{.push raises: [].}

import std/sequtils
import chronos, chronicles
import ./protocol, ./waggle/messages
import ../stream/connection
import ../peerid

export protocol, messages, connection

logScope:
  topics = "libp2p waggle"

const WaggleCodec* = "/waggle/1.0"

type
  WaggleError* = object of LPError

  PiecesHandler* = proc(peer: PeerId, topic: seq[byte], msg: ObjectPieces) {.
    async: (raises: [CancelledError]), gcsafe
  .}

  TopicStream = ref object
    stream: Stream
    topic: seq[byte]
    receiving: bool
    ready: bool
    lock: AsyncLock

  Waggle* = ref object of LPProtocol
    streams: seq[TopicStream]
    maxMessageSize: int
    maxTopicSize: int
    maxStreams: int
    maxStreamsPerPeer: int
    stopping: bool

proc admit(
    p: Waggle, stream: Stream, receiving: bool
): TopicStream {.raises: [WaggleError].} =
  if p.stopping:
    raise newException(WaggleError, "Waggle has stopped")
  if p.streams.len >= p.maxStreams or
      p.streams.countIt(it.stream.peerId == stream.peerId) >= p.maxStreamsPerPeer:
    raise newException(WaggleError, "Waggle stream limit reached")
  result = TopicStream(stream: stream, receiving: receiving, lock: newAsyncLock())
  p.streams.add(result)

proc setTopic(
    p: Waggle, session: TopicStream, topic: seq[byte]
) {.raises: [WaggleError].} =
  if topic.len > p.maxTopicSize:
    raise newException(WaggleError, "Waggle topic exceeds maximum length")
  for other in p.streams:
    if other != session and other.ready and other.receiving == session.receiving and
        other.stream.peerId == session.stream.peerId and other.topic == topic:
      raise newException(WaggleError, "Duplicate Waggle topic stream")
  session.topic = topic
  session.ready = true

proc forget(p: Waggle, session: TopicStream) =
  p.streams.keepItIf(it != session)

method init*(p: Waggle) =
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    var session: TopicStream
    try:
      session = p.admit(stream, receiving = false)
      let subscription = TopicSubscription.decode(await stream.readLp(p.maxMessageSize))
      if subscription.isErr:
        raise newException(WaggleError, subscription.error)
      p.setTopic(session, subscription.get().topicId)
      # The subscriber only writes its handshake; further bytes are a violation.
      var unexpected: byte
      await stream.readExactly(addr unexpected, 1)
      trace "Unexpected data on Waggle subscription stream", peer = stream.peerId
    except LPStreamError as exc:
      trace "Waggle subscription stream ended", peer = stream.peerId, err = exc.msg
    except WaggleError as exc:
      trace "Invalid Waggle subscription", peer = stream.peerId, err = exc.msg
    finally:
      if session != nil:
        p.forget(session)
      await stream.reset()

  p.codec = WaggleCodec
  p.handler = handle

proc new*(
    T: typedesc[Waggle],
    maxMessageSize: int = 1024 * 1024,
    maxTopicSize: int = 1024,
    maxStreams: int = 128,
    maxStreamsPerPeer: int = 16,
): T =
  doAssert maxMessageSize > 0 and maxTopicSize >= 0
  doAssert maxStreams > 0 and maxStreamsPerPeer > 0
  let p = T(
    maxMessageSize: maxMessageSize,
    maxTopicSize: maxTopicSize,
    maxStreams: maxStreams,
    maxStreamsPerPeer: maxStreamsPerPeer,
  )
  p.init()
  p.setStreamLimits(
    maxIncomingStreamsTotal = maxStreams,
    maxIncomingStreamsPerPeer = maxStreamsPerPeer,
    maxOutgoingStreamsTotal = maxStreams,
    maxOutgoingStreamsPerPeer = maxStreamsPerPeer,
  )
  p

proc subscribe*(
    p: Waggle, stream: Stream, topic: seq[byte], handler: PiecesHandler
) {.async: (raises: [CancelledError, LPStreamError, WaggleError]).} =
  ## Takes ownership of a negotiated stream, sends the subscription, and receives
  ## until EOF or cancellation. The stream is reset on every exit, including errors.
  doAssert handler != nil
  var session: TopicStream
  try:
    session = p.admit(stream, receiving = true)
    p.setTopic(session, topic)
    let subscription = TopicSubscription(topicId: topic).encode()
    if subscription.len > p.maxMessageSize:
      raise newException(WaggleError, "Waggle subscription exceeds maximum length")
    await stream.writeLp(subscription)
    while true:
      let decoded = ObjectPieces.decode(await stream.readLp(p.maxMessageSize))
      if decoded.isErr:
        raise newException(WaggleError, decoded.error)
      await handler(stream.peerId, topic, decoded.get())
  except LPStreamEOFError:
    discard
  finally:
    if session != nil:
      p.forget(session)
    await stream.reset()

proc subscribers*(p: Waggle, topic: seq[byte]): seq[PeerId] =
  ## Peers with an active inbound subscription for this topic.
  for session in p.streams:
    if session.ready and not session.receiving and not session.stream.closed and
        session.topic == topic:
      result.add(session.stream.peerId)

proc send*(
    p: Waggle, peer: PeerId, topic: seq[byte], msg: ObjectPieces
): Future[bool] {.async: (raises: [CancelledError, LPStreamError, WaggleError]).} =
  ## Sends to a subscribed peer, returning false if no subscription exists.
  ## Concurrent sends apply backpressure through a per-stream lock. A cancelled
  ## or failed write resets the stream because its frame may be incomplete.
  if msg.encodedSize() > p.maxMessageSize:
    raise newException(WaggleError, "Waggle message exceeds maximum length")
  var target: TopicStream
  for session in p.streams:
    if session.ready and not session.receiving and session.stream.peerId == peer and
        session.topic == topic:
      target = session
      break
  if target == nil:
    return false
  await target.lock.acquire()
  try:
    if target.stream.closed:
      return false
    try:
      await target.stream.writeLp(msg.encode())
    except CancelledError as exc:
      await target.stream.reset()
      raise exc
    except LPStreamError as exc:
      await target.stream.reset()
      raise exc
    return true
  finally:
    try:
      target.lock.release()
    except AsyncLockError as exc:
      raiseAssert exc.msg

method start*(p: Waggle) {.async: (raises: [CancelledError]).} =
  p.stopping = false
  await procCall LPProtocol(p).start()

method stop*(p: Waggle) {.async: (raises: []).} =
  p.stopping = true
  let streams = p.streams
  p.streams = @[]
  for session in streams:
    await session.stream.reset()
  await procCall LPProtocol(p).stop()
