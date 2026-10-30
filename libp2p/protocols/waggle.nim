# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Experimental Waggle topic streams. Applications own object semantics and routing.

{.push raises: [], gcsafe.}

import std/sequtils
import chronos, chronicles
import ./protocol, ./waggle/messages
import ../stream/connection
import ../peerid
import ../results as lpresults

export lpresults

export protocol, messages, connection, chronicles

logScope:
  topics = "libp2p waggle"

const
  WaggleCodec* = "/waggle/1.0"
  WaggleInvalidDataCause* = "Invalid Waggle data"

type
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

proc admit(p: Waggle, stream: Stream, receiving: bool): LPResult[TopicStream] =
  if p.stopping:
    return err("Waggle has stopped")
  if p.streams.len >= p.maxStreams or
      p.streams.countIt(it.stream.peerId == stream.peerId) >= p.maxStreamsPerPeer:
    return err("Waggle stream limit reached")
  let session = TopicStream(stream: stream, receiving: receiving, lock: newAsyncLock())
  p.streams.add(session)
  return ok(session)

proc setTopic(p: Waggle, session: TopicStream, topic: seq[byte]): LPResult[void] =
  if topic.len > p.maxTopicSize:
    return err("Waggle topic exceeds maximum length")
  for other in p.streams:
    if other != session and other.ready and other.receiving == session.receiving and
        other.stream.peerId == session.stream.peerId and other.topic == topic:
      return err("Duplicate Waggle topic stream")
  session.topic = topic
  session.ready = true
  return ok()

proc forget(p: Waggle, session: TopicStream) =
  p.streams.keepItIf(it != session)

proc invalidSubscription(p: Waggle, stream: Stream, reason: string) =
  trace "Invalid Waggle subscription", peer = stream.peerId, err = reason

proc new*(
    T: typedesc[Waggle],
    maxMessageSize: int = 65536,
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
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    var session: TopicStream
    try:
      session = p.admit(stream, receiving = false).valueOr:
        p.invalidSubscription(stream, $error)
        return
      let subscription = TopicSubscription.decode(await stream.readLp(p.maxMessageSize))
      if subscription.isErr:
        p.invalidSubscription(stream, subscription.error)
        return
      p.setTopic(session, subscription.get().topicId).isOkOr:
        p.invalidSubscription(stream, $error)
        return
      # The subscriber only writes its handshake; further bytes are a violation.
      var unexpected: byte
      try:
        await stream.readExactly(addr unexpected, 1)
      except LPStreamRemoteClosedError:
        # A subscriber may close its write side after the handshake.
        await stream.join()
        return
      trace "Unexpected data on Waggle subscription stream", peer = stream.peerId
    except LPStreamError as exc:
      trace "Waggle subscription stream ended", peer = stream.peerId, err = exc.msg
    finally:
      if session != nil:
        p.forget(session)
      await noCancel stream.reset()

  p.codec = WaggleCodec
  p.handler = handle
  p

proc subscribe*(
    p: Waggle, stream: Stream, topic: seq[byte], handler: PiecesHandler
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  ## Takes ownership of a stream opened for WaggleCodec, sends the subscription,
  ## and receives until EOF, cancellation, or a returned error. The stream is reset
  ## on every exit.
  doAssert handler != nil
  var session: TopicStream
  try:
    session = ?p.admit(stream, receiving = true)
    ?p.setTopic(session, topic)
    let subscription = TopicSubscription(topicId: topic).encode()
    if subscription.len > p.maxMessageSize:
      return err("Waggle subscription exceeds maximum length")
    await stream.writeLp(subscription)
    while true:
      let decoded = ObjectPieces.decode(await stream.readLp(p.maxMessageSize))
      if decoded.isErr:
        return err(decoded.error, WaggleInvalidDataCause)
      await handler(stream.peerId, topic, decoded.get())
  except LPStreamResetError, LPStreamClosedError, LPStreamConnDownError:
    return err(getCurrentExceptionMsg())
  except LPStreamEOFError as exc:
    trace "Waggle receive stream ended", peer = stream.peerId, err = exc.msg
  except InvalidVarintError, MaxSizeError:
    return err(getCurrentExceptionMsg(), WaggleInvalidDataCause)
  except LPStreamError as exc:
    return err(exc)
  finally:
    if session != nil:
      p.forget(session)
    await noCancel stream.reset()
  return ok()

proc subscribers*(p: Waggle, topic: seq[byte]): seq[PeerId] =
  ## Peers with an active inbound subscription for this topic.
  var peers: seq[PeerId]
  for session in p.streams:
    if session.ready and not session.receiving and not session.stream.closed and
        session.topic == topic:
      peers.add(session.stream.peerId)
  return peers

proc send*(
    p: Waggle, peer: PeerId, topic: seq[byte], msg: ObjectPieces
): Future[LPResult[bool]] {.async: (raises: [CancelledError]).} =
  ## Concurrent sends are serialized by a per-stream lock. A cancelled or failed
  ## write resets the stream because its frame may be incomplete.
  ## Returns ok(true) after writing, or ok(false) if no writable subscription exists.
  ## Validation and stream failures return errors; cancellation propagates.
  if msg.encodedSize() > p.maxMessageSize:
    return err("Waggle message exceeds maximum length")
  var selected = Opt.none(TopicStream)
  for session in p.streams:
    if session.ready and not session.receiving and session.stream.peerId == peer and
        session.topic == topic:
      selected = Opt.some(session)
      break
  let target = selected.valueOr:
    return ok(false)
  await target.lock.acquire()
  try:
    if target.stream.closed:
      return ok(false)
    try:
      await target.stream.writeLp(msg.encode())
    except CancelledError as exc:
      await noCancel target.stream.reset()
      raise exc
    except LPStreamError as exc:
      await noCancel target.stream.reset()
      return err(exc)
    return ok(true)
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
  await noCancel allFutures(streams.mapIt(it.stream.reset()))
  await procCall LPProtocol(p).stop()
