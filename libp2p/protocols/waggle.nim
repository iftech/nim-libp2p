# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Experimental Waggle dissemination with application-defined object semantics.

{.push raises: [], gcsafe.}

import std/[sequtils, sets]
import chronos, chronicles
import ./protocol, ./waggle/messages
import ../muxers/muxer
import ../stream/connection
import ../peerid
from ../utils/future import trackFut
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

  WaggleEventKind* {.pure.} = enum
    Subscribed
    Unsubscribed
    InvalidData

  WaggleEvent* = object
    kind*: WaggleEventKind
    peerId*: PeerId
    connectionId*: uint64
    topic*: seq[byte]
    message*: ObjectPieces
    reason*: string

  WaggleEventHandler* = proc(event: WaggleEvent) {.gcsafe, raises: [].}

  WaggleConnection = ref object
    id: uint64
    muxer: Muxer

  TopicStream = ref object
    stream: Stream
    topic: seq[byte]
    receiving: bool
    ready: bool
    lock: AsyncLock
    link: WaggleConnection

  Waggle* = ref object of LPProtocol
    streams: seq[TopicStream]
    maxMessageSize: int
    maxTopicSize: int
    maxStreams: int
    maxStreamsPerPeer: int
    stopping: bool
    links: seq[WaggleConnection]
    nextConnectionId: uint64
    topicWhitelist: Opt[HashSet[seq[byte]]]
    onEvent: WaggleEventHandler
    tasks: seq[Future[void]]

proc notify(
    p: Waggle,
    kind: WaggleEventKind,
    link: WaggleConnection,
    topic: seq[byte],
    msg = ObjectPieces(),
    reason = "",
) =
  if p.onEvent != nil and link != nil:
    p.onEvent(
      WaggleEvent(
        kind: kind,
        peerId: link.muxer.connection.peerId,
        connectionId: link.id,
        topic: topic,
        message: msg,
        reason: reason,
      )
    )

proc findConnection(p: Waggle, stream: Stream): WaggleConnection =
  if p.links.len == 0:
    return nil
  var current = stream
  while current != nil:
    for link in p.links:
      if current == link.muxer.connection:
        return link
    let wrapped = current.getWrapped()
    if wrapped == current:
      break
    current = wrapped

proc writeSession(
  p: Waggle, target: TopicStream, msg: ObjectPieces
): Future[LPResult[bool]] {.async: (raises: [CancelledError]).}

proc admit(p: Waggle, stream: Stream, receiving: bool): LPResult[TopicStream] =
  if p.stopping:
    return err("Waggle has stopped")
  if p.streams.len >= p.maxStreams or
      p.streams.countIt(it.stream.peerId == stream.peerId) >= p.maxStreamsPerPeer:
    return err("Waggle stream limit reached")
  let session = TopicStream(
    stream: stream,
    receiving: receiving,
    lock: newAsyncLock(),
    link: p.findConnection(stream),
  )
  p.streams.add(session)
  return ok(session)

proc setTopic(p: Waggle, session: TopicStream, topic: seq[byte]): LPResult[void] =
  if session.link == nil:
    session.link = p.findConnection(session.stream)
  if topic.len > p.maxTopicSize:
    return err("Waggle topic exceeds maximum length")
  for other in p.streams:
    if other != session and other.ready and other.receiving == session.receiving and
        other.stream.peerId == session.stream.peerId and
        (other.link == session.link or other.link == nil or session.link == nil) and
        other.topic == topic:
      return err("Duplicate Waggle topic stream")
  session.topic = topic
  session.ready = true
  return ok()

proc forget(p: Waggle, session: TopicStream) =
  p.streams.keepItIf(it != session)

proc invalidSubscription(
    p: Waggle, stream: Stream, session: TopicStream, reason: string
) =
  let link =
    if session == nil:
      p.findConnection(stream)
    else:
      session.link
  let topic =
    if session == nil:
      @[]
    else:
      session.topic
  trace "Invalid Waggle subscription", peer = stream.peerId, err = reason
  p.notify(WaggleEventKind.InvalidData, link, topic, reason = reason)

proc new*(
    T: typedesc[Waggle],
    maxMessageSize: int = 65536,
    maxTopicSize: int = 1024,
    maxStreams: int = 128,
    maxStreamsPerPeer: int = 16,
    topicWhitelist = Opt.none(HashSet[seq[byte]]),
    onEvent: WaggleEventHandler = nil,
): T =
  doAssert maxMessageSize > 0 and maxTopicSize >= 0
  doAssert maxStreams > 0 and maxStreamsPerPeer > 0
  let p = T(
    topicWhitelist: topicWhitelist,
    onEvent: onEvent,
    maxMessageSize: maxMessageSize,
    maxTopicSize: maxTopicSize,
    maxStreams: maxStreams,
    maxStreamsPerPeer: maxStreamsPerPeer,
  )
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    var session: TopicStream
    try:
      session = p.admit(stream, receiving = false).valueOr:
        p.invalidSubscription(stream, session, $error)
        return
      let subscription = TopicSubscription.decode(await stream.readLp(p.maxMessageSize))
      if subscription.isErr:
        p.invalidSubscription(stream, session, subscription.error)
        return
      let topic = subscription.get().topicId
      if p.topicWhitelist.isSome and topic notin p.topicWhitelist.get():
        p.invalidSubscription(stream, session, "Topic is not allowed")
        return
      p.setTopic(session, topic).isOkOr:
        p.invalidSubscription(stream, session, $error)
        return
      if session.link != nil:
        p.notify(WaggleEventKind.Subscribed, session.link, topic)
      # The subscriber only writes its handshake; further bytes are a violation.
      var unexpected: byte
      try:
        await stream.readExactly(addr unexpected, 1)
      except LPStreamRemoteClosedError:
        # A subscriber may close its write side after the handshake.
        await stream.join()
        return
      p.invalidSubscription(
        stream, session, "Unexpected data after subscription handshake"
      )
    except LPStreamError as exc:
      if session != nil and not session.ready:
        p.invalidSubscription(stream, session, exc.msg)
      else:
        trace "Waggle subscription stream ended", peer = stream.peerId, err = exc.msg
    finally:
      if session != nil:
        p.forget(session)
        if session.link != nil and session.ready:
          p.notify(WaggleEventKind.Unsubscribed, session.link, session.topic)
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
  for session in p.streams:
    if session.ready and not session.receiving and session.stream.peerId == peer and
        session.topic == topic:
      return await p.writeSession(session, msg)
  return ok(false)

proc writeSession(
    p: Waggle, target: TopicStream, msg: ObjectPieces
): Future[LPResult[bool]] {.async: (raises: [CancelledError]).} =
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

proc removeConnection(p: Waggle, link: WaggleConnection) {.async: (raises: []).} =
  p.links.keepItIf(it != link)
  let sessions = p.streams.filterIt(it.link == link)
  for session in sessions:
    await noCancel session.stream.reset()

proc addConnection*(p: Waggle, muxer: Muxer): Result[bool, string] =
  ## Register an upgraded muxer whose stream handler routes incoming protocols.
  ## Register each new muxer and re-register live muxers after a stop/start cycle.
  if p.stopping or muxer == nil or muxer.handler == nil or muxer.connection.closed:
    return err("Waggle requires a live running muxer")
  for link in p.links:
    if link.muxer == muxer:
      return ok(false)
  if p.links.len >= p.maxStreams:
    return err("Waggle connection limit reached")
  inc p.nextConnectionId
  let link = WaggleConnection(id: p.nextConnectionId, muxer: muxer)
  p.links.add(link)
  proc monitor() {.async: (raises: [CancelledError]).} =
    await muxer.handler.join()
    await p.removeConnection(link)

  p.tasks.trackFut(monitor())
  ok(true)

method start*(p: Waggle) {.async: (raises: [CancelledError]).} =
  p.stopping = false
  await procCall LPProtocol(p).start()

method stop*(p: Waggle) {.async: (raises: []).} =
  p.stopping = true
  let links = p.links
  for link in links:
    await p.removeConnection(link)
  let streams = p.streams
  p.streams = @[]
  await noCancel allFutures(streams.mapIt(it.stream.reset()))
  let tasks = p.tasks
  p.tasks = @[]
  for task in tasks:
    await task.cancelAndWait()
  await procCall LPProtocol(p).stop()
