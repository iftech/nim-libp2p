# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import tables, sequtils, oids
import chronos, chronicles, metrics
import
  ../muxer,
  ../../stream/connection,
  ../../stream/bufferstream,
  ../../utils/shortlog,
  ../../peerinfo,
  ./coder,
  ./lpchannel

export muxer

logScope:
  topics = "libp2p mplex"

const
  MplexCodec* = "/mplex/6.7.0"
  MaxChannelCount = 200
  MaxBufferedBytes* = 4 * MaxMsgSize
    ## Maximum unread data across four fully decoded frames.

when defined(libp2p_expensive_metrics):
  declareGauge(libp2p_mplex_channels, "mplex channels", labels = ["initiator", "peer"])

type
  InvalidChannelIdError* = object of MuxerError

  Mplex* = ref object of Muxer
    channels: array[bool, Table[uint64, LPChannel]]
    currentId: uint64
    inChannTimeout: Duration
    outChannTimeout: Duration
    isClosed: bool
    oid*: Oid
    maxChannCount: int
    maxBufferedBytes: int

func shortLog*(m: Mplex): auto =
  shortLog(m.connection)

chronicles.formatIt(Mplex):
  shortLog(it)

proc newTooManyChannels(): ref TooManyChannels =
  newException(TooManyChannels, "max allowed channel count exceeded")

proc newInvalidChannelIdError(): ref InvalidChannelIdError =
  newException(InvalidChannelIdError, "max allowed channel count exceeded")

proc bufferedBytes(m: Mplex): int =
  var total = 0
  for initiator in [false, true]:
    for channel in m.channels[initiator].values:
      if channel.protocol.len == 0:
        total += channel.len
  total

proc drainChannelTasks(channs: seq[LPChannel]) {.async: (raises: []).} =
  ## Awaits the per-channel tasks so they don't outlive the muxer; callers must
  ## have torn channels and connection down first.
  var futs: seq[Future[void]]
  for chann in channs:
    futs.add(chann.cleanupFut)
    if not chann.handlerFut.isNil():
      futs.add(chann.handlerFut)
    if not chann.resetMessageFut.isNil():
      futs.add(chann.resetMessageFut)
  await noCancel allFutures(futs)

proc cleanupChann(m: Mplex, chann: LPChannel) {.async: (raises: []).} =
  ## remove the local channel from the internal tables
  ##
  try:
    await chann.join()
    if not chann.resetMessageFut.isNil():
      await noCancel chann.resetMessageFut.join()
    m.channels[chann.initiator].del(chann.id)
    trace "Cleaned up channel", muxer = m, chann

    when defined(libp2p_expensive_metrics):
      libp2p_mplex_channels.set(
        m.channels[chann.initiator].len.int64,
        labelValues = [$chann.initiator, $m.connection.peerId],
      )
  except CancelledError as exc:
    trace "Mplex channel cleanup canceled", err = exc.msg, muxer = m, channel = chann

proc newStreamInternal*(
    m: Mplex,
    initiator: bool = true,
    chanId: uint64 = 0,
    name: string = "",
    timeout: Duration,
): LPChannel {.gcsafe, raises: [InvalidChannelIdError].} =
  ## create new channel/stream
  ##
  let id =
    if initiator:
      m.currentId.inc()
      m.currentId
    else:
      chanId

  if id in m.channels[initiator]:
    raise newInvalidChannelIdError()

  let channel = LPChannel.init(id, m.connection, initiator, name, timeout = timeout)

  channel.peerId = m.connection.peerId
  channel.observedAddr = m.connection.observedAddr
  channel.localAddr = m.connection.localAddr
  channel.transportDir = m.connection.transportDir
  when defined(libp2p_agents_metrics):
    channel.shortAgent = m.connection.shortAgent

  trace "Creating new channel", muxer = m, channel = channel, id, initiator, name

  m.channels[initiator][id] = channel

  # All the errors are handled inside `cleanupChann()` procedure.
  channel.cleanupFut = m.cleanupChann(channel)

  when defined(libp2p_expensive_metrics):
    libp2p_mplex_channels.set(
      m.channels[initiator].len.int64, labelValues = [$initiator, $m.connection.peerId]
    )

  channel

proc handleStream(m: Mplex, chann: LPChannel) {.async: (raises: []).} =
  ## call the muxer stream handler for this channel
  ##
  await m.streamHandler(chann)
  trace "Mplex stream handler completed", muxer = m, channel = chann
  doAssert(chann.closed, "connection not closed by handler!")

method handle*(m: Mplex) {.async: (raises: []).} =
  trace "Mplex handler started", muxer = m
  try:
    while not m.connection.atEof:
      trace "Waiting for data", muxer = m
      let
        (id, msgType, data) = await m.connection.readMsg()
        initiator = bool(ord(msgType) and 1)

      logScope:
        id = id
        initiator = initiator
        msgType = msgType
        size = data.len

      trace "Read message from connection", muxer = m, messageSize = data.len

      var channel =
        if MessageType(msgType) != MessageType.New:
          let tmp = m.channels[initiator].getOrDefault(id, nil)
          if tmp == nil:
            trace "Channel not found, skipping", muxer = m
            continue

          tmp
        else:
          if m.channels[false].len > m.maxChannCount - 1:
            trace "Too many channels created by remote peer",
              allowedMax = m.maxChannCount, muxer = m
            raise newTooManyChannels()

          # Stream names are only for debugging and retaining them lets peers
          # multiply the frame-size limit by the channel limit.
          m.newStreamInternal(false, id, timeout = m.outChannTimeout)

      trace "Processing channel message", muxer = m, channel, messageSize = data.len

      case msgType
      of MessageType.New:
        trace "Created channel", muxer = m, channel

        if m.streamHandler != nil:
          # Launch handler task
          # All the errors are handled inside `handleStream()` procedure.
          channel.handlerFut = m.handleStream(channel)
      of MessageType.MsgIn, MessageType.MsgOut:
        if channel.protocol.len == 0:
          let bufferedBytes = m.bufferedBytes()
          if data.len > m.maxBufferedBytes or
              bufferedBytes > m.maxBufferedBytes - data.len:
            debug "mplex pre-negotiation buffer limit reached",
              allowedMax = m.maxBufferedBytes,
              buffered = bufferedBytes,
              incoming = data.len,
              channel
            await channel.reset()
            continue

        trace "Pushing data to channel", muxer = m, channel, len = data.len
        try:
          await channel.pushData(data)
          trace "Pushed data to channel", muxer = m, channel, len = data.len
        except LPStreamClosedError as exc:
          # Channel is being closed, but `cleanupChann` was not yet triggered.
          trace "Channel data delivery failed",
            err = exc.msg, muxer = m, channel, messageSize = data.len
          discard # Ignore message, same as if `cleanupChann` had completed.
      of MessageType.CloseIn, MessageType.CloseOut:
        await channel.pushEof()
      of MessageType.ResetIn, MessageType.ResetOut:
        await channel.resetChannel(isLocal = false)
  except CancelledError:
    trace "Mplex handler canceled", muxer = m
  except LPStreamEOFError as exc:
    trace "Stream EOF", err = exc.msg, muxer = m
  except LPStreamError as exc:
    trace "Unexpected stream exception in mplex read loop", err = exc.msg, muxer = m
  except MuxerError as exc:
    debug "Unexpected muxer exception in mplex read loop", err = exc.msg, muxer = m
  finally:
    await m.close()
  trace "Mplex handler stopped", muxer = m

proc new*(
    M: type Mplex,
    conn: RawConn,
    inTimeout: Duration = DefaultChanTimeout,
    outTimeout: Duration = DefaultChanTimeout,
    maxChannCount: int = MaxChannelCount,
    maxBufferedBytes: int = MaxBufferedBytes,
): Mplex =
  M(
    connection: conn,
    inChannTimeout: inTimeout,
    outChannTimeout: outTimeout,
    oid: genOid(),
    maxChannCount: maxChannCount,
    maxBufferedBytes: maxBufferedBytes,
  )

method newStream*(
    m: Mplex, name: string = "", lazy: bool = false
): Future[MuxedStream] {.async: (raises: [CancelledError, LPStreamError, MuxerError]).} =
  let channel = m.newStreamInternal(timeout = m.inChannTimeout)

  if not lazy:
    await channel.open()

  return Connection(channel)

method close*(m: Mplex) {.async: (raises: []).} =
  if m.isClosed:
    trace "Already closed", muxer = m
    return
  m.isClosed = true

  trace "Closing mplex", muxer = m

  var channs = toSeq(m.channels[false].values) & toSeq(m.channels[true].values)

  for chann in channs:
    await chann.close()

  await m.connection.close()

  # TODO while we're resetting, new channels may be created that will not be
  #      closed properly

  channs = toSeq(m.channels[false].values) & toSeq(m.channels[true].values)

  for chann in channs:
    await chann.reset()

  await drainChannelTasks(channs)

  m.channels[false].clear()
  m.channels[true].clear()

  trace "Closed mplex", muxer = m

method getStreams*(m: Mplex): seq[MuxedStream] {.gcsafe.} =
  var streams: seq[MuxedStream]
  for c in m.channels[false].values:
    streams.add(c)
  for c in m.channels[true].values:
    streams.add(c)
  streams
