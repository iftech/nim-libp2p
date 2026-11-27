# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import sequtils, std/[tables]
import chronos, chronicles, metrics, stew/[endians2, byteutils, objects]
import ../muxer, ../../stream/connection
import ../../utils/[shortlog, zeroqueue]

export muxer

logScope:
  topics = "libp2p yamux"

const
  YamuxCodec* = "/yamux/1.0.0"
  YamuxVersion = 0.uint8
  YamuxDefaultWindowSize* = 256 * 1024
  MaxSendQueueSize = YamuxDefaultWindowSize
  MaxChannelCount* = 256
  MaxSendWindow = int64(high(uint32))

when defined(libp2p_yamux_metrics):
  declareGauge libp2p_yamux_channels, "yamux channels", labels = ["initiator", "peer"]
  declareHistogram libp2p_yamux_send_queue,
    "message send queue length (in byte)",
    buckets = [0.0, 100.0, 250.0, 1000.0, 2000.0, 3200.0, 6400.0, 25600.0, 262144.0]
  declareHistogram libp2p_yamux_recv_queue,
    "message recv queue length (in byte)",
    buckets = [0.0, 100.0, 250.0, 1000.0, 2000.0, 3200.0, 6400.0, 25600.0, 262144.0]

type
  YamuxError* = object of MuxerError

  MsgType = enum
    Data = 0x0
    WindowUpdate = 0x1
    Ping = 0x2
    GoAway = 0x3

  MsgFlags {.size: 2.} = enum
    Syn
    Ack
    Fin
    Rst

  GoAwayStatus = enum
    NormalTermination = 0x0
    ProtocolError = 0x1
    InternalError = 0x2

  YamuxHeader = object
    version: uint8
    msgType: MsgType
    flags: set[MsgFlags]
    streamId: uint32
    length: uint32

proc readHeader(
    conn: LPStream
): Future[YamuxHeader] {.async: (raises: [CancelledError, LPStreamError, MuxerError]).} =
  var buffer: array[12, byte]
  await conn.readExactly(addr buffer[0], 12)

  var hdr: YamuxHeader
  hdr.version = buffer[0]
  let flags = fromBytesBE(uint16, buffer[2 .. 3])
  if hdr.version != YamuxVersion or not hdr.msgType.checkedEnumAssign(buffer[1]) or
      flags notin 0'u16 .. 15'u16:
    raise newException(YamuxError, "Wrong header")
  hdr.flags = cast[set[MsgFlags]](flags)
  hdr.streamId = fromBytesBE(uint32, buffer[4 .. 7])
  hdr.length = fromBytesBE(uint32, buffer[8 .. 11])
  hdr

proc `$`(header: YamuxHeader): string =
  "{" & $header.msgType & ", " & "{" &
    header.flags.foldl(
      if a != "":
        a & ", " & $b
      else:
        $b,
      "",
    ) & "}, " & "streamId: " & $header.streamId & ", " & "length: " & $header.length &
    "}"

proc encode(header: YamuxHeader): array[12, byte] =
  var buf: array[12, byte]
  buf[0] = header.version
  buf[1] = uint8(header.msgType)
  buf[2 .. 3] = toBytesBE(uint16(cast[uint8](header.flags)))
    # workaround https://github.com/nim-lang/Nim/issues/21789
  buf[4 .. 7] = toBytesBE(header.streamId)
  buf[8 .. 11] = toBytesBE(header.length)
  buf

proc write(
    conn: LPStream, header: YamuxHeader
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  trace "Writing directly on stream", header = $header
  var buffer = header.encode()
  conn.write(@buffer)

proc ping(T: type[YamuxHeader], flag: MsgFlags, pingData: uint32): T =
  T(version: YamuxVersion, msgType: MsgType.Ping, flags: {flag}, length: pingData)

proc goAway(T: type[YamuxHeader], status: GoAwayStatus): T =
  T(version: YamuxVersion, msgType: MsgType.GoAway, length: uint32(status))

proc data(
    T: type[YamuxHeader],
    streamId: uint32,
    length: uint32 = 0,
    flags: set[MsgFlags] = {},
): T =
  T(
    version: YamuxVersion,
    msgType: MsgType.Data,
    length: length,
    flags: flags,
    streamId: streamId,
  )

proc windowUpdate(
    T: type[YamuxHeader], streamId: uint32, delta: uint32, flags: set[MsgFlags] = {}
): T =
  T(
    version: YamuxVersion,
    msgType: MsgType.WindowUpdate,
    length: delta,
    flags: flags,
    streamId: streamId,
  )

type
  ToSend = ref object
    data: seq[byte]
    sent: int
    fut: Future[void].Raising([CancelledError, LPStreamError])

  YamuxChannel* = ref object of Connection
    id: uint32
    recvWindow: int
    sendWindow: int64
    maxRecvWindow: int
    maxSendQueueSize: int
    conn: RawConn
    isSrc: bool
    opened: bool
    isSending: bool
    sendQueue: seq[ToSend]
    recvQueue: ZeroQueue
    isReset: bool
    remoteReset: bool
    closedRemotely: AsyncEvent
    closedLocally: bool
    receivedData: AsyncEvent
    cleanupFut: Future[void]
    handlerFut: Future[void]
    sendLoopFut: Future[void]

proc `$`(channel: YamuxChannel): string =
  var str = if channel.conn.dir == Out: "=> " else: "<= "
  str &= $channel.id
  var s: seq[string] = @[]
  if channel.closedRemotely.isSet():
    s.add("ClosedRemotely")
  if channel.closedLocally:
    s.add("ClosedLocally")
  if channel.isReset:
    s.add("Reset")
  if s.len > 0:
    str &=
      " {" &
      s.foldl(
        if a != "":
          a & ", " & b
        else:
          b,
        "",
      ) & "}"
  str

proc lengthSendQueue(channel: YamuxChannel): int =
  ## Returns the length of what remains to be sent
  ##
  channel.sendQueue.foldl(a + b.data.len - b.sent, 0)

proc lengthSendQueueWithLimit(channel: YamuxChannel): int =
  ## Returns the length of what remains to be sent, but limit the size of big messages.
  ##
  # For leniency, limit big messages size to the third of maxSendQueueSize
  # This value is arbitrary, it's not in the specs, it permits to store up to
  # 3 big messages if the peer is stalling.
  channel.sendQueue.foldl(
    a + min(b.data.len - b.sent, channel.maxSendQueueSize div 3), 0
  )

proc actuallyClose(channel: YamuxChannel) {.async: (raises: []).} =
  if channel.closedLocally and channel.sendQueue.len == 0 and
      channel.closedRemotely.isSet():
    await procCall Connection(channel).closeImpl()

proc remoteClosed(channel: YamuxChannel) {.async: (raises: []).} =
  if not channel.closedRemotely.isSet():
    channel.closedRemotely.fire()
    await channel.actuallyClose()
  channel.isClosedRemotely = true

method closeImpl*(channel: YamuxChannel) {.async: (raises: []).} =
  if not channel.closedLocally:
    trace "Closing yamux channel locally", streamId = channel.id, conn = channel.conn
    channel.closedLocally = true

    if not channel.isReset and channel.sendQueue.len == 0:
      try:
        await channel.conn.write(YamuxHeader.data(channel.id, 0, {Fin}))
      except CancelledError, LPStreamError:
        discard
    await channel.actuallyClose()

method closeWrite*(channel: YamuxChannel) {.async: (raises: []).} =
  ## For yamux, closeWrite is the same as close - it implements half-close
  await channel.close()

proc clearQueues(channel: YamuxChannel, error: ref LPStreamEOFError = nil) =
  for toSend in channel.sendQueue:
    if error.isNil():
      toSend.fut.complete()
    else:
      toSend.fut.fail(error)
  channel.sendQueue = @[]
  channel.recvQueue.clear()

proc reset(channel: YamuxChannel, isLocal: bool = false) {.async: (raises: []).} =
  # If we reset locally, we want to flush up to a maximum of recvWindow
  # bytes. It's because the peer we're connected to can send us data before
  # it receives the reset.
  if channel.isReset:
    return
  trace "Reset channel"
  channel.isReset = true
  channel.remoteReset = not isLocal
  channel.isClosed = true
  channel.clearQueues(newLPStreamEOFError())

  channel.sendWindow = 0
  if not channel.closedLocally:
    if isLocal and not channel.isSending:
      try:
        await channel.conn.write(YamuxHeader.data(channel.id, 0, {Rst}))
      except CancelledError, LPStreamError:
        discard
    await channel.closeImpl()
  if not channel.closedRemotely.isSet():
    await channel.remoteClosed()
  channel.receivedData.fire()
  if not isLocal:
    # If the reset is remote, there's no reason to flush anything.
    channel.recvWindow = 0

method resetImpl*(channel: YamuxChannel) {.async: (raises: []).} =
  await channel.reset(isLocal = true)

proc updateRecvWindow(
    channel: YamuxChannel
) {.async: (raises: [CancelledError, LPStreamError]).} =
  ## Send to the peer a window update when the recvWindow is empty enough
  ##
  # In order to avoid spamming a window update everytime a byte is read,
  # we send it everytime half of the maxRecvWindow is read.
  let inWindow = channel.recvWindow + channel.recvQueue.len
  if inWindow > channel.maxRecvWindow div 2:
    return

  let delta = channel.maxRecvWindow - inWindow
  channel.recvWindow.inc(delta.int)
  await channel.conn.write(YamuxHeader.windowUpdate(channel.id, delta.uint32))
  trace "Increasing the recvWindow", delta

method readOnce*(
    channel: YamuxChannel, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  ## Read from a yamux channel

  if channel.isReset:
    raise
      if channel.remoteReset:
        trace "Stream is remote reset when readOnce", channel = $channel
        newLPStreamResetError()
      elif channel.closedLocally:
        trace "Stream is closed locally when readOnce", channel = $channel
        newLPStreamClosedError()
      else:
        trace "Stream is down when readOnce", channel = $channel
        newLPStreamConnDownError()
  if channel.isEof:
    channel.clearQueues()
    raise newLPStreamRemoteClosedError()
  if channel.recvQueue.isEmpty():
    channel.receivedData.clear()
    let
      closedRemotelyFut = channel.closedRemotely.wait()
      receivedDataFut = channel.receivedData.wait()
    defer:
      if not closedRemotelyFut.finished():
        await closedRemotelyFut.cancelAndWait()
      if not receivedDataFut.finished():
        await receivedDataFut.cancelAndWait()
    await closedRemotelyFut or receivedDataFut
    if channel.closedRemotely.isSet() and channel.recvQueue.isEmpty():
      channel.isEof = true
      channel.clearQueues()
      return
        0 # we return 0 to indicate that the channel is closed for reading from now on

  let consumed = channel.recvQueue.consumeTo(pbytes, nbytes)

  # We made some room in the recv buffer let the peer know
  await channel.updateRecvWindow()
  channel.activity = true
  return consumed

proc gotDataFromRemote(
    channel: YamuxChannel, b: sink seq[byte]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  channel.recvWindow -= b.len
  channel.recvQueue.push(move(b))
  channel.receivedData.fire()
  when defined(libp2p_yamux_metrics):
    libp2p_yamux_recv_queue.observe(channel.recvQueue.len.int64)
  await channel.updateRecvWindow()

proc sendLoop(channel: YamuxChannel) {.async: (raises: []).} =
  if channel.isSending:
    return
  channel.isSending = true
  defer:
    channel.isSending = false

  const NumBytesHeader = 12

  while channel.sendQueue.len > 0:
    channel.sendQueue.keepItIf(not it.fut.finished())

    if channel.sendWindow <= 0:
      trace "Trying to send while the sendWindow is empty"
      if channel.lengthSendQueueWithLimit() > channel.maxSendQueueSize:
        trace "Channel send queue too big, resetting",
          maxSendQueueSize = channel.maxSendQueueSize,
          currentQueueSize = channel.lengthSendQueueWithLimit()
        await channel.reset(isLocal = true)
      break

    let
      bytesAvailable = channel.lengthSendQueue()
      numBytesToSend = min(channel.sendWindow, bytesAvailable.int64).int
    var
      sendBuffer = newSeqUninit[byte](NumBytesHeader + numBytesToSend)
      header = YamuxHeader.data(channel.id, numBytesToSend.uint32)
      inBuffer = 0

    if numBytesToSend >= bytesAvailable and channel.closedLocally:
      trace "Last buffer we will send on this channel", numBytesToSend, bytesAvailable
      header.flags.incl({Fin})

    sendBuffer[0 ..< NumBytesHeader] = header.encode()

    var futures: seq[Future[void].Raising([CancelledError, LPStreamError])]
    while inBuffer < numBytesToSend:
      var toSend = channel.sendQueue[0]
      # concatenate the different message we try to send into one buffer
      let bufferToSend = min(toSend.data.len - toSend.sent, numBytesToSend - inBuffer)

      sendBuffer.toOpenArray(NumBytesHeader, NumBytesHeader + numBytesToSend - 1)[
        inBuffer ..< (inBuffer + bufferToSend)
      ] = toSend.data.toOpenArray(toSend.sent, toSend.sent + bufferToSend - 1)

      channel.sendQueue[0].sent.inc(bufferToSend)

      if toSend.sent >= toSend.data.len:
        # if every byte of the message is in the buffer, add the write future to the
        # sequence of futures to be completed (or failed) when the buffer is sent
        futures.add(toSend.fut)
        channel.sendQueue.delete(0)

      inBuffer.inc(bufferToSend)

    trace "Trying to send buffer", header = $header
    try:
      await channel.conn.write(move(sendBuffer))
      channel.sendWindow.dec(inBuffer)
    except CancelledError:
      discard # sendLoopFut is channel-owned and never cancelled from outside
    except LPStreamError as exc:
      trace "Yamux frame write failed",
        err = exc.msg,
        channel = $channel,
        peerId = channel.peerId,
        protocol = channel.protocol
      let connDown = newLPStreamConnDownError(exc)
      for fut in futures:
        fut.fail(connDown)
      await channel.reset()
      break

    for fut in futures:
      fut.complete()

    channel.activity = true

method write*(
    channel: YamuxChannel, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  ## Write to yamux channel
  ##
  var resFut = newFuture[void]("Yamux Send")

  if channel.remoteReset:
    trace "Stream is reset when write", channel = $channel
    resFut.fail(newLPStreamResetError())
    return resFut

  if channel.closedLocally or channel.isReset:
    resFut.fail(newLPStreamClosedError())
    return resFut

  if msg.len == 0:
    resFut.complete()
    return resFut

  channel.sendQueue.add(ToSend(data: move(msg), sent: 0, fut: resFut))

  when defined(libp2p_yamux_metrics):
    libp2p_yamux_send_queue.observe(channel.lengthSendQueue().int64)

  if not channel.isSending:
    channel.sendLoopFut = channel.sendLoop()

  return resFut

proc open(channel: YamuxChannel) {.async: (raises: [CancelledError, LPStreamError]).} =
  ## Open a yamux channel by sending a window update with Syn or Ack flag
  ##
  if channel.opened:
    trace "Try to open channel twice"
    return
  channel.opened = true
  channel.isReset = false

  await channel.conn.write(
    YamuxHeader.windowUpdate(
      channel.id,
      uint32(max(channel.maxRecvWindow - YamuxDefaultWindowSize, 0)),
      {if channel.isSrc: Syn else: Ack},
    )
  )

method getWrapped*(channel: YamuxChannel): Connection =
  channel.conn

type Yamux* = ref object of Muxer
  channels: Table[uint32, YamuxChannel]
  flushed: Table[uint32, int]
  flushedOrder: seq[uint32]
  currentId: uint32
  isClosed: bool
  maxChannCount: int
  windowSize: int
  maxSendQueueSize: int
  inTimeout: Duration
  outTimeout: Duration

when defined(libp2p_yamux_metrics):
  proc lenBySrc(m: Yamux, isSrc: bool): int =
    m.channels.values.countIt(it.isSrc == isSrc)

proc forgetFlushed(m: Yamux, id: uint32) =
  m.flushed.del(id)
  let index = m.flushedOrder.find(id)
  if index >= 0:
    m.flushedOrder.delete(index)

proc rememberFlushed(m: Yamux, id: uint32, recvWindow: int) =
  let maxFlushed = max(m.maxChannCount, 0)
  if id notin m.flushed:
    m.flushedOrder.add(id)
  m.flushed[id] = recvWindow

  while m.flushedOrder.len > maxFlushed:
    let oldest = m.flushedOrder[0]
    m.flushedOrder.delete(0)
    m.flushed.del(oldest)

proc cleanupChannel(m: Yamux, channel: YamuxChannel) {.async: (raises: []).} =
  try:
    await channel.join()
  except CancelledError:
    discard
  m.channels.del(channel.id)
  when defined(libp2p_yamux_metrics):
    libp2p_yamux_channels.set(
      m.lenBySrc(channel.isSrc).int64, [$channel.isSrc, $channel.peerId]
    )
  if channel.isReset and channel.recvWindow > 0:
    m.rememberFlushed(channel.id, channel.recvWindow)

proc createStream(
    m: Yamux, id: uint32, isSrc: bool, recvWindow: int, maxSendQueueSize: int
): YamuxChannel =
  # During initialization, recvWindow can be larger than maxRecvWindow.
  # This is because the peer we're connected to will always assume
  # that the initial recvWindow is 256k.
  # To solve this contradiction, no updateWindow will be sent until
  # recvWindow is less than maxRecvWindow
  var stream = YamuxChannel(
    id: id,
    maxRecvWindow: recvWindow,
    recvWindow:
      if recvWindow > YamuxDefaultWindowSize: recvWindow else: YamuxDefaultWindowSize,
    sendWindow: YamuxDefaultWindowSize,
    maxSendQueueSize: maxSendQueueSize,
    isSrc: isSrc,
    conn: m.connection,
    receivedData: newAsyncEvent(),
    closedRemotely: newAsyncEvent(),
  )
  stream.objName = "YamuxStream"
  if isSrc:
    stream.dir = Direction.Out
    stream.timeout = m.outTimeout
  else:
    stream.dir = Direction.In
    stream.timeout = m.inTimeout
  stream.timeoutHandler = proc(): Future[void] {.async: (raises: [], raw: true).} =
    trace "Idle timeout expired, resetting YamuxChannel"
    stream.reset(isLocal = true)
  stream.initStream()
  stream.peerId = m.connection.peerId
  stream.observedAddr = m.connection.observedAddr
  stream.localAddr = m.connection.localAddr
  stream.transportDir = m.connection.transportDir
  when defined(libp2p_agents_metrics):
    stream.shortAgent = m.connection.shortAgent
  m.channels[id] = stream
  stream.cleanupFut = m.cleanupChannel(stream)
  trace "Created channel", id, pid = m.connection.peerId
  when defined(libp2p_yamux_metrics):
    libp2p_yamux_channels.set(m.lenBySrc(isSrc).int64, [$isSrc, $stream.peerId])
  return stream

proc forceClose(channel: YamuxChannel) {.async: (raises: []).} =
  ## Drives a channel through its terminal state without waiting on the peer, so
  ## `cleanupChannel`'s `await channel.join()` returns after muxer close.
  channel.closedRemotely.fire()
  channel.isClosedRemotely = true
  if not channel.closeEvent.isSet():
    await channel.actuallyClose()
  channel.receivedData.fire()

proc drainChannelTasks(channels: seq[YamuxChannel]) {.async: (raises: []).} =
  ## Awaits the per-channel tasks so they don't outlive the muxer; callers must
  ## have torn channels and connection down first.
  var futs: seq[Future[void]]
  for channel in channels:
    futs.add(channel.cleanupFut)
    if not channel.handlerFut.isNil():
      futs.add(channel.handlerFut)
    if not channel.sendLoopFut.isNil():
      futs.add(channel.sendLoopFut)
  await noCancel allFutures(futs)

method close*(m: Yamux) {.async: (raises: []).} =
  if m.isClosed == true:
    trace "Already closed"
    return

  trace "Closing yamux"
  let channels = toSeq(m.channels.values())
  for channel in channels:
    channel.clearQueues(newLPStreamEOFError())
    channel.recvWindow = 0
    channel.sendWindow = 0
    channel.closedLocally = true
    channel.isReset = true
    channel.opened = false
    channel.isClosed = true
    await channel.forceClose()
  try:
    await m.connection.write(YamuxHeader.goAway(NormalTermination))
  except CancelledError as exc:
    trace "Yamux shutdown frame canceled", err = exc.msg
  except LPStreamError as exc:
    trace "Yamux shutdown frame write failed", err = exc.msg
  await m.connection.close()

  await drainChannelTasks(channels)

  m.isClosed = true
  trace "Closed yamux"

proc handleStream(m: Yamux, channel: YamuxChannel) {.async: (raises: []).} =
  ## Call the muxer stream handler for this channel
  ##
  await m.streamHandler(channel)
  trace "Yamux stream handler completed", channel = $channel
  doAssert(channel.isClosed, "connection not closed by handler!")

func openStreamProtocols(m: Yamux): seq[string] =
  ## Distinct negotiated protocols of the still-open streams, bounded for logs
  var protocols: seq[string]
  for channel in m.channels.values:
    if channel.protocol.len > 0 and channel.protocol notin protocols:
      protocols.add(channel.protocol)
      if protocols.len == ShortCollectionMax:
        break
  protocols

proc discardData(
    conn: RawConn, length: uint32
) {.async: (raises: [CancelledError, LPStreamError]).} =
  # Unknown or reset streams still carry framed payloads; never interpret those
  # bytes as headers or allocate an untrusted frame-sized discard buffer.
  # Implementation choice to bound discard memory, not a protocol limit.
  const bufferSize = 8192
  var buffer: array[bufferSize, byte]
  var remaining = length
  while remaining > 0:
    let count = min(remaining, uint32(buffer.len)).int
    await conn.readExactly(addr buffer[0], count)
    remaining -= uint32(count)

method handle*(m: Yamux) {.async: (raises: []).} =
  trace "Yamux handler started", peerId = m.connection.peerId
  # Loop exits without an exception only on EOF or GoAway
  var
    reason = "end of stream"
    err = ""
  try:
    while not m.connection.atEof:
      trace "Waiting for header"
      let header = await m.connection.readHeader()
      trace "Message received", header = $header

      case header.msgType
      of Ping:
        if MsgFlags.Syn in header.flags:
          await m.connection.write(YamuxHeader.ping(MsgFlags.Ack, header.length))
      of GoAway:
        var status: GoAwayStatus
        if status.checkedEnumAssign(header.length):
          trace "Received go away", status
          reason = "remote sent go away: " & $status
        else:
          trace "Yamux shutdown status rejected", status = header.length
          reason = "remote sent go away with unknown status: " & $header.length
        break
      of Data, WindowUpdate:
        if MsgFlags.Syn in header.flags:
          if header.streamId in m.channels:
            trace "Trying to create an existing channel, skipping", id = header.streamId
          else:
            m.forgetFlushed(header.streamId)

            if header.streamId mod 2 == m.currentId mod 2:
              trace "Peer used our reserved stream id, skipping",
                id = header.streamId,
                currentId = m.currentId,
                peerId = m.connection.peerId
              raise newException(YamuxError, "Peer used our reserved stream id")
            if m.channels.len >= m.maxChannCount:
              trace "Too many channels created by remote peer",
                peerId = m.connection.peerId, allowedMax = m.maxChannCount
              var remaining = YamuxDefaultWindowSize
              if header.msgType == Data:
                if header.length > uint32(remaining):
                  raise newException(YamuxError, "Peer exhausted the recvWindow")
                remaining -= int(header.length)
              m.rememberFlushed(header.streamId, remaining)
              await m.connection.write(YamuxHeader.data(header.streamId, 0, {Rst}))
              if header.msgType == Data:
                await m.connection.discardData(header.length)
              continue
            let newStream =
              m.createStream(header.streamId, false, m.windowSize, m.maxSendQueueSize)
            await newStream.open()
            newStream.handlerFut = m.handleStream(newStream)
        elif header.streamId notin m.channels:
          if header.msgType == Data:
            m.flushed.withValue(header.streamId, flushed):
              if header.length > uint32(flushed[]):
                raise
                  newException(YamuxError, "Peer exhausted the recvWindow after reset")
              flushed[] -= int(header.length)
              if flushed[] == 0:
                m.forgetFlushed(header.streamId)
            await m.connection.discardData(header.length)

          # If we do not have a stream, likely we sent a RST and/or closed the stream
          trace "Unknown stream id", id = header.streamId

          continue

        let channel =
          try:
            m.channels[header.streamId]
          except KeyError as e:
            raise newException(
              YamuxError,
              "Stream was cleaned up before handling data: " & $header.streamId & " : " &
                e.msg,
              e,
            )

        if header.msgType == WindowUpdate:
          channel.sendWindow =
            min(channel.sendWindow + int64(header.length), MaxSendWindow)
          if not channel.isSending:
            channel.sendLoopFut = channel.sendLoop()
        else:
          if header.length.int > channel.recvWindow.int:
            # check before allocating the buffer
            raise newException(YamuxError, "Peer exhausted the recvWindow")

          if header.length > 0 and not channel.handlerFut.isNil() and
              channel.handlerFut.finished():
            # The handler owned the stream and returned: nobody will read this.
            trace "Yamux data after the stream handler returned, resetting",
              channel = $channel
            await m.connection.discardData(header.length)
            await channel.reset(isLocal = true)
          elif header.length > 0:
            var buffer = newSeqUninit[byte](header.length)
            await m.connection.readExactly(addr buffer[0], int(header.length))
            trace "Yamux data frame received", messageSize = buffer.len
            await channel.gotDataFromRemote(move(buffer))

        if MsgFlags.Fin in header.flags:
          trace "Remote closed channel"
          await channel.remoteClosed()
        if MsgFlags.Rst in header.flags:
          trace "Remote reset channel"
          await channel.reset()
  except CancelledError as exc:
    reason = "handler canceled"
    err = exc.msg
  except LPStreamEOFError as exc:
    reason = "end of stream"
    err = exc.msg
  except LPStreamError as exc:
    reason = "stream error"
    err = exc.msg
  except YamuxError as exc:
    reason = "protocol error"
    err = exc.msg
    try:
      await m.connection.write(YamuxHeader.goAway(ProtocolError))
    except CancelledError, LPStreamError:
      discard
  except MuxerError as exc:
    reason = "muxer error"
    err = exc.msg
    try:
      await m.connection.write(YamuxHeader.goAway(ProtocolError))
    except CancelledError, LPStreamError:
      discard
  finally:
    # Checked before our own close below: tells a local close (e.g. a
    # disconnect requested by the application) apart from a remote one
    debug "Yamux connection closed",
      peerId = m.connection.peerId,
      reason,
      err,
      connectionAlreadyClosed = m.connection.closed,
      openStreams = m.channels.len,
      protocols = m.openStreamProtocols() #nolint
    await m.close()
  trace "Yamux handler stopped"

method getStreams*(m: Yamux): seq[MuxedStream] {.gcsafe.} =
  var streams: seq[MuxedStream]
  for c in m.channels.values:
    streams.add(c)
  streams

method newStream*(
    m: Yamux, name: string = "", lazy: bool = false
): Future[MuxedStream] {.async: (raises: [CancelledError, LPStreamError, MuxerError]).} =
  if m.channels.len > m.maxChannCount - 1:
    raise newException(TooManyChannels, "max allowed channel count exceeded")
  let stream = m.createStream(m.currentId, true, m.windowSize, m.maxSendQueueSize)
  m.currentId += 2
  if not lazy:
    await stream.open()
  return stream

proc new*(
    T: type[Yamux],
    conn: RawConn,
    maxChannCount: int = MaxChannelCount,
    windowSize: int = YamuxDefaultWindowSize,
    maxSendQueueSize: int = MaxSendQueueSize,
    inTimeout: Duration = 5.minutes,
    outTimeout: Duration = 5.minutes,
): T =
  T(
    connection: conn,
    currentId: if conn.dir == Out: 1 else: 2,
    maxChannCount: maxChannCount,
    windowSize: windowSize,
    maxSendQueueSize: maxSendQueueSize,
    inTimeout: inTimeout,
    outTimeout: outTimeout,
  )
