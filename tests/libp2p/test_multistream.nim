# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import
  ../../libp2p/[
    multistream,
    stream/bufferstream,
    stream/bridgestream,
    stream/connection,
    multiaddress,
    transports/transport,
    transports/tcptransport,
    protocols/protocol,
    upgrademngrs/upgrade,
    utils/future,
  ]
import ../tools/[unittest, sync, multiaddress]

{.push raises: [].}

converter toStringSeq(s: string): seq[string] =
  @[s]

## Mock stream for select test
type TestSelectStream = ref object of Connection
  step*: int

method readOnce*(
    s: TestSelectStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  let fut = newFuture[int]()
  case s.step
  of 1:
    var buf = newSeq[byte](1)
    buf[0] = 19
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 2
    fut.complete(buf.len)
  of 2:
    var buf = "/multistream/1.0.0\n"
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 3
    fut.complete(buf.len)
  of 3:
    var buf = newSeq[byte](1)
    buf[0] = 18
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 4
    fut.complete(buf.len)
  of 4:
    var buf = "/test/proto/1.0.0\n"
    copyMem(pbytes, addr buf[0], buf.len())
    fut.complete(buf.len)
  else:
    copyMem(pbytes, cstring("\0x3na\n"), "\0x3na\n".len())

    fut.complete("\0x3na\n".len())
  fut

method write*(
    s: TestSelectStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  newFutureCompleted[void]()

method close(s: TestSelectStream) {.async: (raises: [], raw: true).} =
  s.isClosed = true
  s.isEof = true
  newFutureCompleted[void]()

proc newTestSelectStream(): TestSelectStream =
  TestSelectStream(step: 1)

## Mock stream for handles `ls` test
type
  LsHandler = proc(procs: seq[byte]): Future[void] {.
    async: (raises: [CancelledError, LPStreamError])
  .}

  TestLsStream = ref object of Connection
    step*: int
    ls*: LsHandler

method readOnce*(
    s: TestLsStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  let fut = newFuture[int]()
  case s.step
  of 1:
    var buf = newSeq[byte](1)
    buf[0] = 19
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 2
    fut.complete(buf.len())
  of 2:
    var buf = "/multistream/1.0.0\n"
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 3
    fut.complete(buf.len())
  of 3:
    var buf = newSeq[byte](1)
    buf[0] = 3
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 4
    fut.complete(buf.len())
  of 4:
    var buf = "ls\n"
    copyMem(pbytes, addr buf[0], buf.len())
    fut.complete(buf.len())
  else:
    var buf = "na\n"
    copyMem(pbytes, addr buf[0], buf.len())
    fut.complete(buf.len())
  fut

method write*(
    s: TestLsStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  if s.step == 4:
    return s.ls(msg)
  newFutureCompleted[void]()

method close(s: TestLsStream): Future[void] {.async: (raises: [], raw: true).} =
  s.isClosed = true
  s.isEof = true
  newFutureCompleted[void]()

proc newTestLsStream(ls: LsHandler): TestLsStream {.gcsafe.} =
  TestLsStream(ls: ls, step: 1)

## Mock stream for handles `na` test
type
  NaHandler = proc(procs: string): Future[void] {.
    async: (raises: [CancelledError, LPStreamError])
  .}

  TestNaStream = ref object of Connection
    step*: int
    na*: NaHandler

method readOnce*(
    s: TestNaStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  let fut = newFuture[int]()
  case s.step
  of 1:
    var buf = newSeq[byte](1)
    buf[0] = 19
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 2
    fut.complete(buf.len())
  of 2:
    var buf = "/multistream/1.0.0\n"
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 3
    fut.complete(buf.len())
  of 3:
    var buf = newSeq[byte](1)
    buf[0] = 18
    copyMem(pbytes, addr buf[0], buf.len())
    s.step = 4
    fut.complete(buf.len())
  of 4:
    var buf = "/test/proto/1.0.0\n"
    copyMem(pbytes, addr buf[0], buf.len())
    fut.complete(buf.len())
  else:
    copyMem(pbytes, cstring("\0x3na\n"), "\0x3na\n".len())

    fut.complete("\0x3na\n".len())
  fut

method write*(
    s: TestNaStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  if s.step == 4:
    return s.na(string.fromBytes(msg))
  newFutureCompleted[void]()

method close(s: TestNaStream): Future[void] {.async: (raises: [], raw: true).} =
  s.isClosed = true
  s.isEof = true
  newFutureCompleted[void]()

proc newTestNaStream(na: NaHandler): TestNaStream =
  TestNaStream(na: na, step: 1)

proc noReachHandler(
    stream: Stream, proto: string
): Future[void] {.async: (raises: [CancelledError]).} =
  raiseAssert "must not be reached"

suite "Multistream select":
  const codecs = "/test/proto/1.0.0"

  teardown:
    checkTrackers()

  asyncTest "test select custom proto":
    let ms = MultistreamSelect.new()
    let stream = newTestSelectStream()
    check (await ms.select(stream, @[codecs])) == codecs
    await stream.close()

  asyncTest "test handle custom proto":
    let ms = MultistreamSelect.new()
    let stream = newTestSelectStream()

    proc testHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      check proto == codecs
      await stream.close()

    ms.addHandler(LPProtocol.new(codecs, testHandler))
    await ms.handle(stream)

  asyncTest "test handle invokes only first matching handler":
    let ms = MultistreamSelect.new()
    var firstCalls = 0

    proc firstHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      firstCalls += 1
      check proto == codecs
      await stream.close()

    ms.addHandler(LPProtocol.new(codecs, firstHandler))
    ms.addHandler(LPProtocol.new(codecs, noReachHandler))
    ms.addHandler(LPProtocol.new(codecs, noReachHandler))

    await ms.handle(newTestSelectStream())
    await ms.handle(newTestSelectStream())

    check firstCalls == 2

  asyncTest "test handle `ls`":
    let ms = MultistreamSelect.new()

    var stream: Stream = nil
    let done = newFuture[void]()
    proc testLsHandler(
        proto: seq[byte]
    ) {.async: (raises: [CancelledError, LPStreamError]).} =
      var strProto: string = string.fromBytes(proto)
      check strProto == "\x26/test/proto1/1.0.0\n/test/proto2/1.0.0\n"
      await stream.close()
      done.complete()

    stream = Connection(newTestLsStream(testLsHandler))
    ms.addHandler("/test/proto1/1.0.0", LPProtoHandler(noReachHandler))
    ms.addHandler("/test/proto2/1.0.0", LPProtoHandler(noReachHandler))

    await ms.handle(stream)
    await done

  asyncTest "test handle `na`":
    let ms = MultistreamSelect.new()

    var stream: Stream = nil
    proc testNaHandler(
        msg: string
    ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
      check msg == "\x03na\n"
      await stream.close()

    stream = newTestNaStream(testNaHandler)

    ms.addHandler("/unabvailable/proto1/1.0.0", LPProtoHandler(noReachHandler))

    await ms.handle(stream)

  asyncTest "e2e - handle":
    var protocol: LPProtocol = new LPProtocol
    proc testHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      check proto == codecs
      try:
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "LPStreamError while handling connection"
      finally:
        await stream.close()

    let msListen = MultistreamSelect.new()
    msListen.addHandler(codecs, LPProtoHandler(testHandler))

    let transport1 = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(@[TcpAutoAddress])

    proc acceptHandler(): Future[void] {.async.} =
      let stream = await transport1.accept()
      await msListen.handle(stream)
      await stream.close()

    let handlerWait = acceptHandler()

    let msDial = MultistreamSelect.new()
    let transport2 = TcpTransport.new(upgrade = Upgrade())
    let stream = await transport2.dial(transport1.addrs[0])

    check (await msDial.select(stream, codecs)) == true

    let hello = string.fromBytes(await stream.readLp(1024))
    check hello == "Hello!"
    await stream.close()

    await transport2.stop()
    await transport1.stop()

    await handlerWait

  asyncTest "e2e - streams limit":
    let blocker = newWaitGroup(1)

    # Start 5 streams which are blocked by `blocker`
    # Try to start a new one, which should fail
    # Unblock the 5 streams, check that we can open a new one
    proc testHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      try:
        await blocker.wait()
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "LPStreamError while handling connection"
      finally:
        await stream.close()

    let protocol = LPProtocol.new(codecs, testHandler, maxIncomingStreamsPerPeer = 5)

    protocol.handler = testHandler
    let msListen = MultistreamSelect.new()
    msListen.addHandler(protocol)

    let transport1 = TcpTransport.new(upgrade = Upgrade())
    await transport1.start(@[TcpAutoAddress])

    proc acceptedOne(c: Stream) {.async.} =
      await msListen.handle(c)
      await c.close()

    proc acceptHandler() {.async.} =
      while true:
        let stream = await transport1.accept()
        asyncSpawn acceptedOne(stream)

    var handlerWait = acceptHandler()

    let msDial = MultistreamSelect.new()
    let transport2 = TcpTransport.new(upgrade = Upgrade())

    proc connector() {.async.} =
      let stream = await transport2.dial(transport1.addrs[0])
      check:
        (await msDial.select(stream, codecs)) == true
      check:
        string.fromBytes(await stream.readLp(1024)) == "Hello!"
      await stream.close()

    # Fill up the 5 allowed streams
    var dialers: seq[Future[void]]
    for _ in 0 ..< 5:
      dialers.add(connector())

    # This one will fail during negotiation
    expect LPStreamEOFError:
      await connector()
    # check that the dialers aren't finished
    check:
      (await dialers[0].withTimeout(10.milliseconds)) == false

    # unblock the dialers
    blocker.done()
    await allFutures(dialers)

    # now must work
    await connector()

    await transport2.stop()
    await transport1.stop()

    await handlerWait.cancelAndWait()

  asyncTest "e2e - ls":
    let msListen = MultistreamSelect.new()
    msListen.addHandler("/test/proto1/1.0.0", LPProtoHandler(noReachHandler))
    msListen.addHandler("/test/proto2/1.0.0", LPProtoHandler(noReachHandler))

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    let listenFut = transport1.start(@[TcpAutoAddress])

    proc acceptHandler(): Future[void] {.async.} =
      let stream = await transport1.accept()
      try:
        await msListen.handle(stream)
      except LPStreamEOFError as e:
        raiseAssert "unexpected error: " & e.msg
      except LPStreamClosedError as e:
        raiseAssert "unexpected error: " & e.msg
      finally:
        await stream.close()

    let acceptFut = acceptHandler()
    let msDial = MultistreamSelect.new()
    let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    let stream = await transport2.dial(transport1.addrs[0])

    let ls = await msDial.list(stream)
    let protos: seq[string] = @["/test/proto1/1.0.0", "/test/proto2/1.0.0"]

    check ls == protos

    await stream.close()
    await acceptFut
    await transport2.stop()
    await transport1.stop()
    await listenFut

  asyncTest "e2e - select one from a list with unsupported protos":
    proc testHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      check proto == codecs
      try:
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "LPStreamError while handling connection"
      finally:
        await stream.close()

    let msListen = MultistreamSelect.new()
    msListen.addHandler(LPProtocol.new(codecs, testHandler))

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(@[TcpAutoAddress])

    proc acceptHandler(): Future[void] {.async.} =
      let stream = await transport1.accept()
      await msListen.handle(stream)

    let acceptFut = acceptHandler()
    let msDial = MultistreamSelect.new()
    let transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    let stream = await transport2.dial(transport1.addrs[0])

    check (await msDial.select(stream, @["/test/no/proto/1.0.0", codecs])) == codecs

    let hello = string.fromBytes(await stream.readLp(1024))
    check hello == "Hello!"

    await stream.close()
    await acceptFut
    await transport2.stop()
    await transport1.stop()

suite "Multistream :: stream limits":
  const codecs = "/test/proto-stream-limits/1.0.0"

  teardown:
    checkTrackers()

  proc acceptHandler(protocol: LPProtocol, transport: Transport) {.async.} =
    let msListen = MultistreamSelect.new()
    msListen.addHandler(protocol)

    proc acceptedOne(c: Stream) {.async.} =
      await msListen.handle(c)
      await c.close()

    while true:
      let stream = await transport.accept()
      asyncSpawn acceptedOne(stream)

  proc makeBlockedHandler(entered: WaitGroup = nil): LPProtoHandler =
    let blocker = newWaitGroup(1)
    # block stream progress in order to make stream occupied while test is running.
    # if handler finishes fast we would never reach limit - it would be a race otherwise.

    proc testHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      if entered != nil:
        entered.done()
      try:
        await blocker.wait()
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "LPStreamError while handling connection"
      finally:
        await stream.close()

    return testHandler

  asyncTest "e2e - inbound total stream limit":
    const maxTotalStreams = 3

    # Every slot must be reserved before the extra dialer starts, otherwise the
    # dialers race on reserveIncoming and the extra one may be the slot winner.
    let reserved = newWaitGroup(maxTotalStreams)
    let protocol = LPProtocol.new(
      codecs, makeBlockedHandler(reserved), maxIncomingStreamsTotal = maxTotalStreams
    )

    let transport1 = TcpTransport.new(upgrade = Upgrade())
    await transport1.start(@[TcpAutoAddress])

    let handlerWait = acceptHandler(protocol, transport1)

    let msDial = MultistreamSelect.new()
    let transport2 = TcpTransport.new(upgrade = Upgrade())

    proc connector() {.async.} =
      let stream = await transport2.dial(transport1.addrs[0])
      check:
        (await msDial.select(stream, protocol.codecs[0])) == true
      check:
        string.fromBytes(await stream.readLp(1024)) == "Hello!"
      await stream.close()

    var dialers: seq[Future[void]]
    for _ in 0 ..< maxTotalStreams:
      dialers.add(connector())

    await reserved.wait()

    expect LPStreamEOFError:
      await connector()

    await dialers.cancelAndWait()
    await transport2.stop()
    await transport1.stop()
    await handlerWait.cancelAndWait()

  asyncTest "e2e - shared budget across compatible codecs":
    # Both slots must be reserved before the third dialer starts, otherwise the
    # dialers race on reserveIncoming and the third one may be the slot winner.
    let reserved = newWaitGroup(2)
    let protocol = LPProtocol.new(
      @["/test/proto1/1.0.0", "/test/proto2/1.0.0"],
      makeBlockedHandler(reserved),
      maxIncomingStreamsTotal = 2,
    )

    let transport1 = TcpTransport.new(upgrade = Upgrade())
    await transport1.start(@[TcpAutoAddress])

    let handlerWait = acceptHandler(protocol, transport1)

    let msDial = MultistreamSelect.new()
    let transport2 = TcpTransport.new(upgrade = Upgrade())

    proc connector(proto: string): Future[void] {.async.} =
      let stream = await transport2.dial(transport1.addrs[0])
      check:
        (await msDial.select(stream, proto)) == true
      check:
        string.fromBytes(await stream.readLp(1024)) == "Hello!"
      await stream.close()

    var d1 = connector("/test/proto1/1.0.0")
    var d2 = connector("/test/proto2/1.0.0")

    await reserved.wait()

    expect LPStreamEOFError:
      await connector("/test/proto1/1.0.0")

    await @[d1, d2].cancelAndWait()
    await transport2.stop()
    await transport1.stop()
    await handlerWait.cancelAndWait()

  asyncTest "e2e - inbound budget released on handler completion":
    var handlerCount = 0
    var handlerResolved = newFuture[void]()
    proc testHandler(
        stream: Stream, proto: string
    ): Future[void] {.async: (raises: [CancelledError]).} =
      handlerCount += 1
      try:
        await stream.writeLp("Hello!")
      except LPStreamError:
        raiseAssert "LPStreamError while handling connection"
      finally:
        await stream.close()
        if handlerCount == 1:
          handlerResolved.complete()

    let protocol = LPProtocol.new(codecs, testHandler, maxIncomingStreamsTotal = 1)

    let transport1 = TcpTransport.new(upgrade = Upgrade())
    await transport1.start(@[TcpAutoAddress])

    let handlerWait = acceptHandler(protocol, transport1)

    let msDial = MultistreamSelect.new()
    let transport2 = TcpTransport.new(upgrade = Upgrade())

    proc connector(): Future[void] {.async.} =
      let stream = await transport2.dial(transport1.addrs[0])
      check:
        (await msDial.select(stream, protocol.codecs[0])) == true
      check:
        string.fromBytes(await stream.readLp(1024)) == "Hello!"
      await stream.close()

    # First stream fills budget, then completes (budget released)
    await connector()
    await handlerResolved
    check handlerCount == 1
    # Second stream should succeed
    await connector()
    check handlerCount == 2

    await transport2.stop()
    await transport1.stop()
    await handlerWait.cancelAndWait()

  asyncTest "e2e - inbound per-peer limit":
    # Signal that both per-peer slots have actually been reserved before
    # launching the third dialer; without this, the three streams race on
    # reserveIncoming and the third dialer may be the one that wins a slot,
    # hanging on the blocked handler until the test timeout.
    let reserved = newWaitGroup(2)
    let protocol = LPProtocol.new(
      codecs, makeBlockedHandler(reserved), maxIncomingStreamsPerPeer = 2
    )

    let transport1 = TcpTransport.new(upgrade = Upgrade())
    await transport1.start(@[TcpAutoAddress])

    let handlerWait = acceptHandler(protocol, transport1)

    let msDial = MultistreamSelect.new()
    let transport2 = TcpTransport.new(upgrade = Upgrade())

    proc connector(): Future[void] {.async.} =
      let stream = await transport2.dial(transport1.addrs[0])
      check:
        (await msDial.select(stream, protocol.codecs[0])) == true
      check:
        string.fromBytes(await stream.readLp(1024)) == "Hello!"
      await stream.close()

    var dialers: seq[Future[void]]
    for _ in 0 ..< 2:
      dialers.add(connector())

    await reserved.wait()

    expect LPStreamEOFError:
      await connector()

    await dialers.cancelAndWait()
    await transport2.stop()
    await transport1.stop()
    await handlerWait.cancelAndWait()

  asyncTest "empty proposal produces one rejection before the next proposal":
    let (client, server) = bridgedConnections()
    let handling = MultistreamSelect.handle(server, @[codecs], active = true)
    defer:
      await handling.cancelAndWait()
      await client.close()
    await client.writeLp("\n")
    check string.fromBytes(await client.readLp(1024)) == "na\n"
    await client.writeLp(codecs & "\n")
    check string.fromBytes(await client.readLp(1024)) == codecs & "\n"
    check (await handling) == codecs

suite "Multistream :: result API":
  const codecs = "/test/proto/1.0.0"

  teardown:
    checkTrackers()

  proc selectAgainstHeader(
      header: string
  ): Future[MultiStreamResult[string]] {.
      async: (raises: [CancelledError, LPStreamError])
  .} =
    let (client, server) = bridgedConnections()
    let selecting = MultistreamSelect.trySelect(client, @[codecs])
    defer:
      await client.close()
      await server.close()
    discard await server.readLp(1024)
    discard await server.readLp(1024)
    await server.writeLp(header)
    let res = await selecting
    res

  asyncTest "trySelect returns HandshakeFailed on a wrong header":
    check (await selectAgainstHeader("/other/1.0.0\n")).error ==
      MultiStreamFailure.HandshakeFailed

  asyncTest "trySelect returns MalformedMessage on a header without newline":
    check (await selectAgainstHeader("/multistream/1.0.0")).error ==
      MultiStreamFailure.MalformedMessage

  asyncTest "tryHandle returns InvalidFirstMessage before the handshake":
    let (client, server) = bridgedConnections()
    let handling = MultistreamSelect.tryHandle(server, @[codecs])
    defer:
      await client.close()
      await server.close()
    await client.writeLp(codecs & "\n")
    check (await handling).error == MultiStreamFailure.InvalidFirstMessage

  asyncTest "handle raises MultiStreamError with the failure text":
    let (client, server) = bridgedConnections()
    let handling = MultistreamSelect.handle(server, @[codecs])
    defer:
      await client.close()
      await server.close()
    await client.writeLp(codecs & "\n")
    try:
      discard await handling
      raiseAssert "handle must raise"
    except MultiStreamError as e:
      check e == MultiStreamFailure.InvalidFirstMessage

suite "Multistream :: optimistic selection":
  const
    codec = "/test/optimistic/1.0.0"
    header = "/multistream/1.0.0\n"

  proc bufferedPair(closeTogether = true): (BridgeStream, BridgeStream) =
    let (client, server) = bridgedConnections(closeTogether = closeTogether)
    client.readQueue = newAsyncQueue[seq[byte]](16)
    server.readQueue = newAsyncQueue[seq[byte]](16)
    (client, server)

  teardown:
    checkTrackers()

  asyncTest "payload is sent before acknowledgement and responses are consumed once":
    let (client, server) = bufferedPair()
    let selected = await MultistreamSelect.selectOptimistic(client, codec)
    defer:
      await selected.close()
    await selected.writeLp("early payload")
    check string.fromBytes(await server.readLp(1024)) == header
    check string.fromBytes(await server.readLp(1024)) == codec & "\n"
    check string.fromBytes(await server.readLp(1024)) == "early payload"
    check selected.getWrapped() == client
    await server.writeLp(header)
    await server.writeLp(codec & "\n")
    await server.writeLp("first")
    await server.writeLp("second")
    check string.fromBytes(await selected.readLp(1024)) == "first"
    check string.fromBytes(await selected.readLp(1024)) == "second"
    check client.protocol == codec

  asyncTest "works with the regular listener":
    let (client, server) = bufferedPair()
    let handling = MultistreamSelect.handle(server, @[codec])
    let selected = await MultistreamSelect.selectOptimistic(client, codec)
    defer:
      await selected.close()
    await selected.writeLp("request")
    check (await handling) == codec
    check string.fromBytes(await server.readLp(1024)) == "request"
    await server.writeLp("response")
    check string.fromBytes(await selected.readLp(1024)) == "response"

  asyncTest "invalid acknowledgements reset the stream and prevent further IO":
    for (responses, expectedError) in [
      (
        @["/wrong/header\n"],
        "Optimistic multistream handshake failed: unexpected codec",
      ),
      (
        @["/multistream/1.0.0"],
        "Optimistic multistream handshake failed: MultistreamSelect failed, malformed message",
      ),
      (@[header, "na\n"], "Optimistic multistream protocol rejected"),
      (@[header, "/wrong/protocol\n"], "Optimistic multistream protocol rejected"),
      (
        @[header, codec],
        "Optimistic multistream protocol negotiation failed: MultistreamSelect failed, malformed message",
      ),
      (
        @[header, ""],
        "Optimistic multistream protocol negotiation failed: MultistreamSelect failed, malformed message",
      ),
    ]:
      let (client, server) = bufferedPair()
      let selected = await MultistreamSelect.selectOptimistic(client, codec)
      defer:
        await selected.close()
      for response in responses:
        await server.writeLp(response)
      expectMsg LPStreamError, expectedError:
        discard await selected.readLp(1024)
      check selected.wasResetLocally
      check client.wasResetLocally
      expectMsg LPStreamClosedError, "Stream Closed!":
        await selected.writeLp("must fail")
      expectMsg LPStreamClosedError, "Stream Closed!":
        discard await selected.readLp(1024)

  asyncTest "EOF during acknowledgement resets the stream":
    let (client, server) = bufferedPair(closeTogether = false)
    let selected = await MultistreamSelect.selectOptimistic(client, codec)
    defer:
      await selected.close()
      await server.close()
    await client.pushEof()
    expectMsg LPStreamEOFError, "Stream EOF!":
      discard await selected.readLp(1024)
    check client.wasResetLocally

  asyncTest "cancellation during acknowledgement resets instead of retrying partial data":
    let (client, server) = bufferedPair()
    let selected = await MultistreamSelect.selectOptimistic(client, codec)
    defer:
      await selected.close()
    await server.writeLp(header)
    let reading = selected.readLp(1024)
    await reading.cancelAndWait()
    check reading.cancelled
    check client.wasResetLocally

  asyncTest "closing without reading releases both streams":
    let (client, server) = bufferedPair()
    let selected = await MultistreamSelect.selectOptimistic(client, codec)
    await selected.close()
    await selected.close()
    check client.closed
    check server.closed

  asyncTest "join completes when the underlying stream closes":
    let (client, server) = bufferedPair(closeTogether = false)
    let selected = await MultistreamSelect.selectOptimistic(client, codec)
    defer:
      await selected.close()
      await server.close()

    let joined = selected.join()
    check not joined.finished()
    await client.close()
    await joined
    check selected.closed
