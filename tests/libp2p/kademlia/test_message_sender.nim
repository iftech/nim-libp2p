# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

# included, not imported: the tests reach into the per-peer bookkeeping.
include ../../../libp2p/protocols/kademlia/message_sender

import sequtils
import
  ../../../libp2p/[protocols/protocol, builders], ../../../libp2p/stream/bridgestream
import
  ../../tools/[
    crypto, fault_stream, lifecycle, multiaddress, stall_server, switch_builder,
    unittest,
  ]

const
  TestCodec = "/test/kad-message-sender/1.0.0"
  MaxTestMsgSize = 4096

type CountingEcho = ref object of LPProtocol
  streams: int ## inbound streams the remote opened
  messages: int ## messages received across all of them
  reply: bool
  closeAfter: int ## close the stream once this many messages arrived; 0 keeps it open
  lastInbound: Stream ## the newest inbound stream, for the test to reset

proc newCountingEcho(reply = true, closeAfter = 0): CountingEcho =
  let echoProto = CountingEcho(reply: reply, closeAfter: closeAfter)
  echoProto.codec = TestCodec
  echoProto.handler = proc(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    echoProto.streams.inc()
    echoProto.lastInbound = stream
    defer:
      await stream.close()

    while not stream.atEof:
      let buf =
        try:
          await stream.readLp(MaxTestMsgSize)
        except LPStreamError:
          return
      echoProto.messages.inc()

      if echoProto.reply:
        try:
          await stream.writeLp(buf)
        except LPStreamError:
          return

      if echoProto.closeAfter > 0 and echoProto.messages >= echoProto.closeAfter:
        return

  echoProto

proc setupPair(
    proto: CountingEcho
): tuple[client: Switch, server: Switch] {.raises: [LPError].} =
  let client = makeStandardSwitch(TcpAutoAddress)
  let server = makeStandardSwitch(TcpAutoAddress)
  server.mount(proto)
  (client, server)

proc sendRequest(
    sender: MessageSender, server: Switch, payload: seq[byte], timeout: Duration
): Future[Result[seq[byte], SendError]] {.async: (raises: [CancelledError]).} =
  await sender.sendRequest(
    server.peerInfo.peerId, server.peerInfo.addrs, payload, timeout
  )

proc sendMessage(
    sender: MessageSender, server: Switch, payload: seq[byte], timeout: Duration
): Future[Result[void, SendError]] {.async: (raises: [CancelledError]).} =
  await sender.sendMessage(
    server.peerInfo.peerId, server.peerInfo.addrs, payload, timeout
  )

proc faultSender(stream: FaultStream): MessageSender {.raises: [LPError].} =
  let base = makeStandardSwitch(TcpAutoAddress)
  MessageSender.new(FaultSwitch.new(base, stream), TestCodec, MaxTestMsgSize)

proc requestOverFaultStream(
    sender: MessageSender, timeout: Duration
): Future[Result[seq[byte], SendError]] {.async: (raises: [CancelledError]).} =
  await sender.sendRequest(randomPeerId(), @[], @[byte 1], timeout)

proc errorAfter(
    stream: FaultStream, timeout: Duration
): Future[SendError] {.async: (raises: [CancelledError, LPError]).} =
  let sender = faultSender(stream)
  let reply = await sender.requestOverFaultStream(timeout)
  await sender.stop()
  require reply.isErr()
  reply.error()

suite "KadDHT message sender":
  teardown:
    checkTrackers()

  asyncTest "reuses a single stream across RPCs to the same peer":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    for i in 0 ..< 3:
      let reply = await sender.sendRequest(server, @[byte i], 1.seconds)
      check reply.tryGet() == @[byte i]

    check:
      proto.streams == 1
      proto.messages == 3

  asyncTest "reopens transparently after the remote drops the stream":
    let proto = newCountingEcho(closeAfter = 1)
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    for i in 0 ..< 2:
      let reply = await sender.sendRequest(server, @[byte i], 1.seconds)
      check reply.tryGet() == @[byte i]

    check proto.streams == 2

  asyncTest "serializes concurrent RPCs on one stream":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    let replies = (0 ..< 4).mapIt(sender.sendRequest(server, @[byte it], 5.seconds))
    await allFutures(replies)

    # Each RPC reads back its own payload, so no reply was mistaken for another.
    for i, fut in replies:
      check fut.read().tryGet() == @[byte i]
    check proto.streams == 1

  asyncTest "a reply-less send retires its stream":
    let proto = newCountingEcho(reply = false)
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    for i in 0 ..< 2:
      check (await sender.sendMessage(server, @[byte i], 1.seconds)).isOk()

    # A remote that does answer would leave its reply buffered, so a
    # fire-and-forget send must never hand its stream to the next RPC.
    checkUntilTimeout:
      proto.streams == 2
      proto.messages == 2

  asyncTest "an unanswered request fails at the read stage":
    let proto = newCountingEcho(reply = false)
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    let reply = await sender.sendRequest(server, @[byte 1], 1.seconds)
    check:
      reply.isErr()
      reply.error().stage == readStage

  asyncTest "an RPC that times out behind another one fails at the wait stage":
    let proto = newCountingEcho(reply = false)
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    let first = sender.sendRequest(server, @[byte 1], 1.seconds)
    let second = await sender.sendRequest(server, @[byte 2], 100.milliseconds)
    let firstReply = await first
    check:
      second.isErr()
      second.error().stage == waitStage
      firstReply.isErr()
      firstReply.error().stage == readStage

  asyncTest "an unreachable peer fails at the refused stage":
    let client = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[client])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    let unreachable = randomPeerId()
    # Windows retries a refused loopback connect for about 2 seconds.
    let reply = await sender.sendRequest(
      unreachable, @[ma("/ip4/127.0.0.1/tcp/1")], @[byte 1], 5.seconds
    )
    check:
      reply.isErr()
      reply.error().stage == refusedStage

  asyncTest "dropPeer forces the next RPC onto a fresh stream":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    check (await sender.sendRequest(server, @[byte 1], 1.seconds)).isOk()

    await sender.dropPeer(server.peerInfo.peerId)

    check (await sender.sendRequest(server, @[byte 2], 1.seconds)).isOk()
    check proto.streams == 2

  asyncTest "a cancelled RPC leaves the peer's connection up":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    await client.connect(server.peerInfo.peerId, server.peerInfo.addrs)

    # The cancellation lands in the dial, which is where it hurts: `Dialer.dial`
    # closes the connection it reused when it is cancelled, which would take
    # down every other stream the peer holds on that connection.
    let cancelled = sender.sendRequest(server, @[byte 1], 5.seconds)
    await cancelled.cancelAndWait()

    check client.isConnected(server.peerInfo.peerId)

    let reply = await sender.sendRequest(server, @[byte 2], 5.seconds)
    check reply.tryGet() == @[byte 2]

  asyncTest "a stalled dial gives up at the RPC deadline":
    let stall = startStallServer()
    let client = makeStandardSwitch(TcpAutoAddress)
    await client.start()

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      # The stall server first: it frees the abandoned dial that `stop` waits for.
      await stall.stop()
      await sender.stop()
      await client.stop()

    let peerId = randomPeerId()
    let started = Moment.now()
    let reply =
      await sender.sendRequest(peerId, @[stall.address], @[byte 1], 200.milliseconds)
    check:
      # The RPC deadline, not the dialer's: the two are 200ms and 30s apart.
      Moment.now() - started < 5.seconds
      reply.isErr()
      reply.error().stage == dialStage

  asyncTest "cancelling an RPC does not wait out a stalled dial":
    const timeout = 30.seconds
    let stall = startStallServer()
    let client = makeStandardSwitch(TcpAutoAddress)
    await client.start()

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await stall.stop()
      await sender.stop()
      await client.stop()

    let peerId = randomPeerId()
    let rpc = sender.sendRequest(peerId, @[stall.address], @[byte 1], timeout)
    await stall.waitAccepted()

    await rpc.cancelAndWait().wait(timeout div 5)
    check rpc.cancelled()

  asyncTest "a reset stream is dropped without another RPC":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    check (await sender.sendRequest(server, @[byte 1], 1.seconds)).isOk()
    check sender.senders.len == 1

    await proto.lastInbound.reset()

    # Only the next RPC to a peer looks at its stream, and it may never come.
    checkUntilTimeout:
      sender.senders.len == 0

  asyncTest "a closing stream keeps the entry an RPC still holds":
    let client = makeStandardSwitch(TcpAutoAddress)
    startAndDeferStop(@[client])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    let peerId = randomPeerId()
    let (stream, remote) = bridgedConnections()
    let ps = sender.senderFor(peerId)
    ps.stream = stream
    ps.watchFut = sender.watchStream(peerId, ps, stream)
    ps.users = 1

    await remote.close()
    checkUntilTimeout:
      ps.stream.isNil()
    check sender.senders.len == 1

    ps.users = 0
    sender.forget(peerId, ps)
    check sender.senders.len == 0

  asyncTest "stop leaves no watcher behind":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    check (await sender.sendRequest(server, @[byte 1], 1.seconds)).isOk()

    let ps = sender.senders.getOrDefault(server.peerInfo.peerId)
    require not ps.isNil()
    check not ps.watchFut.isNil()

    await sender.stop()
    check:
      ps.watchFut.isNil()
      sender.senders.len == 0

  asyncTest "a stopped sender refuses to dial":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    await sender.stop()

    let reply = await sender.sendRequest(server, @[byte 1], 1.seconds)
    check:
      reply.isErr()
      reply.error().stage == dialStage
      proto.streams == 0

  asyncTest "a restarted sender dials again":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    await sender.stop()
    sender.start()
    check not sender.stopped

    let reply = await sender.sendRequest(server, @[byte 1], 1.seconds)
    check:
      reply.tryGet() == @[byte 1]
      proto.streams == 1

  asyncTest "a failed write or read fails at its stage and resets the stream":
    let failedWrite = FaultStream.new(onWrite = Fault.Fail)
    let failedRead = FaultStream.new(onRead = Fault.Fail)
    defer:
      await failedWrite.close()
      await failedRead.close()

    let writeErr = await failedWrite.errorAfter(1.seconds)
    let readErr = await failedRead.errorAfter(1.seconds)
    check:
      writeErr.stage == writeStage
      writeErr.msg == "fault stream write failed"
      readErr.stage == readStage
      readErr.msg == "fault stream read failed"
      failedWrite.wasResetLocally()
      failedWrite.reads == 0
      failedRead.wasResetLocally()

  asyncTest "a hung write or read gives up at the RPC deadline":
    let hungWrite = FaultStream.new(onWrite = Fault.Hang)
    let hungRead = FaultStream.new(onRead = Fault.Hang)
    defer:
      await hungWrite.close()
      await hungRead.close()

    let writeErr = await hungWrite.errorAfter(100.milliseconds)
    let readErr = await hungRead.errorAfter(100.milliseconds)
    check:
      writeErr.stage == writeStage
      writeErr.msg == "timed out writing"
      readErr.stage == readStage
      readErr.msg == "timed out waiting for reply"
      hungWrite.wasResetLocally()
      hungRead.wasResetLocally()
      hungWrite.cancels == 1
      hungRead.cancels == 1

  asyncTest "cancelling an RPC mid-write or mid-read resets the stream":
    let hungWrite = FaultStream.new(onWrite = Fault.Hang)
    let hungRead = FaultStream.new(onRead = Fault.Hang)
    defer:
      await hungWrite.close()
      await hungRead.close()

    for stream in [hungWrite, hungRead]:
      let sender = faultSender(stream)
      defer:
        await sender.stop()
      let rpc = sender.requestOverFaultStream(5.seconds)
      await stream.hung.wait()
      await rpc.cancelAndWait()
      await sender.stop()
      check:
        stream.cancels == 1
        stream.wasResetLocally()

  asyncTest "cancelling an RPC queued behind another leaves the lock free":
    let stream = FaultStream.new(onWrite = Fault.Hang)
    let fresh = FaultStream.new(onWrite = Fault.Fail)
    let sender = faultSender(stream)
    defer:
      await sender.stop()
      await stream.close()
      await fresh.close()

    let peerId = randomPeerId()
    let first = sender.sendRequest(peerId, @[], @[byte 1], 5.seconds)
    await stream.hung.wait()
    let queued = sender.sendRequest(peerId, @[], @[byte 2], 5.seconds)
    await queued.cancelAndWait()
    await first.cancelAndWait()

    FaultSwitch(sender.switch).stream = fresh
    let reply = await sender.sendRequest(peerId, @[], @[byte 3], 1.seconds)
    check:
      reply.error().stage == writeStage
      reply.error().msg == "fault stream write failed"

  asyncTest "a reused stream that fails gets one fresh stream":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    let stale = FaultStream.new(onWrite = Fault.Fail)
    defer:
      await sender.stop()
      await stale.close()

    let peerId = server.peerInfo.peerId
    let ps = sender.senderFor(peerId)
    ps.stream = stale

    let reply = await sender.sendRequest(server, @[byte 1], 1.seconds)
    check:
      reply.tryGet() == @[byte 1]
      stale.wasResetLocally()
      ps.reuseFailures == 1
      proto.streams == 1

  asyncTest "closing one of two connections to a peer keeps its stream":
    let proto = newCountingEcho()
    let (client, server) = setupPair(proto)
    startAndDeferStop(@[client, server])

    let sender = MessageSender.new(client, TestCodec, MaxTestMsgSize)
    defer:
      await sender.stop()

    let peerId = server.peerInfo.peerId
    check (await sender.sendRequest(server, @[byte 1], 1.seconds)).isOk()
    let first = client.connManager.getConnections()[peerId]
    await client.connect(
      peerId, server.peerInfo.addrs, forceDial = true, reuseConnection = false
    )
    let second = client.connManager.getConnections()[peerId].filterIt(it notin first)
    require second.len == 1

    let disconnected = Future[void].Raising([CancelledError]).init("disconnected")
    let onDisconnect = proc(
        peerId: PeerId, event: ConnEvent
    ) {.async: (raises: [CancelledError]).} =
      disconnected.completeOnce()
    client.addConnEventHandler(onDisconnect, ConnEventKind.Disconnected)
    defer:
      client.removeConnEventHandler(onDisconnect, ConnEventKind.Disconnected)

    await second[0].connection.close()
    await disconnected
    check:
      client.isConnected(peerId)
      sender.senders.len == 1

    check (await sender.sendRequest(server, @[byte 2], 1.seconds)).isOk()
    check proto.streams == 1
