# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[importutils, sequtils]
import chronos
import
  ../../../libp2p/[
    transports/tcptransport,
    upgrademngrs/upgrade,
    builders,
    protocols/connectivity/autonat/client,
    protocols/connectivity/autonat/server,
    stream/bufferstream,
    utils/future,
    nameresolving/nameresolver,
    nameresolving/mockresolver,
  ]
import ../../tools/[unittest, crypto, bufferstream, switch_builder, multiaddress]

proc makeAutonatSwitch(nameResolver: NameResolver = nil): Switch =
  return makeStandardSwitchBuilder(TcpAutoAddress)
    .withAutonat()
    .withNameResolver(nameResolver)
    .build()

proc makeSwitch(): Switch =
  return makeStandardSwitch(TcpAutoAddress)

proc makeAutonatServicePrivate(): Switch =
  var autonatProtocol = new LPProtocol
  autonatProtocol.handler = proc(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      discard await stream.readLp(1024)
      await stream.writeLp(
        AutonatMsg(
          msgType: Opt.some(MsgType.DialResponse),
          response: Opt.some(
            AutonatDialResponse(
              status: Opt.some(DialError),
              text: Opt.some("dial failed"),
              ma: Opt.none(MultiAddress),
            )
          ),
        ).encode()
      )
    except LPStreamError:
      raiseAssert "Unexpected LPStreamError in autonat private service handler"
    finally:
      await stream.close()
  autonatProtocol.codec = AutonatCodec
  let switch = makeSwitch()
  switch.mount(autonatProtocol)
  switch

proc dialRequest(peerId: PeerId, addrs: seq[MultiAddress]): seq[byte] =
  AutonatMsg(
    msgType: Opt.some(MsgType.Dial),
    dial: Opt.some(
      AutonatDial(
        peerInfo: Opt.some(AutonatPeerInfo(id: Opt.some(peerId), addrs: addrs))
      )
    ),
  ).encode()

type SilentRemote = object
  server: StreamServer
  ma: MultiAddress
  accepted: Future[void]
  release: AsyncEvent

proc newSilentRemote(): SilentRemote =
  let
    accepted = newFuture[void]("autonat.test.accepted")
    release = newAsyncEvent()

  # The remote accepts and never speaks, so a dial to it holds its permit.
  proc onAccept(server: StreamServer, client: StreamTransport) {.async: (raises: []).} =
    accepted.completeOnce()
    await noCancel release.wait()
    await client.closeWait()

  let server = createStreamServer(initTAddress("127.0.0.1:0"), onAccept, {ReuseAddr})
  server.start()
  SilentRemote(
    server: server,
    ma: MultiAddress.init(server.local).tryGet(),
    accepted: accepted,
    release: release,
  )

proc stop(remote: SilentRemote) {.async.} =
  remote.release.fire()
  remote.server.stop()
  await remote.server.closeWait()

suite "Autonat":
  teardown:
    checkTrackers()

  asyncTest "dialMe returns public address":
    let
      src = makeSwitch()
      dst = makeAutonatSwitch()
    await src.start()
    await dst.start()

    await src.connect(dst)
    let maddr =
      await AutonatClient.new().dialMe(src, dst.peerInfo.peerId, dst.peerInfo.addrs)
    check maddr in src.peerInfo.addrs
    await allFutures(src.stop(), dst.stop())

  asyncTest "dialMe handles dial error msg":
    let
      src = makeSwitch()
      dst = makeAutonatServicePrivate()

    await src.start()
    await dst.start()

    await src.connect(dst)
    expect AutonatUnreachableError:
      discard
        await AutonatClient.new().dialMe(src, dst.peerInfo.peerId, dst.peerInfo.addrs)
    await allFutures(src.stop(), dst.stop())

  asyncTest "Timeout is triggered in autonat handle":
    let
      src = makeSwitch()
      dst = makeSwitch()
      autonat = Autonat.new(dst, dialTimeout = 1.seconds)
      doesNothingListener = TcpTransport.new(upgrade = Upgrade())

    dst.mount(autonat)
    await src.start()
    await dst.start()
    await doesNothingListener.start(@[TcpWildcardAddress])

    await src.connect(dst)
    let stream = await src.dial(dst.peerInfo.peerId, @[AutonatCodec])
    # we ask to be dialed in the does nothing listener instead
    await stream.writeLp(dialRequest(src.peerInfo.peerId, doesNothingListener.addrs))
    let response = AutonatMsg.decode(await stream.readLp(1024)).get().response.get()
    check:
      response.status == DialError
      response.text == "Dial timeout"
      response.ma.isNone()
    await allFutures(doesNothingListener.stop(), src.stop(), dst.stop())

  asyncTest "Silent dial targets of one peer do not block another peer":
    const
      dialTimeout = 3.seconds
      floodStreams = 5
    let
      flooder = makeSwitch()
      honest = makeSwitch()
      dst = makeSwitch()
      remote = newSilentRemote()

    dst.mount(Autonat.new(dst, dialTimeout = dialTimeout))
    await allFutures(flooder.start(), honest.start(), dst.start())
    await flooder.connect(dst)
    await honest.connect(dst)

    let request = dialRequest(flooder.peerInfo.peerId, @[remote.ma])
    var floodStreamsOpened: seq[Stream]
    let first = await flooder.dial(dst.peerInfo.peerId, @[AutonatCodec])
    floodStreamsOpened.add(first)
    try:
      await first.writeLp(request)
    except LPStreamError as e:
      raiseAssert "first flood stream must be admitted: " & e.msg
    for _ in 1 ..< floodStreams:
      let stream = await flooder.dial(dst.peerInfo.peerId, @[AutonatCodec])
      floodStreamsOpened.add(stream)
      # the per-peer stream limit rejects all but the first stream
      expect LPStreamError:
        await stream.writeLp(request)
        discard await stream.readLp(1024)
    # optimistic negotiation sends no round trip, so wait until a flood dial holds the permit
    await remote.accepted

    let
      start = Moment.now()
      stream = await honest.dial(dst.peerInfo.peerId, @[AutonatCodec])
    await stream.writeLp(dialRequest(honest.peerInfo.peerId, honest.peerInfo.addrs))
    let response = AutonatMsg.decode(await stream.readLp(1024)).get().response.get()
    check:
      Moment.now() - start < dialTimeout
      response.status == DialRefused
      response.text == "Too many concurrent dials"

    await remote.stop()
    await allFutures(floodStreamsOpened.mapIt(it.close()))
    await stream.close()
    await allFutures(flooder.stop(), honest.stop(), dst.stop())

  test "Default stream limits admit one stream per peer and eight in total":
    let
      autonat = Autonat.new(nil)
      peers = PeerId.random(DefaultMaxIncomingStreamsTotal)
      extraPeer = PeerId.random()

    for peer in peers:
      check autonat.reserveIncoming(peer)
    check:
      not autonat.reserveIncoming(peers[0]) # per peer limit
      not autonat.reserveIncoming(extraPeer) # total limit

    autonat.releaseIncoming(peers[0])
    check autonat.reserveIncoming(extraPeer)

  test "A semaphore above the default raises the total stream limit to match":
    const semSize = DefaultMaxIncomingStreamsTotal * 2
    let
      autonat = Autonat.new(nil, semSize = semSize)
      peers = PeerId.random(semSize)

    for peer in peers:
      check autonat.reserveIncoming(peer)
    check not autonat.reserveIncoming(PeerId.random()) # total limit

  asyncTest "Dial is refused when no dial permit is free":
    let
      autonat = Autonat.new(nil, semSize = 1)
      peerId = PeerId.random()
      responses = BufferStream.new()
      stream = TestBufferStream.new(
        proc(
            data: sink seq[byte]
        ) {.async: (raises: [CancelledError, LPStreamError]).} =
          await responses.pushData(data)
      )
    stream.peerId = peerId
    stream.observedAddr = Opt.some(MultiAddress.init("/ip4/1.2.3.4/tcp/4040").tryGet())
    privateAccess(Autonat)
    check autonat.sem.tryAcquire()

    let handled = autonat.handler(stream, AutonatCodec)
    await stream.pushData(dialRequest(peerId, @[]))
    let response = AutonatMsg.decode(await responses.readLp(1024)).get().response.get()
    check:
      response.status == DialRefused
      response.text == "Too many concurrent dials"
      response.ma.isNone()

    await handled
    await responses.close()

  asyncTest "Message without type is handled as Dial":
    let
      src = makeSwitch()
      dst = makeSwitch()
      autonat = Autonat.new(dst, dialTimeout = 1.seconds)
      doesNothingListener = TcpTransport.new(upgrade = Upgrade())

    dst.mount(autonat)
    await src.start()
    await dst.start()
    await doesNothingListener.start(@[TcpWildcardAddress])

    await src.connect(dst)
    let stream = await src.dial(dst.peerInfo.peerId, @[AutonatCodec])
    let buffer = AutonatMsg(
      dial: Opt.some(
        AutonatDial(
          peerInfo: Opt.some(
            AutonatPeerInfo(
              id: Opt.some(src.peerInfo.peerId), addrs: doesNothingListener.addrs
            )
          )
        )
      )
    ).encode()
    await stream.writeLp(buffer)
    # the server replies instead of erroring out on the absent type
    let response = AutonatMsg.decode(await stream.readLp(1024)).get().response.get()
    check response.status == DialError
    await allFutures(doesNothingListener.stop(), src.stop(), dst.stop())

  asyncTest "dialMe dials dns and returns public address":
    let
      src = makeSwitch()
      dst = makeAutonatSwitch(nameResolver = MockResolver.default())

    await src.start()
    await dst.start()

    let testAddr = ma("/dns4/localhost/") & dst.peerInfo.addrs[0][1].tryGet()

    await src.connect(dst)
    let maddr = await AutonatClient.new().dialMe(src, dst.peerInfo.peerId, @[testAddr])

    check maddr in src.peerInfo.addrs
    await allFutures(src.stop(), dst.stop())
