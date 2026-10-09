# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import
  ../../../libp2p/[
    transports/tcptransport,
    upgrademngrs/upgrade,
    builders,
    protocols/connectivity/autonat/client,
    protocols/connectivity/autonat/server,
    nameresolving/nameresolver,
    nameresolving/mockresolver,
  ]
import ../../tools/[unittest, switch_builder, multiaddress]

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
    let buffer = AutonatMsg(
      msgType: Opt.some(MsgType.Dial),
      dial: Opt.some(
        AutonatDial(
          peerInfo: Opt.some(
            AutonatPeerInfo(
              id: Opt.some(src.peerInfo.peerId),
              # we ask to be dialed in the does nothing listener instead
              addrs: doesNothingListener.addrs,
            )
          )
        )
      ),
    ).encode()
    await stream.writeLp(buffer)
    let response = AutonatMsg.decode(await stream.readLp(1024)).get().response.get()
    check:
      response.status == Opt.some(DialError)
      response.text.get() == "Dial timeout"
      response.ma.isNone()
    await allFutures(doesNothingListener.stop(), src.stop(), dst.stop())

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
    check response.status == Opt.some(DialError)
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
