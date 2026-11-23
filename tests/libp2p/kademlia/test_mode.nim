# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[protocols/kademlia, stream/connection, switch]
import ../../../libp2p/services/reachabilityobservers
import ../../tools/[lifecycle, unittest]
import ./utils

proc dialFindNode(
    querier, target: KadDHT
): Future[Opt[Message]] {.async: (raises: [CancelledError]).} =
  ## Dial the target's Kad codec, send a FIND_NODE and return the reply, or
  ## `Opt.none` when the target refuses to serve (stream reset, no reply).
  let stream =
    try:
      await querier.switch.dial(target.switch, querier.codec)
    except CatchableError:
      return Opt.none(Message)
  defer:
    await stream.close()

  let msg = Message(msgType: Opt.some(MessageType.findNode), key: target.rtable.selfId)
  try:
    await stream.writeLp(msg.encode(querier.config.hideConnectionStatus))
    let replyBuf = await stream.readLp(MaxMsgSize)
    let reply = Message.decode(replyBuf).valueOr:
      return Opt.none(Message)
    # A served query yields a well-formed FIND_NODE reply; anything else is a
    # broken server masquerading as one, so do not count it as served.
    if reply.msgType != MessageType.findNode:
      return Opt.none(Message)
    return Opt.some(reply)
  except CatchableError:
    return Opt.none(Message)

type FakeReachability = ref object
  value: NetworkReachability

const
  TestWindow = 50.milliseconds
  ImmediateAutoMode = AutoModeConfig.init(
    promotionWindow = ZeroDuration,
    demotionWindow = ZeroDuration,
    cooldown = ZeroDuration,
  )
  WindowedAutoMode = AutoModeConfig.init(
    promotionWindow = TestWindow, demotionWindow = TestWindow, cooldown = ZeroDuration
  )
  DemotionWindowedAutoMode = AutoModeConfig.init(
    promotionWindow = ZeroDuration, demotionWindow = TestWindow, cooldown = ZeroDuration
  )
  CooldownAutoMode = AutoModeConfig.init(
    promotionWindow = ZeroDuration,
    demotionWindow = ZeroDuration,
    cooldown = TestWindow * 2,
  )
  UnknownDemotionAutoMode = AutoModeConfig.init(
    promotionWindow = ZeroDuration,
    demotionWindow = ZeroDuration,
    cooldown = ZeroDuration,
    unknownDemotion = Opt.some(TestWindow),
  )

proc setupAutoKad(
    source = FakeReachability(value: NetworkReachability.Unknown),
    config = ImmediateAutoMode,
): KadDHT =
  let kad = setupKad(isServer = false)
  let handler = kad.enableAutoMode(
    proc(): NetworkReachability {.gcsafe, raises: [].} =
      source.value,
    config,
  )
  check handler == kad.autoModeHandler.get()
  kad

proc verdict(
    kad: KadDHT, reachability: NetworkReachability
) {.async: (raises: [CancelledError]).} =
  await kad.autoModeHandler.get()(reachability, Opt.none(float), Opt.none(MultiAddress))

template checkModeAfter(kad: KadDHT, expected: bool, since: Moment, window: Duration) =
  let timer = kad.modeTimer
  check not timer.isNil()
  await timer
  check:
    kad.isServer == expected
    Moment.now() - since >= window

template checkCancelled(timer: Future[void]) =
  await allFutures(timer)
  check timer.cancelled()

suite "KadDHT dynamic mode":
  teardown:
    checkTrackers()

  test "initial mode follows the configured flag":
    check:
      setupKad(isServer = true).isServer
      not setupKad(isServer = false).isServer

  asyncTest "changeMode reports whether the mode changed":
    let kad = setupKad(isServer = false)

    check (await kad.changeMode(isServer = true))
    check kad.isServer

    # The same mode twice changes nothing.
    check not (await kad.changeMode(isServer = true))
    check kad.isServer

    check (await kad.changeMode(isServer = false))
    check not kad.isServer

  asyncTest "server answers queries, client resets them":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    let client = setupKad(isServer = false)
    startAndDeferStop(@[querier, server, client])

    check (await querier.dialFindNode(server)).isSome()
    check (await querier.dialFindNode(client)).isNone()

  asyncTest "downgrade to client mode stops serving and drops peers":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    check (await querier.dialFindNode(server)).isSome()

    check (await server.changeMode(isServer = false))
    check (await querier.dialFindNode(server)).isNone()

    check (await server.changeMode(isServer = true))
    check (await querier.dialFindNode(server)).isSome()

  asyncTest "downgrade resets an in-flight inbound stream":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    let stream = await querier.switch.dial(server.switch, querier.codec)
    defer:
      await stream.close()

    # One round-trip parks the server handler on the next read, so the stream is
    # held open and tracked as a server stream.
    let msg =
      Message(msgType: Opt.some(MessageType.findNode), key: server.rtable.selfId)
    await stream.writeLp(msg.encode(querier.config.hideConnectionStatus))
    discard await stream.readLp(MaxMsgSize)

    checkUntilTimeout:
      server.serverStreams.len == 1

    check (await server.changeMode(isServer = false))
    check server.serverStreams.len == 0

    # The downgrade must reset the parked stream: the querier's next read ends in
    # EOF, not a timeout (a timeout would mean the reset never propagated).
    expect LPStreamEOFError:
      discard await stream.readLp(MaxMsgSize)

  asyncTest "server closes the stream on an undecodable request":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    let stream = await querier.switch.dial(server.switch, querier.codec)
    defer:
      await stream.close()

    let truncated = @[0x0A'u8, 0x05, 0x01]
    check Message.decode(truncated).isErr()

    await stream.writeLp(truncated)
    expect LPStreamEOFError:
      discard await stream.readLp(MaxMsgSize)

  asyncTest "server skips REGISTER and GET_ADS and keeps the stream open":
    let querier = setupKad()
    let server = setupKad(isServer = true)
    startAndDeferStop(@[querier, server])

    let stream = await querier.switch.dial(server.switch, querier.codec)
    defer:
      await stream.close()

    let hide = querier.config.hideConnectionStatus
    for msgType in [MessageType.register, MessageType.getAds]:
      await stream.writeLp(
        Message(msgType: Opt.some(msgType), key: server.rtable.selfId).encode(hide)
      )
    await stream.writeLp(
      Message(msgType: Opt.some(MessageType.findNode), key: server.rtable.selfId).encode(
        hide
      )
    )

    let reply = Message.decode(await stream.readLp(MaxMsgSize))
    check reply.get().msgType == MessageType.findNode

  asyncTest "auto mode ignores a verdict while stopped":
    let kad = setupAutoKad()

    await kad.verdict(NetworkReachability.Reachable)
    check not kad.isServer

    await kad.start()
    await kad.stop()
    await kad.verdict(NetworkReachability.Reachable)
    check not kad.isServer

  asyncTest "auto mode restarts from the current reachability":
    let source = FakeReachability(value: NetworkReachability.Unknown)
    let kad = setupAutoKad(source)
    await kad.start()
    await kad.verdict(NetworkReachability.Reachable)
    check kad.isServer

    await kad.stop()
    await kad.start()
    check not kad.isServer

    # A Reachable verdict that came while stopped is not sent again.
    await kad.stop()
    source.value = NetworkReachability.Reachable
    await kad.start()
    check kad.isServer

    await kad.stop()
    source.value = NetworkReachability.Unknown
    await kad.start()
    defer:
      await kad.stop()
    check not kad.isServer

    await kad.verdict(NetworkReachability.Unknown)
    check not kad.isServer

    await kad.verdict(NetworkReachability.Reachable)
    check kad.isServer

    await kad.verdict(NetworkReachability.NotReachable)
    check not kad.isServer

  asyncTest "auto mode handler stays subscribed once across restarts":
    let kad = setupAutoKad()
    let observers = ReachabilityObservers.new()
    check observers.add(kad.autoModeHandler.get())

    for _ in 0 ..< 2:
      await kad.start()
      await kad.stop()
      # A resubscribe after a restart matches the stored closure.
      check not observers.add(kad.autoModeHandler.get())
    check observers.len() == 1

    await kad.start()
    defer:
      await kad.stop()
    await observers.notify(NetworkReachability.Reachable, Opt.none(float))
    check kad.isServer

    check observers.remove(kad.autoModeHandler.get())
    check observers.len() == 0

  asyncTest "enabling auto mode twice keeps one handler":
    let kad = setupAutoKad()
    let current = proc(): NetworkReachability {.gcsafe, raises: [].} =
      NetworkReachability.Reachable
    let handler = kad.enableAutoMode(current)
    check handler == kad.autoModeHandler.get()

    await kad.start()
    defer:
      await kad.stop()
    check not kad.isServer

  asyncTest "start keeps a fixed mode":
    for isServer in [true, false]:
      let kad = setupKad(isServer = isServer)
      await kad.start()
      await kad.stop()
      await kad.start()
      check kad.isServer == isServer
      await kad.stop()

  asyncTest "auto mode stop cancels a pending promotion":
    let kad = setupAutoKad(config = WindowedAutoMode)
    await kad.start()
    await kad.verdict(NetworkReachability.Reachable)
    let timer = kad.modeTimer
    check:
      not kad.isServer
      not timer.isNil()

    await kad.stop()
    check kad.modeTimer.isNil()
    timer.checkCancelled()
    check not kad.isServer

  asyncTest "auto mode restart counts the window from the new verdict":
    let kad = setupAutoKad(config = WindowedAutoMode)
    await kad.start()
    await kad.verdict(NetworkReachability.Reachable)
    let staleTimer = kad.modeTimer
    await kad.stop()

    await kad.start()
    defer:
      await kad.stop()
    staleTimer.checkCancelled()
    check:
      kad.modeTimer.isNil()
      not kad.isServer

    let verdictAt = Moment.now()
    await kad.verdict(NetworkReachability.Reachable)
    kad.checkModeAfter(expected = true, verdictAt, TestWindow)

  asyncTest "auto mode start waits the window on a current Reachable":
    let source = FakeReachability(value: NetworkReachability.Reachable)
    let kad = setupAutoKad(source, WindowedAutoMode)
    let startAt = Moment.now()
    await kad.start()
    defer:
      await kad.stop()
    check not kad.isServer

    kad.checkModeAfter(expected = true, startAt, TestWindow)
    check kad.modeTimer.isNil()

  asyncTest "auto mode drops the timer when the verdict reverts":
    let kad = setupAutoKad(config = WindowedAutoMode)
    await kad.start()
    defer:
      await kad.stop()
    await kad.verdict(NetworkReachability.Reachable)
    let timer = kad.modeTimer
    check not timer.isNil()

    await kad.verdict(NetworkReachability.NotReachable)
    check kad.modeTimer.isNil()
    timer.checkCancelled()
    check not kad.isServer

  asyncTest "a fixed mode creates no timer":
    for isServer in [true, false]:
      let kad = setupKad(isServer = isServer)
      await kad.start()
      check (await kad.changeMode(not isServer))
      check kad.modeTimer.isNil()
      await kad.stop()

  asyncTest "auto mode demotes a server only after the window and resets queries":
    let querier = setupKad()
    let kad = setupAutoKad(config = DemotionWindowedAutoMode)
    startAndDeferStop(@[querier, kad])
    await kad.verdict(NetworkReachability.Reachable)
    check kad.isServer
    check (await querier.dialFindNode(kad)).isSome()

    let verdictAt = Moment.now()
    await kad.verdict(NetworkReachability.NotReachable)
    check:
      kad.isServer
      not kad.modeTimer.isNil()

    kad.checkModeAfter(expected = false, verdictAt, TestWindow)
    check (await querier.dialFindNode(kad)).isNone()

  asyncTest "auto mode cooldown delays a second change past the window":
    let kad = setupAutoKad(config = CooldownAutoMode)
    await kad.start()
    defer:
      await kad.stop()

    let promotedAt = Moment.now()
    await kad.verdict(NetworkReachability.Reachable)
    check kad.isServer

    await kad.verdict(NetworkReachability.NotReachable)
    check:
      kad.isServer
      not kad.modeTimer.isNil()

    kad.checkModeAfter(expected = false, promotedAt, TestWindow * 2)

  asyncTest "auto mode demotes a server after Unknown holds for the window":
    let kad = setupAutoKad(config = UnknownDemotionAutoMode)
    await kad.start()
    defer:
      await kad.stop()
    await kad.verdict(NetworkReachability.Reachable)
    check kad.isServer

    let verdictAt = Moment.now()
    await kad.verdict(NetworkReachability.Unknown)
    check:
      kad.isServer
      not kad.modeTimer.isNil()

    kad.checkModeAfter(expected = false, verdictAt, TestWindow)

  asyncTest "auto mode applies verdicts in arrival order":
    let kad = setupAutoKad(config = WindowedAutoMode)
    await kad.start()
    defer:
      await kad.stop()
    await kad.verdict(NetworkReachability.Reachable)
    let timer = kad.modeTimer
    check not timer.isNil()

    # Both verdicts run in order, so the newer NotReachable wins.
    let older = kad.verdict(NetworkReachability.Reachable)
    let newer = kad.verdict(NetworkReachability.NotReachable)
    await allFutures(older, newer)
    check kad.modeTimer.isNil()
    timer.checkCancelled()
    check not kad.isServer

  asyncTest "auto mode keeps a manual change made during a pending change":
    for isServer in [true, false]:
      let kad = setupAutoKad(config = WindowedAutoMode)
      await kad.start()
      if not isServer:
        check (await kad.changeMode(isServer = true))
      let verdict =
        if isServer: NetworkReachability.Reachable else: NetworkReachability.NotReachable
      await kad.verdict(verdict)
      let timer = kad.modeTimer
      check not timer.isNil()

      check (await kad.changeMode(isServer))
      await timer
      check kad.isServer == isServer
      await kad.stop()
