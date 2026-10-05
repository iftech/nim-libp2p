{.used.}

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, net, sequtils
import
  ../../../libp2p/[
    switch,
    protocols/protocol,
    multiaddress,
    transports/tcptransport,
    upgrademngrs/upgrade,
    builders,
    protocols/connectivity/autonatv2/types,
    protocols/connectivity/autonatv2/server,
    protocols/connectivity/autonatv2/utils,
    protocols/connectivity/autonatv2/client,
    protocols/connectivity/autonatv2/mockserver,
  ]
import ../../tools/[unittest, crypto, switch_builder, multiaddress]

proc startAndConnect(src, dst: Switch, client: AutonatV2Client) {.async.} =
  client.setup(src)
  src.mount(client)
  await src.start()
  await dst.start()
  await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)

proc setupAutonat(
    srcAddrs: seq[MultiAddress] = @[TcpAutoAddress],
    dstAddrs: seq[MultiAddress] = @[TcpAutoAddress],
    config: AutonatV2Config = AutonatV2Config.new(),
): Future[(Switch, Switch, AutonatV2Client)] {.async.} =
  let
    src = makeStandardSwitchBuilder(srcAddrs).build()
    dst = makeStandardSwitchBuilder(dstAddrs).withAutonatV2Server(config).build()
    client = AutonatV2Client.new(rng())

  await startAndConnect(src, dst, client)
  (src, dst, client)

proc checkedGetIPAddress(): string =
  try:
    $getPrimaryIPAddr()
  except Exception:
    ""

proc newDialbackSwitch(transport: string): Switch =
  if transport == "yamux":
    return SwitchBuilder
      .new()
      .withRng(rng())
      .withNoise()
      .withAddress(TcpAutoAddress)
      .withTcpTransport()
      .withYamux()
      .build()
  let address = if transport == "quic": QuicAutoAddress else: TcpAutoAddress
  makeStandardSwitch(address)

template dialbackConnectionTest(transport, scenario: string) =
  let
    src = newDialbackSwitch(transport)
    dst = newDialbackSwitch(transport)
    fresh = scenario == "fresh identity"
    separatePeer = fresh or scenario == "fresh outbound"
    backPeer =
      if separatePeer:
        newDialbackSwitch(transport)
      else:
        dst
    client = AutonatV2Client.new(rng())
  var acknowledged = false

  proc sendBack(nonce: Nonce): Future[bool] {.async.} =
    if fresh:
      await backPeer.connect(src.peerInfo.peerId, src.peerInfo.addrs)
    elif scenario == "fresh outbound":
      await src.connect(backPeer.peerInfo.peerId, backPeer.peerInfo.addrs)
    let back =
      await backPeer.dialer.dial(src.peerInfo.peerId, @[$AutonatV2Codec.DialBack])
    defer:
      await back.close()
      if separatePeer:
        await backPeer.disconnect(src.peerInfo.peerId)
    await back.writeLp(DialBack(nonce: nonce).encode())
    try:
      let response = await back.readLp(AutonatV2MsgLpSize)
      return DialBackResponse.decode(response).isOk
    except LPStreamError:
      return false

  proc handleRequest(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()
    try:
      let req = AutonatV2Msg
        .decode(await stream.readLp(AutonatV2MsgLpSize))
        .get().oneof.dialRequest
      if fresh:
        check not await sendBack(req.nonce xor 1)
      acknowledged = await sendBack(req.nonce)
      if fresh:
        # A second fresh connection must not overwrite an accepted proof.
        check not await sendBack(req.nonce)
      await stream.writeLp(
        AutonatV2Msg(
          oneof: AutonatV2MsgOneof(
            kind: MsgKind.DialResponse,
            dialResponse: DialResponse(
              status: ResponseStatus.Ok,
              addrIdx: Opt.some(0.AddrIdx),
              dialStatus: Opt.some(DialStatus.Ok),
            ),
          )
        ).encode()
      )
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raiseAssert exc.msg

  let verifier = LPProtocol()
  verifier.handler = handleRequest
  verifier.codec = $AutonatV2Codec.DialRequest
  dst.mount(verifier)
  client.setup(src)
  src.mount(client)
  await src.start()
  await dst.start()
  if separatePeer:
    await backPeer.start()
  defer:
    if separatePeer:
      await backPeer.stop()
    await allFutures(src.stop(), dst.stop())
  if scenario == "existing inbound":
    await dst.connect(src.peerInfo.peerId, src.peerInfo.addrs)
  else:
    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)

  if fresh:
    let response = await client.sendDialRequest(dst.peerInfo.peerId, src.peerInfo.addrs)
    check response.reachability == Reachable
    check acknowledged
  else:
    # The verifier claims success without ever dialing this endpoint.
    let unreachable =
      if transport == "quic":
        ma("/ip4/192.0.2.1/udp/1/quic-v1")
      else:
        ma("/ip4/192.0.2.1/tcp/1")
    expect AutonatV2Error:
      discard await client.sendDialRequest(dst.peerInfo.peerId, @[unreachable])
    check not acknowledged

suite "AutonatV2":
  teardown:
    checkTrackers()

  asyncTest "asNetworkReachability":
    check asNetworkReachability(DialResponse(status: EInternalError)) == Unknown
    check asNetworkReachability(DialResponse(status: ERequestRejected)) == Unknown
    check asNetworkReachability(DialResponse(status: EDialRefused)) == Unknown
    check asNetworkReachability(
      DialResponse(status: ResponseStatus.Ok, dialStatus: Opt.none(DialStatus))
    ) == Unknown
    check asNetworkReachability(
      DialResponse(status: ResponseStatus.Ok, dialStatus: Opt.some(Unused))
    ) == Unknown
    check asNetworkReachability(
      DialResponse(status: ResponseStatus.Ok, dialStatus: Opt.some(EDialError))
    ) == NotReachable
    check asNetworkReachability(
      DialResponse(status: ResponseStatus.Ok, dialStatus: Opt.some(EDialBackError))
    ) == NotReachable
    check asNetworkReachability(
      DialResponse(status: ResponseStatus.Ok, dialStatus: Opt.some(DialStatus.Ok))
    ) == Reachable

  asyncTest "asAutonatV2Response":
    let addrs = @[ma("/ip4/127.0.0.1/tcp/4000")]
    let errorDialResp = DialResponse(
      status: ResponseStatus.Ok,
      addrIdx: Opt.none(AddrIdx),
      dialStatus: Opt.none(DialStatus),
    )
    check asAutonatV2Response(errorDialResp, addrs) ==
      AutonatV2Response(
        reachability: Unknown, dialResp: errorDialResp, addrs: Opt.none(MultiAddress)
      )

    let correctDialResp = DialResponse(
      status: ResponseStatus.Ok,
      addrIdx: Opt.some(0.AddrIdx),
      dialStatus: Opt.some(DialStatus.Ok),
    )
    check asAutonatV2Response(correctDialResp, addrs) ==
      AutonatV2Response(
        reachability: Reachable, dialResp: correctDialResp, addrs: Opt.some(addrs[0])
      )

    let missingAddrDialResp = DialResponse(
      status: ResponseStatus.Ok,
      addrIdx: Opt.some(1.AddrIdx),
      dialStatus: Opt.none(DialStatus),
    )
    check asAutonatV2Response(missingAddrDialResp, addrs) ==
      AutonatV2Response(
        reachability: Unknown,
        dialResp: missingAddrDialResp,
        addrs: Opt.none(MultiAddress),
      )

  asyncTest "Instantiate server":
    let serverSwitch = makeStandardSwitchBuilder().withAutonatV2Server().build()
    await serverSwitch.start()
    await serverSwitch.stop()

  asyncTest "Instantiate server with config":
    let serverSwitch = makeStandardSwitchBuilder()
      .withAutonatV2Server(AutonatV2Config.new(allowPrivateAddresses = true))
      .build()

    await serverSwitch.start()
    await serverSwitch.stop()

  asyncTest "Successful DialRequest":
    let (src, dst, client) =
      await setupAutonat(config = AutonatV2Config.new(allowPrivateAddresses = true))
    defer:
      await allFutures(src.stop(), dst.stop())

    check (await client.sendDialRequest(dst.peerInfo.peerId, src.peerInfo.addrs)) ==
      AutonatV2Response(
        reachability: Reachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.Ok),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(src.peerInfo.addrs[0]),
      )

  for transport in ["mplex", "yamux", "quic"]:
    for scenario in [
      "existing outbound", "existing inbound", "fresh outbound", "fresh identity"
    ]:
      # the asyncTest closure cannot capture the lent loop variables
      let
        transport = transport
        scenario = scenario
      asyncTest "DialBack connection binding: " & transport & ", " & scenario:
        dialbackConnectionTest(transport, scenario)

  asyncTest "Successful DialRequest with amplification attack prevention":
    # use ip address other than 127.0.0.1 for client
    let
      listenAddrs = @[
        ma("/ip4/" & checkedGetIPAddress() & "/tcp/4040"), ma("/ip4/127.0.0.1/tcp/4040")
      ]
      reqAddrs = @[listenAddrs[0]]
      (src, dst, client) = await setupAutonat(
        srcAddrs = listenAddrs,
        config = AutonatV2Config.new(allowPrivateAddresses = true),
      )
    defer:
      await allFutures(src.stop(), dst.stop())

    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: Reachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.Ok),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(src.peerInfo.addrs[0]),
      )

  asyncTest "Failed DialRequest":
    let (src, dst, client) =
      await setupAutonat(config = AutonatV2Config.new(dialTimeout = 1.seconds))
    defer:
      await allFutures(src.stop(), dst.stop())

    check (
      await client.sendDialRequest(dst.peerInfo.peerId, @[ma("/ip4/1.1.1.1/tcp/4040")])
    ) ==
      AutonatV2Response(
        reachability: NotReachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.EDialError),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(ma("/ip4/1.1.1.1/tcp/4040")),
      )

  asyncTest "Failed DialRequest with amplification attack prevention":
    # use ip address other than 127.0.0.1 for client
    let
      listenAddrs = @[
        ma("/ip4/" & checkedGetIPAddress() & "/tcp/4040"), ma("/ip4/127.0.0.1/tcp/4040")
      ]
      reqAddrs = @[ma("/ip4/1.1.1.1/tcp/4040")]
      (src, dst, client) = await setupAutonat(
        srcAddrs = listenAddrs, config = AutonatV2Config.new(dialTimeout = 1.seconds)
      )
    defer:
      await allFutures(src.stop(), dst.stop())

    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: NotReachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.EDialError),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(reqAddrs[0]),
      )

  asyncTest "DialRequest with IPv6 addr refused by IPv4-only server":
    # server listens on IPv4 only, so it refuses to dial any IPv6 addr
    let (src, dst, client) = await setupAutonat()
    defer:
      await allFutures(src.stop(), dst.stop())

    let reqAddrs = @[ma("/ip6/2001:db8::1/tcp/4040")]
    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: Unknown,
        dialResp: DialResponse(
          status: EDialRefused,
          addrIdx: Opt.none(AddrIdx),
          dialStatus: Opt.none(DialStatus),
        ),
        addrs: Opt.none(MultiAddress),
      )

  asyncTest "DialRequest with IPv4 addr refused by IPv6-only server":
    # server listens on IPv6 only, so it refuses to dial any IPv4 addr
    let (src, dst, client) = await setupAutonat(dstAddrs = @[TcpAutoAddressIP6])
    defer:
      await allFutures(src.stop(), dst.stop())

    let reqAddrs = @[ma("/ip4/1.1.1.1/tcp/4040")]
    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: Unknown,
        dialResp: DialResponse(
          status: EDialRefused,
          addrIdx: Opt.none(AddrIdx),
          dialStatus: Opt.none(DialStatus),
        ),
        addrs: Opt.none(MultiAddress),
      )

  asyncTest "DialRequest with private IPv6 addr refused by default":
    let
      dualStackAddrs = @[TcpAutoAddressIP4, TcpAutoAddressIP6]
      (src, dst, client) =
        await setupAutonat(srcAddrs = dualStackAddrs, dstAddrs = dualStackAddrs)
    defer:
      await allFutures(src.stop(), dst.stop())

    # request only the IPv6 listen addr of the client
    let reqAddrs = src.peerInfo.addrs.filterIt(TCP_IP6.match(it))
    check reqAddrs.len == 1

    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: Unknown,
        dialResp: DialResponse(
          status: EDialRefused,
          addrIdx: Opt.none(AddrIdx),
          dialStatus: Opt.none(DialStatus),
        ),
        addrs: Opt.none(MultiAddress),
      )

  asyncTest "DialRequest with private IPv6 addr accepted with allowPrivateAddresses=true":
    let
      dualStackAddrs = @[TcpAutoAddressIP4, TcpAutoAddressIP6]
      (src, dst, client) = await setupAutonat(
        srcAddrs = dualStackAddrs,
        dstAddrs = dualStackAddrs,
        config = AutonatV2Config.new(allowPrivateAddresses = true),
      )
    defer:
      await allFutures(src.stop(), dst.stop())

    let reqAddrs = src.peerInfo.addrs.filterIt(TCP_IP6.match(it))
    check reqAddrs.len == 1

    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: Reachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.Ok),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(reqAddrs[0]),
      )

  asyncTest "DialRequest with a DNS addr refused by default":
    let (src, dst, client) = await setupAutonat()
    defer:
      await allFutures(src.stop(), dst.stop())

    # a name has no IP until the server resolves it, so it is never dialed back
    let reqAddrs = @[ma("/dns4/localhost/tcp/4040")]
    check (await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)) ==
      AutonatV2Response(
        reachability: Unknown,
        dialResp: DialResponse(
          status: EDialRefused,
          addrIdx: Opt.none(AddrIdx),
          dialStatus: Opt.none(DialStatus),
        ),
        addrs: Opt.none(MultiAddress),
      )

  asyncTest "Amplification attack prevention skipped when observed IPv4 addr matches a requested addr":
    # the requested addr matches the observed addr of the client,
    # so the server dials back right away without demanding dial data
    # dialDataSize is set above what the client accepts to prove the skip:
    # a DialDataRequest would have failed the request with AutonatV2Error
    let (src, dst, client) = await setupAutonat(
      config = AutonatV2Config.new(
        dialDataSize = (MaxAcceptedDialDataRequest + 1).uint64,
        allowPrivateAddresses = true,
      )
    )
    defer:
      await allFutures(src.stop(), dst.stop())

    check (await client.sendDialRequest(dst.peerInfo.peerId, src.peerInfo.addrs)) ==
      AutonatV2Response(
        reachability: Reachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.Ok),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(src.peerInfo.addrs[0]),
      )

  asyncTest "Amplification attack prevention skipped when observed IPv6 addr matches a requested addr":
    # dialDataSize above the client cap proves the skip: a DialDataRequest would fail with AutonatV2Error
    let
      ipv6Addrs = @[TcpAutoAddressIP6]
      (src, dst, client) = await setupAutonat(
        srcAddrs = ipv6Addrs,
        dstAddrs = ipv6Addrs,
        config = AutonatV2Config.new(
          dialDataSize = (MaxAcceptedDialDataRequest + 1).uint64,
          allowPrivateAddresses = true,
        ),
      )
    defer:
      await allFutures(src.stop(), dst.stop())

    check (await client.sendDialRequest(dst.peerInfo.peerId, src.peerInfo.addrs)) ==
      AutonatV2Response(
        reachability: Reachable,
        dialResp: DialResponse(
          status: ResponseStatus.Ok,
          dialStatus: Opt.some(DialStatus.Ok),
          addrIdx: Opt.some(0.AddrIdx),
        ),
        addrs: Opt.some(src.peerInfo.addrs[0]),
      )

  asyncTest "Amplification attack prevention runs before the dial back":
    # the client refuses to pay dial data, so the server must not dial it back
    let
      listenAddrs = @[
        ma("/ip4/" & checkedGetIPAddress() & "/tcp/4040"), ma("/ip4/127.0.0.1/tcp/4040")
      ]
      reqAddrs = @[listenAddrs[0]]
      (src, dst, client) = await setupAutonat(
        srcAddrs = listenAddrs,
        config = AutonatV2Config.new(
          dialDataSize = (MaxAcceptedDialDataRequest + 1).uint64,
          allowPrivateAddresses = true,
        ),
      )
    defer:
      await allFutures(src.stop(), dst.stop())

    expect(AutonatV2Error):
      discard await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)

    check src.connManager.connCount(dst.peerInfo.peerId) == 1

  asyncTest "Failed dial-back negotiation closes the new connection":
    let
      src = makeStandardSwitchBuilder(@[TcpAutoAddress]).build()
      dst = makeStandardSwitchBuilder(@[TcpAutoAddress])
        .withAutonatV2Server(AutonatV2Config.new(allowPrivateAddresses = true))
        .build()
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())
    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)
    let stream =
      await src.dialer.dial(dst.peerInfo.peerId, @[$AutonatV2Codec.DialRequest])
    defer:
      await stream.close()
    await stream.writeLp(
      AutonatV2Msg(
        oneof: AutonatV2MsgOneof(
          kind: MsgKind.DialRequest,
          dialRequest: DialRequest(addrs: src.peerInfo.addrs, nonce: 0.Nonce),
        )
      ).encode()
    )
    let response = AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).get()
    check response.oneof.dialResponse.dialStatus == Opt.some(DialStatus.EDialError)
    checkUntilTimeout:
      src.connManager.connCount(dst.peerInfo.peerId) == 1

  asyncTest "Malformed dial data refuses the dial back":
    let (src, dst, client) = await setupAutonat(
      config =
        AutonatV2Config.new(allowPrivateAddresses = true, dialTimeout = 50.milliseconds)
    )
    defer:
      await allFutures(src.stop(), dst.stop())
    let stream =
      await src.dialer.dial(dst.peerInfo.peerId, @[$AutonatV2Codec.DialRequest])
    defer:
      await stream.close()
    let request = AutonatV2Msg(
      oneof: AutonatV2MsgOneof(
        kind: MsgKind.DialRequest,
        dialRequest: DialRequest(addrs: @[ma("/ip4/127.0.0.2/tcp/1")], nonce: 0.Nonce),
      )
    ).encode()
    await stream.writeLp(request)
    let challenge = AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).get()
    check challenge.oneof.kind == MsgKind.DialDataRequest
    # A second request does not satisfy the dial-data challenge.
    await stream.writeLp(request)
    let response = AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).get()
    check:
      response.oneof.kind == MsgKind.DialResponse
      response.oneof.dialResponse.status == EDialRefused
      response.oneof.dialResponse.dialStatus.isNone

  asyncTest "DialRequest refused when every dial back permit is taken":
    let (src, dst, client) = await setupAutonat(
      config = AutonatV2Config.new(
        maxConcurrentDialBacks = 1,
        maxConcurrentRequestsPerPeer = 2,
        allowPrivateAddresses = true,
        amplificationAttackTimeout = 1.minutes,
      )
    )
    defer:
      await allFutures(src.stop(), dst.stop())

    # the server holds its only permit while it waits for dial data that never comes
    let holdingStream =
      await src.dialer.dial(dst.peerInfo.peerId, @[$AutonatV2Codec.DialRequest])
    defer:
      await holdingStream.close()

    await holdingStream.writeLp(
      AutonatV2Msg(
        oneof: AutonatV2MsgOneof(
          kind: MsgKind.DialRequest,
          dialRequest:
            DialRequest(addrs: @[ma("/ip4/1.1.1.1/tcp/4040")], nonce: 0.Nonce),
        )
      ).encode()
    )
    let held = AutonatV2Msg.decode(await holdingStream.readLp(AutonatV2MsgLpSize)).valueOr:
      raiseAssert "expected a DialDataRequest: " & error
    check held.oneof.kind == MsgKind.DialDataRequest

    check (await client.sendDialRequest(dst.peerInfo.peerId, src.peerInfo.addrs)) ==
      AutonatV2Response(
        reachability: Unknown,
        dialResp: DialResponse(
          status: EDialRefused,
          addrIdx: Opt.none(AddrIdx),
          dialStatus: Opt.none(DialStatus),
        ),
        addrs: Opt.none(MultiAddress),
      )
    check src.connManager.connCount(dst.peerInfo.peerId) == 1

  test "Concurrent DialRequests are capped per peer and in total":
    let
      dst = makeStandardSwitch()
      autonatServer = server.AutonatV2.new(
        dst,
        AutonatV2Config.new(
          maxConcurrentRequestsPerPeer = 1, maxConcurrentRequestsTotal = 2
        ),
      )
      peerA = PeerId.random(rng()).get()
      peerB = PeerId.random(rng()).get()
      peerC = PeerId.random(rng()).get()

    check:
      autonatServer.reserveIncoming(peerA)
      not autonatServer.reserveIncoming(peerA)
      autonatServer.reserveIncoming(peerB)
      not autonatServer.reserveIncoming(peerC)

    autonatServer.releaseIncoming(peerA)
    check autonatServer.canAcceptIncoming(peerA)

  asyncTest "Server responding with invalid messages":
    let
      src = makeStandardSwitch()
      dst = makeStandardSwitch()
      client = AutonatV2Client.new(rng())
      autonatV2Mock = AutonatV2Mock.new()
      reqAddrs = @[ma("/ip4/127.0.0.1/tcp/4040")]

    client.setup(src)
    dst.mount(autonatV2Mock)
    src.mount(client)
    await src.start()
    await dst.start()
    defer:
      await allFutures(src.stop(), dst.stop())

    await src.connect(dst.peerInfo.peerId, dst.peerInfo.addrs)

    # 1. invalid autonatv2msg
    autonatV2Mock.response = DialBackResponse(status: DialBackStatus.Ok).encode()
    expect(AutonatV2Error):
      discard await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)

    # 2. msg that is not DialResponse or DialDataRequest
    autonatV2Mock.response = AutonatV2Msg(
      oneof: AutonatV2MsgOneof(
        kind: MsgKind.DialRequest, dialRequest: DialRequest(addrs: @[], nonce: 0.uint64)
      )
    ).encode()
    expect(AutonatV2Error):
      discard await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)

    # 3. invalid addrIdx (e.g. 1000 when only 1 is present)
    autonatV2Mock.response = AutonatV2Msg(
      oneof: AutonatV2MsgOneof(
        kind: MsgKind.DialResponse,
        dialResponse: DialResponse(
          status: ResponseStatus.Ok,
          addrIdx: Opt.some(1000.AddrIdx),
          dialStatus: Opt.some(DialStatus.Ok),
        ),
      )
    ).encode()
    expect(AutonatV2Error):
      discard await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)

    # 4. omitted addrIdx must still validate as index 0
    autonatV2Mock.response = AutonatV2Msg(
      oneof: AutonatV2MsgOneof(
        kind: MsgKind.DialResponse,
        dialResponse: DialResponse(
          status: ResponseStatus.Ok,
          addrIdx: Opt.none(AddrIdx),
          dialStatus: Opt.some(DialStatus.Ok),
        ),
      )
    ).encode()
    expect(AutonatV2Error):
      discard await client.sendDialRequest(dst.peerInfo.peerId, reqAddrs)
