{.used.}
## # Circuit Relay example
##
## Circuit Relay can be used when a node cannot reach another node
## directly, but can reach it through another node (the Relay).
##
## That may happen because of NAT, Firewalls, or incompatible transports.
##
## More informations [here](https://libp2p.io/docs/circuit-relay/).
import chronos, stew/byteutils
import libp2p, libp2p/protocols/connectivity/relay/[relay, client]

# Helper to create a circuit relay node
proc createCircuitRelaySwitch(r: Relay): Switch =
  SwitchBuilder
    .new()
    .withRng(newRng())
    .withAddresses(@[MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet()])
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .withCircuitRelay(r)
    .build()

proc main() {.async.} =
  # Create a custom protocol
  let customProtoCodec = "/test"
  var proto = new LPProtocol
  proto.codec = customProtoCodec
  proto.handler = proc(
      stream: Stream, proto: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      var msg = string.fromBytes(await stream.readLp(1024))
      echo "1 - Dst Received: ", msg
      assert "test1" == msg
      await stream.writeLp("test2")
      msg = string.fromBytes(await stream.readLp(1024))
      echo "2 - Dst Received: ", msg
      assert "test3" == msg
      await stream.writeLp("test4")
    except LPStreamError as exc:
      echo "exception in handler", exc.msg

  let
    relay = Relay.new()
    clSrc = RelayClient.new()
    clDst = RelayClient.new()

    # Create three hosts, enable relay client on two of them.
    # The third one can relay connections for other peers.
    # RelayClient can use a relay, Relay is a relay.
    swRel = createCircuitRelaySwitch(relay)
    swSrc = createCircuitRelaySwitch(clSrc)
    swDst = createCircuitRelaySwitch(clDst)

  swDst.mount(proto)

  await swRel.start()
  await swSrc.start()
  await swDst.start()

  let
    # Create a relay address to swDst using swRel as the relay
    addrs = MultiAddress
      .init(
        $swRel.peerInfo.addrs[0] & "/p2p/" & $swRel.peerInfo.peerId & "/p2p-circuit"
      )
      .get()

  # Connect Dst to the relay
  await swDst.connect(swRel.peerInfo.peerId, swRel.peerInfo.addrs)

  # Dst reserve a slot on the relay.
  let rsvp = await clDst.reserve(swRel.peerInfo.peerId, swRel.peerInfo.addrs)

  # Src dial Dst using the relay
  let stream = await swSrc.dial(swDst.peerInfo.peerId, @[addrs], customProtoCodec)

  await stream.writeLp("test1")
  var msg = string.fromBytes(await stream.readLp(1024))
  echo "1 - Src Received: ", msg
  assert "test2" == msg
  await stream.writeLp("test3")
  msg = string.fromBytes(await stream.readLp(1024))
  echo "2 - Src Received: ", msg
  assert "test4" == msg

  await relay.stop()
  await allFutures(swSrc.stop(), swDst.stop(), swRel.stop())

waitFor(main())
