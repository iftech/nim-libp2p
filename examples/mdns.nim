{.used.}
# Discover LAN peers and choose which ones to connect to.
import chronos
import libp2p

proc main() {.async.} =
  let node = SwitchBuilder
    .new()
    .withRng(newRng())
    .withAddress(MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet())
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .withMdns(
      onPeerFound = proc(
          switch: Switch, peer: MdnsPeer
      ) {.async: (raises: [CancelledError]).} =
        # Replace this condition with the application's own admission policy.
        # This example will connect to all new peers discovered.
        if not switch.isConnected(peer.peerId):
          # Use addresses from the address book to respect the configured
          # address policy.
          let addrs = switch.peerStore[AddressBook][peer.peerId]
          if addrs.len == 0:
            echo "Peer discovered but no usable addresses found: ", peer.peerId
            return

          try:
            await switch.connect(peer.peerId, addrs)
            echo "Connected to ", peer.peerId
          except DialFailedError as e:
            echo "Could not connect: ", e.msg
    )
    .build()

  await node.start()
  try:
    await sleepAsync(30.seconds)
  finally:
    # Stopping the switch cancels in-flight mDNS callbacks.
    await node.stop()

waitFor(main())
