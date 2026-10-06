{.used.}

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import
  ../../libp2p/crypto/crypto,
  ../../libp2p/multicodec,
  ../../libp2p/peerinfo,
  ../../libp2p/peerid,
  ../../libp2p/routing_record
import ../tools/[unittest, crypto, multiaddress]

suite "PeerInfo":
  test "Should init with private key":
    let seckey = PrivateKey.random(ECDSA, rng()).get()
    var peerInfo = PeerInfo.new(seckey)
    var peerId = PeerId.init(seckey).get()

    check peerId == peerInfo.peerId
    check seckey.getPublicKey().get() == peerInfo.publicKey

  test "tryNew returns the peer info without raising":
    let seckey = PrivateKey.random(Ed25519, rng()).get()
    let peerInfo = PeerInfo.tryNew(seckey, protocols = ["/test/1.0.0"]).get()

    check:
      peerInfo.peerId == PeerId.init(seckey).get()
      peerInfo.publicKey == seckey.getPublicKey().get()
      peerInfo.protocols == @["/test/1.0.0"]

  test "Signed peer record":
    const
      ExpectedDomain = $multiCodec("libp2p-peer-record")
      ExpectedPayloadType = @[(byte) 0x03, (byte) 0x01]

    let
      seckey = PrivateKey.random(rng()).tryGet()
      peerId = PeerId.init(seckey).get()
      multiAddresses = @[ma("/ip4/0.0.0.0/tcp/24"), ma("/ip4/0.0.0.0/tcp/25")]
      peerInfo = PeerInfo.new(seckey, multiAddresses)

    waitFor(peerInfo.update())

    let
      env = peerInfo.signedPeerRecord.envelope
      rec = PeerRecord.decode(env.payload()).tryGet()

    # Check envelope fields
    check:
      env.publicKey == peerInfo.publicKey
      env.payloadType == ExpectedPayloadType
      env.verify(ExpectedDomain)

    # Check payload (routing record)
    check:
      rec.peerId == peerId
      rec.seqNo > 0
      rec.addresses.len == 2
      rec.addresses[0].address == multiAddresses[0]
      rec.addresses[1].address == multiAddresses[1]

  test "Public address mapping":
    let
      seckey = PrivateKey.random(ECDSA, rng()).get()
      multiAddresses = @[ma("/ip4/0.0.0.0/tcp/24"), ma("/ip4/0.0.0.0/tcp/25")]
      multiAddresses2 = @[ma("/ip4/8.8.8.8/tcp/33")]

    proc addressMapper(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      check input == multiAddresses
      await sleepAsync(0.seconds)
      return multiAddresses2

    var peerInfo =
      PeerInfo.new(seckey, multiAddresses, addressMappers = @[addressMapper])
    waitFor peerInfo.update()
    check peerInfo.addrs == multiAddresses2

  asyncTest "Direct construction initializes the address-expansion lock":
    let
      privateKey = PrivateKey.random(ECDSA, rng()).get()
      publicKey = privateKey.getPublicKey().get()
      listenAddrs = @[ma("/ip4/0.0.0.0/tcp/24")]
    var mapperCalls = 0

    proc addressMapper(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc mapperCalls
      return input

    let peerInfo = PeerInfo(
      peerId: PeerId.init(publicKey).get(),
      privateKey: privateKey,
      publicKey: publicKey,
      listenAddrs: listenAddrs,
      addressMappers: @[addressMapper],
    )

    check (await peerInfo.expandAddrs()) == listenAddrs
    await peerInfo.update()
    check:
      mapperCalls == 2
      peerInfo.addrs == listenAddrs

  asyncTest "Address mapper passes are serialized":
    let
      seckey = PrivateKey.random(ECDSA, rng()).get()
      listenAddrs = @[ma("/ip4/0.0.0.0/tcp/24")]
    var active, maxActive: int

    proc addressMapper(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      inc active
      maxActive = max(maxActive, active)
      defer:
        dec active
      await sleepAsync(10.milliseconds)
      return input

    let peerInfo = PeerInfo.new(seckey, listenAddrs, addressMappers = @[addressMapper])
    await allFutures(peerInfo.expandAddrs(), peerInfo.expandAddrs(listenAddrs))
    check maxActive == 1

  test "Announced addresses win over the mapper chain":
    let
      seckey = PrivateKey.random(ECDSA, rng()).get()
      listenAddrs = @[ma("/ip4/0.0.0.0/tcp/24")]
      mapperAddrs = @[ma("/ip4/8.8.8.8/tcp/33")]
      announcedAddrs =
        @[ma("/ip4/203.0.113.7/tcp/9000"), ma("/ip4/203.0.113.7/udp/9000/quic-v1")]

    var mapperCalled = false
    proc addressMapper(
        input: seq[MultiAddress]
    ): Future[seq[MultiAddress]] {.async: (raises: [CancelledError]).} =
      mapperCalled = true
      return mapperAddrs

    let peerInfo = PeerInfo.new(
      seckey,
      listenAddrs,
      addressMappers = @[addressMapper],
      announcedAddrs = announcedAddrs,
    )
    waitFor peerInfo.update()

    # announcedAddrs win, and the mapper chain still runs on the listen addrs
    check:
      peerInfo.addrs == announcedAddrs
      mapperCalled == true

  test "addressPolicy still filters announced addresses":
    let
      seckey = PrivateKey.random(ECDSA, rng()).get()
      publicAddr = ma("/ip4/203.0.113.7/tcp/9000")
      privateAddr = ma("/ip4/192.168.1.42/tcp/9000")
      announcedAddrs = @[publicAddr, privateAddr]

    proc onlyPublic(maddr: MultiAddress): bool {.gcsafe, raises: [].} =
      maddr == publicAddr

    let peerInfo = PeerInfo.new(
      seckey, [], addressPolicy = onlyPublic, announcedAddrs = announcedAddrs
    )
    waitFor peerInfo.update()

    check peerInfo.addrs == @[publicAddr]

  test "Observers fire on notifyObservers":
    let
      seckey = PrivateKey.random(ECDSA, rng()).get()
      multiAddresses = @[ma("/ip4/0.0.0.0/tcp/24")]
      peerInfo = PeerInfo.new(seckey, multiAddresses)

    var
      callsA = 0
      callsB = 0

    proc obsA(p: PeerInfo) {.gcsafe, raises: [].} =
      inc callsA

    proc obsB(p: PeerInfo) {.gcsafe, raises: [].} =
      inc callsB

    peerInfo.addObserver(obsA)
    peerInfo.addObserver(obsB)
    peerInfo.addObserver(nil) # nil guard: must be no-op

    peerInfo.notifyObservers()
    check:
      callsA == 1
      callsB == 1

    peerInfo.notifyObservers()
    check:
      callsA == 2
      callsB == 2

    # removed observer is not triggered
    peerInfo.removeObserver(obsA)
    peerInfo.notifyObservers()
    check:
      callsA == 2
      callsB == 3

  test "Observers fire on update":
    let
      seckey = PrivateKey.random(ECDSA, rng()).get()
      multiAddresses = @[ma("/ip4/0.0.0.0/tcp/24")]
      peerInfo = PeerInfo.new(seckey, multiAddresses)

    var
      calls: int
      seenAddrs: seq[MultiAddress]

    proc obs(p: PeerInfo) {.gcsafe, raises: [].} =
      inc calls
      seenAddrs = p.addrs

    peerInfo.addObserver(obs)

    # updated triggers observers initially
    # (PeerInfo.new does not set up `.addrs` property initially)
    waitFor peerInfo.update()
    check:
      calls == 1
      seenAddrs == peerInfo.addrs

    # update won't trigger observers since `.addrs` was not changed
    waitFor peerInfo.update()
    check:
      calls == 1
