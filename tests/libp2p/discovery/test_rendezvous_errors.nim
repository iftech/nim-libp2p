# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import strformat, strutils, chronos
import
  ../../../libp2p/[
    protocols/rendezvous,
    protocols/rendezvous/protobuf,
    peerinfo,
    switch,
    routing_record,
    crypto/crypto,
    protocols/protocol,
    stream/connection,
  ]
import ../../tools/[lifecycle, unittest, crypto]
import ./utils

suite "RendezVous Errors":
  teardown:
    checkTrackers()

  asyncTest "Various local error":
    let rdv = RendezVous.new(
      rng(),
      RendezVousConfig.new(
        minDuration = MinimumAcceptedDuration, maxDuration = MaximumDuration
      ),
    )
    expect AdvertiseError:
      discard await rendezvous.request(
        rdv, Opt.some("A".repeat(300)), Opt.none(int), Opt.none(seq[PeerId])
      )
    expect AdvertiseError:
      discard await rendezvous.request(
        rdv, Opt.some("A"), Opt.some(-1), Opt.none(seq[PeerId])
      )
    expect AdvertiseError:
      discard await rendezvous.request(
        rdv, Opt.some("A"), Opt.some(3000), Opt.none(seq[PeerId])
      )
    expect AdvertiseError:
      await rdv.advertise("A".repeat(300))
    expect AdvertiseError:
      await rdv.advertise("A", Opt.some(73.hours))
    expect AdvertiseError:
      await rdv.advertise("A", Opt.some(30.seconds))

  asyncTest "Advertise timeout releases the semaphore slot":
    let
      rdv = createSwitch(RendezVousConfig.new())
      silentPeer = createSwitch()

    proc neverRespond(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      defer:
        await stream.close()
      try:
        while true:
          discard await stream.readLp(4096)
      except LPStreamError:
        discard

    silentPeer.mount(LPProtocol.new(@[RendezVousCodec], neverRespond))
    startAndDeferStop(@[rdv.switch, silentPeer])

    await rdv.switch.connect(silentPeer.peerInfo.peerId, silentPeer.peerInfo.addrs)
    await rdv.advertise("foo")

    check rdv.sema.availableSlots() == SemaphoreDefaultSize

  let testCases = @[
    (
      "Register - Invalid Namespace",
      (
        proc(node: RendezVous): Message =
          prepareRegisterMessage(
            "A".repeat(300), node.switch.peerInfo.signedPeerRecord.encode(), 2.hours
          )
      ),
      ResponseStatus.InvalidNamespace,
    ),
    (
      "Register - Invalid Signed Peer Record",
      (
        proc(node: RendezVous): Message =
          # Malformed SPR - empty bytes will fail validation
          prepareRegisterMessage("namespace", newSeq[byte](), 2.hours)
      ),
      ResponseStatus.InvalidSignedPeerRecord,
    ),
    (
      "Register - Invalid TTL",
      (
        proc(node: RendezVous): Message =
          prepareRegisterMessage(
            "namespace", node.switch.peerInfo.signedPeerRecord.encode(), 73.hours
          )
      ),
      ResponseStatus.InvalidTTL,
    ),
    (
      "Discover - Invalid Namespace",
      (
        proc(node: RendezVous): Message =
          prepareDiscoverMessage(ns = Opt.some("A".repeat(300)))
      ),
      ResponseStatus.InvalidNamespace,
    ),
    (
      "Discover - Invalid Cookie",
      (
        proc(node: RendezVous): Message =
          # Empty buffer will fail Cookie.decode().tryGet() and yield InvalidCookie
          prepareDiscoverMessage(cookie = Opt.some(newSeq[byte]()))
      ),
      ResponseStatus.InvalidCookie,
    ),
  ]

  for test in testCases:
    let (testName, getMessage, expectedStatus) = test

    asyncTest &"Node returns ERROR_CODE for invalid message - {testName}":
      let (rendezvousNode, peerNodes) = setupRendezvousNodeWithPeerNodes(1)
      startAndDeferStop(peerNodes & rendezvousNode)

      await connect(peerNodes[0], rendezvousNode)

      let
        peerNode = peerNodes[0]
        messageBuf = encode(getMessage(peerNode))

      let
        responseBuf = await sendRdvMessage(peerNode, rendezvousNode, messageBuf)
        responseMessage = Message.decode(responseBuf).tryGet()
        actualStatus =
          if responseMessage.registerResponse.isSome():
            responseMessage.registerResponse.get.status
          else:
            responseMessage.discoverResponse.get.status

      check actualStatus == expectedStatus

  asyncTest "Node returns NotAuthorized when Register exceeding peer limit":
    let (rendezvousNode, peerNodes) = setupRendezvousNodeWithPeerNodes(1)
    startAndDeferStop(peerNodes & rendezvousNode)

    await connect(peerNodes[0], rendezvousNode)

    # Pre-populate registrations up to the limit for this peer under the same namespace
    let namespace = "namespaceNA"
    await populatePeerRegistrations(
      peerNodes[0], rendezvousNode, namespace, RegistrationLimitPerPeer
    )

    # Attempt one more registration which should be rejected with NotAuthorized
    let messageBuf = encode(
      prepareRegisterMessage(
        namespace, peerNodes[0].switch.peerInfo.signedPeerRecord.encode(), 2.hours
      )
    )

    let responseBuf = await sendRdvMessage(peerNodes[0], rendezvousNode, messageBuf)
    let responseMessage = Message.decode(responseBuf).tryGet()
    check responseMessage.registerResponse.get.status == ResponseStatus.NotAuthorized
