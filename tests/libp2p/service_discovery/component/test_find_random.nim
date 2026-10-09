# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, sequtils
import ../../../../libp2p/[extended_peer_record, peerid]
import ../../../../libp2p/protocols/[kademlia, protocol, service_discovery]
import ../../../../libp2p/stream/connection
import ../../../tools/[lifecycle, topology, unittest]
import ../utils

proc foreignXpr(): Value =
  Value.fromBytes(makeAdvertisement().encode())

suite "Service Discovery - XPR key binding":
  test "replyXpr rejects a reply whose record key is not the queried key":
    let ad = makeAdvertisement()
    let ownKey = ad.data.peerId.toKey()
    let reply = Message(
      record: Opt.some(
        Record(key: Opt.some(ownKey), value: Opt.some(Value.fromBytes(ad.encode())))
      )
    )

    check:
      replyXpr(ownKey, reply).isSome()
      replyXpr(randomPeerId().toKey(), reply).isNone()

  asyncTest "lookupRandom drops a record whose subject is not the queried peer":
    let discos = setupServiceDiscoveryNodes(3, xprPublishing = false)
    startAndDeferStop(discos)
    await connectStar(discos)

    let servedKey = discos[2].switch.peerInfo.peerId.toKey()
    discos[2].dataTable.insert(servedKey, foreignXpr(), Timestamp.now())

    check (await discos[1].lookupRandom()).len == 0

  asyncTest "lookupRandom finds a caller-supplied XPR under its signer's key":
    let discos = setupServiceDiscoveryNodes(3, xprPublishing = false)
    startAndDeferStop(discos)
    await connectStar(discos)

    let signer = discos[2].switch.peerInfo
    let service = makeServiceInfo()
    let advert = makeAdvertisement(service.id, signer.privateKey, signer.addrs)
    check discos[0].startAdvertising(service, Opt.some(advert.encode())).isOk()

    checkUntilTimeout:
      discos[2].dataTable.get(signer.peerId.toKey()).isSome()

    let records = await discos[1].lookupRandom()
    check records.mapIt(it.peerId) == @[signer.peerId]

suite "Service Discovery Component - Find Random":
  teardown:
    checkTrackers()

  asyncTest "Simple find random node":
    let discos = setupServiceDiscoveryNodes(5)
    startAndDeferStop(discos)

    await connectStar(discos)

    let records = await discos[1].lookupRandom()

    check records.len == 4
    let peerIds = discos.mapIt(it.switch.peerInfo.peerId)
    for record in records:
      check record.peerId in peerIds

  asyncTest "lookupRandom completes when there are no peers to query":
    # With an empty routing table the shortlist is empty, so the lookup returns
    # immediately and lookupRandom must complete rather than hang.
    let discos = setupServiceDiscoveryNodes(1)
    startAndDeferStop(discos)

    check await discos[0].lookupRandom().withTimeout(5.seconds)

  asyncTest "lookupRandom can be cancelled while the lookup is in flight":
    # Hold the peer's FIND_NODE request open. This is a synchronization point,
    # so cancellation always happens while lookupRandom owns an active RPC stream.
    let discos = setupServiceDiscoveryNodes(2)
    let requestReceived = newFuture[void]("find-random-request-received")
    let handlerFinished = newFuture[void]("find-random-handler-finished")
    discos[1].handler = proc(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      defer:
        handlerFinished.complete()
        await stream.close()
      try:
        discard await stream.readLp(ServiceDiscoveryMaxMsgSize)
        requestReceived.complete()
        await stream.join()
      except LPStreamError as e:
        raiseAssert e.msg

    startAndDeferStop(discos)
    await connectStar(discos)

    let fut = discos[0].lookupRandom()
    await requestReceived
    await fut.cancelAndWait()
    await handlerFinished

  asyncTest "a disco node answers a ping on its own codec":
    let discos = setupServiceDiscoveryNodes(2)
    startAndDeferStop(discos)

    check await discos[0].ping(
      discos[1].switch.peerInfo.peerId, discos[1].switch.peerInfo.addrs
    )
