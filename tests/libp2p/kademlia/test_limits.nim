# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils, tables
import ../../../libp2p/[protocols/kademlia, switch, builders]
import ../../../libp2p/utils/future
import ../../tools/[lifecycle, multiaddress, stall_server, topology, unittest]
import ./utils.nim

suite "KadDHT - Limits":
  teardown:
    checkTrackers()

  asyncTest "admitPeers spawns at most maxConcurrentProbes probes":
    let kad = setupKad()
    kad.admissionSem = newAsyncSemaphore(2)

    let peers = peersWithAddrs(5)
    kad.admitPeers(peers)

    # candidates beyond the semaphore are dropped, never queued
    check kad.admissionProbes.len == 2

    let probes = move kad.admissionProbes
    await noCancel probes.values.toSeq().cancelAndWait()

  asyncTest "admitPeers records addresses of candidates past the probe cap":
    let kad = setupKad()
    kad.admissionSem = newAsyncSemaphore(2)

    let peers = peersWithAddrs(5)
    kad.admitPeers(peers)

    # a lookup shortlists every candidate, so all of them must stay dialable
    let addressBook = kad.switch.peerStore[AddressBook]
    for p in peers:
      check addressBook[p.peerId] == p.addrs

    let probes = move kad.admissionProbes
    await noCancel probes.values.toSeq().cancelAndWait()

  asyncTest "a candidate dropped for a full probe cap is probed on a later call":
    let kad = setupKad()
    kad.admissionSem = newAsyncSemaphore(1)

    let peers = peersWithAddrs(2)
    kad.admitPeers(peers)
    check kad.admissionProbes.len == 1

    let firstProbes = move kad.admissionProbes
    # cancelling the probe releases its slot through ``admitPeer``'s defer
    await noCancel firstProbes.values.toSeq().cancelAndWait()
    check kad.admissionSem.availableSlots() == 1

    kad.admitPeers(@[peers[1]])
    check kad.admissionProbes.len == 1

    let secondProbes = move kad.admissionProbes
    await noCancel secondProbes.values.toSeq().cancelAndWait()

  asyncTest "an admission probe frees its slot at the probe timeout":
    let stall = startStallServer()
    let kad = setupKad(testKadConfig(timeout = 500.milliseconds))
    startAndDeferStop(@[kad.switch])
    defer:
      # Before the switch: `stop` waits for the dial this probe abandons.
      await stall.stop()
    kad.admissionSem = newAsyncSemaphore(1)

    kad.admitPeers(@[PeerInfo(peerId: randomPeerId(), addrs: @[stall.address])])
    check kad.admissionProbes.len == 1

    let probes = move kad.admissionProbes
    # A peer that accepts and never speaks costs `timeout`, not the dialer's 30s.
    await allFutures(probes.values().toSeq()).wait(5.seconds)
    check kad.admissionSem.availableSlots() == 1

  asyncTest "liveness probes do not consume admissionSem slots":
    ## Admission and eviction use independent semaphores: a saturated
    ## livenessSem must not prevent admitPeers from launching probes.
    let kad = setupKad()
    kad.admissionSem = newAsyncSemaphore(2)
    kad.livenessSem = newAsyncSemaphore(1)
    check kad.livenessSem.tryAcquire() # hold the only liveness slot

    let peers = peersWithAddrs(3)
    kad.admitPeers(peers)

    check kad.admissionProbes.len == 2

    let probes = move kad.admissionProbes
    await noCancel probes.values.toSeq().cancelAndWait()
    kad.livenessSem.release()

  test "updateShortlist caps shortlist at maxShortlistSize":
    let kad = setupKad()
    kad.config.limits.maxShortlistSize = 5

    let targetKey = randomPeerId().toKey()
    var state = LookupState.init(kad, targetKey)

    # Generate 20 fresh peers and feed them through updateShortlist.
    var peers: seq[Peer]
    for i in 0 ..< 20:
      peers.add(closerPeer(randomPeerId().toKey()))

    let msg = Message(msgType: MessageType.findNode, closerPeers: peers)
    discard state.updateShortlist(msg)

    check state.shortlist.len <= kad.config.limits.maxShortlistSize

  test "updateShortlist prefers closer peers when over cap":
    let kad = setupKad()
    kad.config.limits.maxShortlistSize = 3

    # Use the no-op hasher so XOR distance is a function of the key bytes
    # directly, making "close" peers easy to construct.
    kad.rtable.config.hasher = Opt.some(noOpHasher)
    var target: Key = newSeq[byte](32)
    var state = LookupState.init(kad, target)
    # Drop any peers pre-seeded from the routing table.
    state.shortlist.clear()

    # Insert a far peer first
    var farId: Key = newSeq[byte](32)
    farId[0] = 0xFF
    let farMsg =
      Message(msgType: MessageType.findNode, closerPeers: @[closerPeer(farId)])
    discard state.updateShortlist(farMsg)

    # Now insert 5 close peers — they should evict the far one
    var closePeers: seq[Peer]
    for i in 1 .. 5:
      var id: Key = newSeq[byte](32)
      id[31] = byte(i)
      closePeers.add(closerPeer(id))
    let closeMsg = Message(msgType: MessageType.findNode, closerPeers: closePeers)
    discard state.updateShortlist(closeMsg)

    check state.shortlist.len == kad.config.limits.maxShortlistSize

  test "updatePeers seeds addresses that outlive the liveness grace period":
    ## Nothing dials a seed, so no `markConnected` or identify lifts it off Low.
    let kad = setupKad()
    let peers = peersWithAddrs(1)
    kad.updatePeers(peers)

    let entries = kad.switch.peerStore[AddressBook].entries(peers[0].peerId)
    check:
      kad.hasKey(peers[0].peerId.toKey())
      entries[0].confidence >= AddressConfidence.Medium

  test "updateShortlist rejects a closer peer no address can reach":
    ## A remote that names bare ids must not displace peers the node can dial.
    let kad = setupKad()
    kad.config.limits.maxShortlistSize = 1

    let targetKey = randomPeerId().toKey()
    var state = LookupState.init(kad, targetKey)
    state.shortlist.clear()

    let ranked =
      @[randomPeerId(), randomPeerId()].sortPeers(targetKey, kad.rtable.config.hasher)
    let (near, far) = (ranked[0], ranked[1])

    discard state.updateShortlist(
      Message(msgType: MessageType.findNode, closerPeers: @[closerPeer(far.toKey())])
    )
    check state.shortlist.len == 1

    let added = state.updateShortlist(
      Message(msgType: MessageType.findNode, closerPeers: @[Peer(id: near.toKey())])
    )

    check:
      added.len == 0
      near notin state.shortlist
      far in state.shortlist

  test "updateShortlist rejects a closer peer whose addresses the policy drops":
    ## An address the node would never dial must not buy what an absent one cannot.
    let kad = setupKad()
    kad.config.addressPolicy = publicRoutableAddressPolicy
    kad.config.limits.maxShortlistSize = 1

    let targetKey = randomPeerId().toKey()
    var state = LookupState.init(kad, targetKey)
    state.shortlist.clear()

    let ranked =
      @[randomPeerId(), randomPeerId()].sortPeers(targetKey, kad.rtable.config.hasher)
    let (near, far) = (ranked[0], ranked[1])

    discard state.updateShortlist(
      Message(
        msgType: MessageType.findNode,
        closerPeers: @[Peer(id: far.toKey(), addrs: @[ma("/ip4/1.2.3.4/tcp/1")])],
      )
    )
    check state.shortlist.len == 1

    let added = state.updateShortlist(
      Message(
        msgType: MessageType.findNode,
        closerPeers: @[Peer(id: near.toKey(), addrs: @[ma("/ip4/192.168.1.5/tcp/1")])],
      )
    )

    check:
      added.len == 0
      near notin state.shortlist
      far in state.shortlist

  asyncTest "putValue rejects values larger than maxValueSize":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    kads[1].config.limits.maxValueSize = 16

    let key = kads[0].rtable.selfId
    let big = newSeq[byte](32)
    let res = await kads[1].putValue(key, big)

    check:
      res.isErr()
      kads[0].dataTable.len == 0
      kads[1].dataTable.len == 0

  asyncTest "handlePutValue drops records exceeding maxValueSize":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    # Lower the receiver's cap so the sender's normal-size put is rejected
    # on the wire even though the sender accepts it locally.
    kads[0].config.limits.maxValueSize = 8
    kads[1].config.limits.maxValueSize = 1024

    let key = kads[0].rtable.selfId
    let value = newSeq[byte](64)
    discard await kads[1].putValue(key, value)

    # Sender stores locally (under its own cap); receiver drops the wire copy.
    # putValue awaited the full RPC batch, so the receiver has already processed
    # (and dropped) the message by the time we reach this check.
    check:
      kads[1].containsData(key, value)
      kads[0].containsNoData(key)

  asyncTest "handlePutValue drops new records when maxLocalRecords is reached":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    kads[0].config.limits.maxLocalRecords = Opt.some(1)

    let
      existingKey = randomPeerId().toKey()
      newKey = randomPeerId().toKey()
      existingValue = @[1.byte]
      newValue = @[2.byte]

    kads[0].dataTable.insert(existingKey, existingValue, Timestamp.now())

    let request = Message(
      msgType: MessageType.putValue,
      key: newKey,
      record: Opt.some(Record(key: newKey, value: Opt.some(newValue))),
    )
    let conn = await kads[1].switch.dial(
      kads[0].switch.peerInfo.peerId, kads[0].switch.peerInfo.addrs, kads[0].codec
    )
    await kads[0].handlePutValue(conn, request)

    check:
      kads[0].containsData(existingKey, existingValue)
      kads[0].containsNoData(newKey)

  asyncTest "getValue skips local insert when maxLocalRecords is reached":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    kads[0].config.limits.maxLocalRecords = Opt.some(1)

    let
      existingKey = randomPeerId().toKey()
      lookupKey = kads[1].rtable.selfId
      existingValue = @[1.byte]
      lookupValue = @[2.byte]

    kads[0].dataTable.insert(existingKey, existingValue, Timestamp.now())
    kads[1].dataTable.insert(lookupKey, lookupValue, Timestamp.now())

    let res = await kads[0].getValue(lookupKey, quorumOverride = Opt.some(1))

    check:
      res.isOk()
      res.value().value == lookupValue
      kads[0].containsData(existingKey, existingValue)
      kads[0].containsNoData(lookupKey)

  asyncTest "getValue drops replies larger than maxValueSize":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    kads[0].config.limits.maxValueSize = 8

    let key = kads[1].rtable.selfId
    kads[1].dataTable.insert(key, newSeq[byte](64), Timestamp.now())

    let res = await kads[0].getValue(key, quorumOverride = Opt.some(1))

    check:
      res.isErr()
      kads[0].containsNoData(key)

  asyncTest "getValue caps ReceivedTable at maxReceivedSize":
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)
    await connectStar(kads)

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3]

    # Seed every other node with the key/value
    for i in 1 ..< 4:
      discard await kads[i].putValue(key, value)

    # Cap kads[0]'s ReceivedTable below the available peers
    kads[0].config.limits.maxReceivedSize = 1
    let res = await kads[0].getValue(key, quorumOverride = Opt.some(1))

    check res.isOk()
    check res.value().value == value

  asyncTest "rpcSem bounds concurrent in-flight RPCs":
    # With a 1-slot semaphore the second concurrent dispatchFindNode must wait
    # for the first to release before it can start. We verify this by checking
    # availableSlots mid-flight (should be 0) and after completion (should be 1).
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)
    await connect(kads[0], kads[1])

    # Replace the semaphore with a 1-slot one; the helper template uses kad.rpcSem.
    kads[0].rpcSem = newAsyncSemaphore(1)

    let target = kads[1].rtable.selfId
    let f1 = kads[0].dispatchFindNode(kads[1].switch.peerInfo.peerId, target)
    let f2 = kads[0].dispatchFindNode(kads[1].switch.peerInfo.peerId, target)
    # Yield so both coroutines get a chance to start; with a 1-slot semaphore
    # f1 holds the slot (suspended in dial) while f2 is blocked on acquire.
    await sleepAsync(0)
    check kads[0].rpcSem.availableSlots == 0
    await allFutures(f1, f2)
    check:
      kads[0].rpcSem.availableSlots == 1
      f1.read().isOk()
      f2.read().isOk()
