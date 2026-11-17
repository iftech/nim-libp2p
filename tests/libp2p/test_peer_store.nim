# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[tables, sequtils]
from std/times import nil
import chronos
import
  ../../libp2p/[
    crypto/crypto,
    multiaddress,
    peerid,
    peerstore,
    protocols/identify,
    routing_record,
    utils/opt,
  ]
import ../tools/[unittest, crypto, multiaddress]

type
  GenericBook[T] = ref object of PeerBook[T]
  IntBook = GenericBook[int]

suite "PeerStore":
  # Testvars
  let
    # Peer 1
    keyPair1 = KeyPair.random(ECDSA, rng()).get()
    peerId1 = PeerId.init(keyPair1.seckey).get()
    multiaddrStr1 =
      "/ip4/127.0.0.1/udp/1234/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
    multiaddr1 = ma(multiaddrStr1)
    storedMultiaddr1 = ma("/ip4/127.0.0.1/udp/1234")
    testcodec1 = "/nim/libp2p/test/0.0.1-beta1"
    # Peer 2
    keyPair2 = KeyPair.random(ECDSA, rng()).get()
    peerId2 = PeerId.init(keyPair2.seckey).get()
    multiaddrStr2 =
      "/ip4/0.0.0.0/tcp/1234/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
    multiaddr2 = ma(multiaddrStr2)
    testcodec2 = "/nim/libp2p/test/0.0.2-beta1"

  proc makeSignedPeerRecord(
      privateKey: PrivateKey, peerId: PeerId, addrs: seq[MultiAddress], seqNo: uint64
  ): SignedPeerRecord =
    SignedPeerRecord.init(privateKey, PeerRecord.init(peerId, addrs, seqNo)).tryGet()

  proc storedPeerRecord(peerStore: PeerStore, peerId: PeerId): PeerRecord =
    let encoded = peerStore[SPRBook][peerId].encode()
    SignedPeerRecord.decode(encoded).tryGet().data

  proc checkStoredPeerRecord(
      peerStore: PeerStore, peerId: PeerId, seqNo: uint64, address: MultiAddress
  ) =
    let stored = peerStore.storedPeerRecord(peerId)
    check:
      stored.seqNo == seqNo
      stored.addresses.len == 1
      stored.addresses[0].address == address

  test "PeerStore API":
    # Set up peer store
    var peerStore = PeerStore.new(nil)

    peerStore[AddressBook][peerId1] = @[multiaddr1]
    peerStore[AddressBook][peerId2] = @[multiaddr2]
    peerStore[ProtoBook][peerId1] = @[testcodec1]
    peerStore[ProtoBook][peerId2] = @[testcodec2]
    peerStore[KeyBook][peerId1] = keyPair1.pubkey
    peerStore[KeyBook][peerId2] = keyPair2.pubkey

    # Test PeerStore::del
    # Delete existing peerId
    peerStore.del(peerId1)
    check peerId1 notin peerStore[AddressBook]
    # Now try and del it again
    peerStore.del(peerId1)

  test "PeerStore API (generics)":
    let peerStore = PeerStore.new(nil)

    peerStore[GenericBook[int]][peerId1] = 1
    peerStore[GenericBook[string]][peerId1] = "a"
    peerStore[GenericBook[Duration]][peerId1] = 2.seconds
    peerStore[GenericBook[times.Duration]][peerId1] = times.initDuration(seconds = 3)
    check:
      peerStore[IntBook][peerId1] == 1
      peerStore[GenericBook[string]][peerId1] == "a"
      peerStore[GenericBook[Duration]][peerId1] == 2.seconds
      peerStore[GenericBook[times.Duration]][peerId1] == times.initDuration(seconds = 3)

    peerStore.del(peerId1)
    check:
      peerId1 notin peerStore[GenericBook[int]]
      peerId1 notin peerStore[GenericBook[string]]
      peerId1 notin peerStore[GenericBook[Duration]]
      peerId1 notin peerStore[GenericBook[times.Duration]]

  test "updatePeerInfo stores and updates only fresh signed peer records":
    let
      peerStore = PeerStore.new(nil)
      initial = makeSignedPeerRecord(keyPair1.seckey, peerId1, @[multiaddr1], 10)
      lower = makeSignedPeerRecord(keyPair1.seckey, peerId1, @[multiaddr2], 9)
      same = makeSignedPeerRecord(keyPair1.seckey, peerId1, @[multiaddr2], 10)
      higher = makeSignedPeerRecord(keyPair1.seckey, peerId1, @[multiaddr2], 11)

    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId1, signedPeerRecord: Opt.some(initial.envelope))
    )
    peerStore.checkStoredPeerRecord(peerId1, 10, multiaddr1)

    for stale in [lower, same]:
      peerStore.updatePeerInfo(
        IdentifyInfo(peerId: peerId1, signedPeerRecord: Opt.some(stale.envelope))
      )
      peerStore.checkStoredPeerRecord(peerId1, 10, multiaddr1)

    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId1, signedPeerRecord: Opt.some(higher.envelope))
    )
    peerStore.checkStoredPeerRecord(peerId1, 11, multiaddr2)

  test "updatePeerInfo ignores invalid signed peer records":
    let
      peerStore = PeerStore.new(nil)
      valid = makeSignedPeerRecord(keyPair1.seckey, peerId1, @[multiaddr1], 10)
      wrongPeer = makeSignedPeerRecord(keyPair2.seckey, peerId2, @[multiaddr2], 11)
      wrongKey = makeSignedPeerRecord(keyPair2.seckey, peerId1, @[multiaddr2], 12)

    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId1, signedPeerRecord: Opt.some(valid.envelope))
    )

    for invalid in [wrongPeer, wrongKey]:
      peerStore.updatePeerInfo(
        IdentifyInfo(peerId: peerId1, signedPeerRecord: Opt.some(invalid.envelope))
      )
      peerStore.checkStoredPeerRecord(peerId1, 10, multiaddr1)

  test "updatePeerInfo replaces malformed existing signed peer record":
    let
      peerStore = PeerStore.new(nil)
      malformed = makeSignedPeerRecord(keyPair2.seckey, peerId1, @[multiaddr2], 20)
      valid = makeSignedPeerRecord(keyPair1.seckey, peerId1, @[multiaddr1], 1)

    peerStore[SPRBook][peerId1] = malformed.envelope
    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId1, signedPeerRecord: Opt.some(valid.envelope))
    )

    peerStore.checkStoredPeerRecord(peerId1, 1, multiaddr1)

  test "updatePeerInfo caps addresses after the dialable filter":
    let
      peerStore = PeerStore.new(nil)
      undialable = (0 ..< MaxIdentifyAddrs).mapIt(ma("/ip4/0.0.0.0/tcp/" & $(it + 1)))
      dialable = (0 .. MaxIdentifyAddrs).mapIt(ma("/ip4/127.0.0.1/tcp/" & $(it + 1)))

    peerStore.updatePeerInfo(
      IdentifyInfo(peerId: peerId1, addrs: undialable & dialable)
    )

    check peerStore[AddressBook][peerId1] == dialable[0 ..< MaxIdentifyAddrs]

  test "updatePeerInfo preserves verified addresses within the address budget":
    let
      peerStore = PeerStore.new(nil)
      reported = (1 .. MaxIdentifyAddrs).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
      verified = ma("/ip4/127.0.0.1/tcp/1000")

    peerStore[AddressBook].markConnected(peerId1, verified)
    peerStore.updatePeerInfo(IdentifyInfo(peerId: peerId1, addrs: reported))

    let stored = peerStore[AddressBook][peerId1]
    check stored.len == MaxPeerStoreAddrs
    check verified in stored
    check reported[0 ..< reported.len - 1].allIt(it in stored)
    check reported[^1] notin stored

  test "PeerStore listeners":
    # Set up peer store with listener
    var
      peerStore = PeerStore.new(nil)
      addrChanged = false

    proc addrChange(peerId: PeerId) {.gcsafe.} =
      addrChanged = true

    peerStore[AddressBook].addHandler(addrChange)

    # Test listener triggered on adding multiaddr
    peerStore[AddressBook][peerId1] = @[multiaddr1]
    check:
      addrChanged == true

    addrChanged = false
    check:
      peerStore[AddressBook].del(peerId1) == true
      addrChanged == true

  test "AgentBook listeners":
    let peerStore = PeerStore.new(nil)
    var changed: seq[PeerId]
    proc agentChange(peerId: PeerId) {.gcsafe.} =
      changed.add(peerId)

    peerStore[AgentBook].addHandler(agentChange)
    peerStore[AgentBook][peerId1] = "test-agent/1.0"

    check:
      changed == @[peerId1]
      peerStore[AgentBook][peerId1] == "test-agent/1.0"

  test "PeerBook API":
    # Set up address book
    var addressBook = PeerStore.new(nil)[AddressBook]

    # Test AddressBook::add
    addressBook[peerId1] = @[multiaddr1]

    check:
      toSeq(keys(addressBook.book))[0] == peerId1
      addressBook[peerId1] == @[storedMultiaddr1]

    # Test AddressBook::get
    check:
      addressBook[peerId1] == @[storedMultiaddr1]

    # Test AddressBook::del
    check:
      # Try to del peerId that doesn't exist
      addressBook.del(peerId2) == false

      # Delete existing peerId
      addressBook.book.len == 1 # sanity
      addressBook.del(peerId1) == true
      addressBook.book.len == 0

    # Test AddressBook::set
    # Set peerId2 with multiple multiaddrs
    addressBook[peerId2] = @[multiaddr1, multiaddr2]
    check:
      toSeq(keys(addressBook.book))[0] == peerId2
      addressBook[peerId2] == @[storedMultiaddr1, multiaddr2]

  test "Pruner - no capacity":
    let peerStore = PeerStore.new(nil, capacity = 0)
    peerStore[AgentBook][peerId1] = "gds"

    peerStore.cleanup(peerId1)

    check peerId1 notin peerStore[AgentBook]

  test "Pruner - FIFO":
    let peerStore = PeerStore.new(nil, capacity = 1)
    peerStore[AgentBook][peerId1] = "gds"
    peerStore[AgentBook][peerId2] = "gds"
    peerStore.cleanup(peerId2)
    peerStore.cleanup(peerId1)
    check:
      peerId1 in peerStore[AgentBook]
      peerId2 notin peerStore[AgentBook]

  test "Pruner - regular capacity":
    var peerStore = PeerStore.new(nil, capacity = 20)

    for i in 0 ..< 30:
      let randomPeerId = PeerId.init(KeyPair.random(ECDSA, rng()).get().pubkey).get()
      peerStore[AgentBook][randomPeerId] = "gds"
      peerStore.cleanup(randomPeerId)

    check peerStore[AgentBook].len == 20

  test "Pruner - infinite capacity":
    var peerStore = PeerStore.new(nil, capacity = -1)

    for i in 0 ..< 30:
      let randomPeerId = PeerId.init(KeyPair.random(ECDSA, rng()).get().pubkey).get()
      peerStore[AgentBook][randomPeerId] = "gds"
      peerStore.cleanup(randomPeerId)

    check peerStore[AgentBook].len == 30

suite "AddressBook TTL / confidence":
  let
    peerId1 = PeerId.random()
    peerId2 = PeerId.random()
    addr1 = ma("/ip4/1.2.3.4/tcp/1234")
    addr2 = ma("/ip4/5.6.7.8/tcp/5678")

  proc makeBook(low, medium, high: Duration): AddressBook =
    let b = AddressBook.new()
    b.ttls = AddressConfidenceTtls(low: low, medium: medium, high: high)
    b

  proc makeStore(low, medium, high: Duration): PeerStore =
    PeerStore.new(
      nil, addressTtls = AddressConfidenceTtls(low: low, medium: medium, high: high)
    )

  proc newRecorder(book: AddressBook): ref seq[PeerId] =
    ## Record the peerId of every change-handler notification.
    var recorded: ref seq[PeerId]
    new(recorded)
    recorded[] = @[]
    book.addHandler(
      proc(peerId: PeerId) {.gcsafe, raises: [].} =
        recorded[].add(peerId)
    )
    recorded

  test "address limit applies to set and extend while preserving verified addresses":
    let book = makeBook(1.hours, 1.hours, 1.hours)
    let addresses = (1 .. MaxPeerStoreAddrs + 2).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
    # replacement drops unverified addresses beyond the limit
    book.set(peerId1, addresses, AddressConfidence.Low)
    check book.entries(peerId1).len == MaxPeerStoreAddrs
    # successful dial can add an address at the limit; a later replacement
    # preserves it and makes room by dropping an unverified address
    book.markConnected(peerId1, addresses[^1])
    book.set(peerId1, addresses, AddressConfidence.Low)
    check book.entries(peerId1).len == MaxPeerStoreAddrs
    check book.entries(peerId1).anyIt(
      it.address == addresses[^1] and it.confidence == AddressConfidence.High
    )
    # at the limit, duplicates are unchanged and new unverified addresses are skipped.
    let before = Moment.now() - 1.minutes
    for entry in book.book[peerId1].mitems:
      if entry.address == addresses[0]:
        entry.lastUpdated = before
    book.extend(peerId1, @[addresses[0], addresses[^2]], AddressConfidence.Medium)
    check book.entries(peerId1).len == MaxPeerStoreAddrs
    let existing = book.entries(peerId1).filterIt(it.address == addresses[0])
    check existing ==
      @[
        AddressEntry(
          address: addresses[0], confidence: AddressConfidence.Low, lastUpdated: before
        )
      ]
    check addresses[^2] notin book[peerId1]

  test "set retains a fresh address when verified addresses fill the book":
    for confidence in [AddressConfidence.High, AddressConfidence.Infinite]:
      let
        book = makeBook(1.hours, 1.hours, 1.hours)
        addresses = (1 .. MaxPeerStoreAddrs + 2).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
      book.set(peerId1, addresses[0 ..< MaxPeerStoreAddrs], confidence)
      book.book[peerId1][0].lastUpdated = Moment.now() - 1.minutes
      # successful connections can push the book above its limit
      book.markConnected(peerId1, addresses[^2])
      book.set(peerId1, @[addresses[^1]], AddressConfidence.Low)
      check addresses[^1] in book[peerId1]
      if confidence == AddressConfidence.Infinite:
        check book.entries(peerId1).len == MaxPeerStoreAddrs + 1
        check addresses[0] in book[peerId1]
      else:
        check book.entries(peerId1).len == MaxPeerStoreAddrs
        check addresses[0] notin book[peerId1]

  test "identify replaces expired verified addresses for a disconnected peer":
    let
      store = makeStore(1.hours, 1.hours, 1.hours)
      book = store[AddressBook]
      addresses = (1 .. MaxPeerStoreAddrs + 3).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
      fresh = addresses[MaxPeerStoreAddrs .. ^1]
    book.extend(peerId1, addresses[0 ..< MaxPeerStoreAddrs], AddressConfidence.High)
    for entry in book.book[peerId1].mitems:
      entry.lastUpdated = Moment.now() - 2.hours
    store.updatePeerInfo(IdentifyInfo(peerId: peerId1, addrs: fresh))
    check book[peerId1] == fresh
    check book.entries(peerId1).len == fresh.len

  test "identify cannot refresh verified eviction order":
    let
      store = PeerStore.new(nil)
      book = store[AddressBook]
      addresses = (1 .. MaxPeerStoreAddrs + 1).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
    book.extend(peerId1, addresses[0 ..< MaxPeerStoreAddrs], AddressConfidence.High)
    for entry in book.book[peerId1].mitems:
      entry.lastUpdated = Moment.now() - 1.minutes
    book.markConnected(peerId1, addresses[0])
    let verifiedTime =
      book.entries(peerId1).filterIt(it.address == addresses[0])[0].lastUpdated
    store.updatePeerInfo(IdentifyInfo(peerId: peerId1, addrs: addresses[1 .. ^1]))
    check addresses[0] in book[peerId1]
    check book.entries(peerId1).len == MaxPeerStoreAddrs
    check book.entries(peerId1).filterIt(it.address == addresses[0])[0].lastUpdated ==
      verifiedTime

  test "extend admits verified addresses when the book is full":
    for confidence in [AddressConfidence.High, AddressConfidence.Infinite]:
      let
        book = makeBook(1.hours, 1.hours, 1.hours)
        addresses = (1 .. MaxPeerStoreAddrs + 2).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
      book.extend(peerId1, addresses[0 ..< MaxPeerStoreAddrs], AddressConfidence.Low)
      book.extend(peerId1, @[addresses[^2]], confidence)
      check book.entries(peerId1).len == MaxPeerStoreAddrs + 1
      check book.entries(peerId1).anyIt(
        it.address == addresses[^2] and it.confidence == confidence
      )
      book.extend(peerId1, @[addresses[^1]], AddressConfidence.Medium)
      check addresses[^1] notin book[peerId1]

  test "extend removes expired entries before applying the address limit":
    let
      book = makeBook(1.hours, 1.hours, 1.hours)
      addresses = (1 .. MaxPeerStoreAddrs + 1).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
    book.extend(peerId1, addresses[0 ..< MaxPeerStoreAddrs], AddressConfidence.Low)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.hours
    book.extend(peerId1, @[addresses[^1]], AddressConfidence.Low)
    check book.entries(peerId1).len == MaxPeerStoreAddrs
    check addresses[0] notin book[peerId1]
    check addresses[^1] in book[peerId1]

  test "extend retains expired entries for connected peers":
    let
      peerStore = makeStore(1.seconds, 1.hours, 1.hours)
      book = peerStore[AddressBook]
      addresses = (1 .. MaxPeerStoreAddrs + 1).mapIt(ma("/ip4/127.0.0.1/tcp/" & $it))
    book.extend(peerId1, addresses[0 ..< MaxPeerStoreAddrs], AddressConfidence.Low)
    peerStore.markPeerConnected(peerId1)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    book.extend(peerId1, @[addresses[^1]], AddressConfidence.Low)
    check book.entries(peerId1).len == MaxPeerStoreAddrs
    check addresses[0] in book[peerId1]
    check addresses[^1] notin book[peerId1]

  test "isExpired - Low expires after low TTL":
    let ttls = AddressConfidenceTtls(low: 1.seconds, medium: 1.hours, high: 24.hours)
    let entry = AddressEntry(
      address: addr1,
      confidence: AddressConfidence.Low,
      lastUpdated: Moment.now() - 2.seconds,
    )
    check entry.isExpired(ttls)

  test "isExpired - Low not expired within TTL":
    let ttls = AddressConfidenceTtls(low: 1.hours, medium: 1.hours, high: 24.hours)
    let entry = AddressEntry(
      address: addr1, confidence: AddressConfidence.Low, lastUpdated: Moment.now()
    )
    check not entry.isExpired(ttls)

  test "isExpired - Medium expires after medium TTL":
    let ttls = AddressConfidenceTtls(low: 1.hours, medium: 1.seconds, high: 24.hours)
    let entry = AddressEntry(
      address: addr1,
      confidence: AddressConfidence.Medium,
      lastUpdated: Moment.now() - 2.seconds,
    )
    check entry.isExpired(ttls)

  test "isExpired - High expires after high TTL":
    let ttls = AddressConfidenceTtls(low: 1.hours, medium: 1.hours, high: 1.seconds)
    let entry = AddressEntry(
      address: addr1,
      confidence: AddressConfidence.High,
      lastUpdated: Moment.now() - 2.seconds,
    )
    check entry.isExpired(ttls)

  test "isExpired - Infinite never expires":
    let ttls = AddressConfidenceTtls(low: 0.seconds, medium: 0.seconds, high: 0.seconds)
    let entry = AddressEntry(
      address: addr1,
      confidence: AddressConfidence.Infinite,
      lastUpdated: Moment.now() - 365.days,
    )
    check not entry.isExpired(ttls)

  test "pruneExpired removes only expired entries, keeps live ones":
    let book = makeBook(1.seconds, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.extend(peerId1, @[addr2], AddressConfidence.Medium)
    # Back-date the Low entry so it's expired
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    book.pruneExpired()
    let remaining = book[peerId1]
    check:
      addr1 notin remaining
      addr2 in remaining

  test "pruneExpired removes peer from AddressBook when all addresses expire":
    let book = makeBook(1.seconds, 1.seconds, 1.seconds)
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    book.pruneExpired()
    check peerId1 notin book

  test "pruneExpired leaves other PeerStore books intact":
    let peerStore = PeerStore.new(
      nil,
      addressTtls =
        AddressConfidenceTtls(low: 1.seconds, medium: 1.seconds, high: 1.seconds),
    )
    peerStore[AgentBook][peerId1] = "go-libp2p"
    peerStore[KeyBook][peerId1] = peerId1.getPubKey().get()
    peerStore[AddressBook].set(peerId1, @[addr1], AddressConfidence.Low)
    peerStore[AddressBook].book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    peerStore[AddressBook].pruneExpired()
    check:
      peerId1 notin peerStore[AddressBook]
      peerStore[AgentBook][peerId1] == "go-libp2p"
      peerId1 in peerStore[KeyBook]

  test "markConnected upgrades existing address to High confidence":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.markConnected(peerId1, addr1)
    check book.entries(peerId1)[0].confidence == AddressConfidence.High

  test "markConnected adds address when not already present":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    let before = Moment.now()
    book.markConnected(peerId1, addr1)
    let after = Moment.now()
    let entries = book.entries(peerId1)
    require entries.len == 1
    check entries[0].lastUpdated >= before
    check entries[0].lastUpdated <= after
    check entries ==
      @[
        AddressEntry(
          address: addr1,
          confidence: AddressConfidence.High,
          lastUpdated: entries[0].lastUpdated,
        )
      ]

  test "markConnected refreshes lastUpdated so address is not expired":
    let book = makeBook(1.seconds, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    # Entry is expired as Low; markConnected should refresh it
    book.markConnected(peerId1, addr1)
    check not book.entries(peerId1)[0].isExpired(book.ttls)

  test "set does not downgrade High confidence to Low":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.High)
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    check book.entries(peerId1)[0].confidence == AddressConfidence.High

  test "set retains expired verified confidence without refreshing it":
    let book = makeBook(1.hours, 1.hours, 1.hours)
    book.set(peerId1, @[addr1, addr2], AddressConfidence.High)
    let expired = Moment.now() - 2.hours
    for entry in book.book[peerId1].mitems:
      entry.lastUpdated = expired
    book.set(peerId1, @[addr1], AddressConfidence.Medium)
    let entries = book.entries(peerId1)
    check entries ==
      @[
        AddressEntry(
          address: addr1, confidence: AddressConfidence.High, lastUpdated: expired
        )
      ]

  test "extend does not downgrade existing confidence":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.High)
    book.extend(peerId1, @[addr1], AddressConfidence.Low)
    check book.entries(peerId1)[0].confidence == AddressConfidence.High

  test "set lower confidence retains Medium confidence and refreshes it":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Medium)
    let before = Moment.now() - 1.minutes
    book.book[peerId1][0].lastUpdated = before
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    check book.entries(peerId1)[0].confidence == AddressConfidence.Medium
    check book.entries(peerId1)[0].lastUpdated > before

  test "extend ignores duplicate addresses without notifying subscribers":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Medium)
    let before = Moment.now() - 1.minutes
    book.book[peerId1][0].lastUpdated = before
    let recorded = newRecorder(book)
    let fullAddr = ma($addr1 & "/p2p/" & $peerId1)
    for confidence in [AddressConfidence.Low, AddressConfidence.High]:
      book.extend(peerId1, @[addr1, fullAddr], confidence)
    check book.entries(peerId1) ==
      @[
        AddressEntry(
          address: addr1, confidence: AddressConfidence.Medium, lastUpdated: before
        )
      ]
    check recorded[].len == 0

  test "set preserves High confidence address absent from incoming list":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.High)
    book.set(peerId1, @[addr2], AddressConfidence.Medium)
    let entries = book.entries(peerId1)
    check:
      entries.len == 2
      entries.filterIt(it.address == addr1)[0].confidence == AddressConfidence.High
      entries.filterIt(it.address == addr2)[0].confidence == AddressConfidence.Medium

  test "set merges preserved entries that normalize to same address":
    let
      book = makeBook(1.hours, 1.hours, 24.hours)
      fullAddr1 = ma($addr1 & "/p2p/" & $peerId1)
      older = Moment.now() - 2.seconds
      newer = Moment.now() - 1.seconds

    book.book[peerId1] = @[
      AddressEntry(
        address: addr1, confidence: AddressConfidence.High, lastUpdated: older
      ),
      AddressEntry(
        address: fullAddr1, confidence: AddressConfidence.Infinite, lastUpdated: newer
      ),
    ]

    book.set(peerId1, @[addr2], AddressConfidence.Medium)
    let
      entries = book.entries(peerId1)
      preserved = entries.filterIt(it.address == addr1)

    check entries.len == 2
    check preserved ==
      @[
        AddressEntry(
          address: addr1, confidence: AddressConfidence.Infinite, lastUpdated: newer
        )
      ]

  test "set does not preserve Low/Medium address absent from incoming list":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Medium)
    book.set(peerId1, @[addr2], AddressConfidence.Medium)
    check book[peerId1] == @[addr2]

  test "AddressBook strips terminal peer id from direct addresses":
    let
      book = makeBook(1.hours, 1.hours, 24.hours)
      fullAddr1 = ma($addr1 & "/p2p/" & $peerId1)
      fullAddr2 = ma($addr2 & "/p2p/" & $peerId2)

    book.set(peerId1, @[fullAddr1, addr1], AddressConfidence.Low)
    check book[peerId1] == @[addr1]

    book.extend(peerId1, @[fullAddr2], AddressConfidence.Medium)
    check book[peerId1] == @[addr1, addr2]

    book.markConnected(peerId1, fullAddr1)
    check entries(book, peerId1).filterIt(it.address == addr1)[0].confidence ==
      AddressConfidence.High

  test "AddressBook preserves relay peer id and strips destination peer id":
    let
      book = makeBook(1.hours, 1.hours, 24.hours)
      relayAddr = MultiAddress
        .init("/ip4/1.2.3.4/tcp/1234/p2p/" & $peerId2 & "/p2p-circuit")
        .get()
      relayAddrWithDst = ma($relayAddr & "/p2p/" & $peerId1)

    book.set(peerId1, @[relayAddr, relayAddrWithDst], AddressConfidence.Low)
    check book[peerId1] == @[relayAddr]

  test "[] hides expired entries while entries returns them raw":
    let book = makeBook(1.seconds, 1.hours, 24.hours)
    book.set(peerId1, @[addr1, addr2], AddressConfidence.Low)
    # Back-date addr2 past the low TTL, addr1 stays fresh.
    book.book[peerId1][1].lastUpdated = Moment.now() - 2.seconds
    check:
      # [] filters expired entries lazily, without any pruning.
      book[peerId1] == @[addr1]
      # entries returns the raw list, expired entry included.
      book.entries(peerId1).len == 2
      book.entries(peerId1).anyIt(it.address == addr2)

  test "contains reflects only non-expired entries":
    let book = makeBook(1.seconds, 1.hours, 24.hours)
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.set(peerId2, @[addr2], AddressConfidence.Low)
    # Expire peerId2's only entry without pruning it.
    book.book[peerId2][0].lastUpdated = Moment.now() - 2.seconds
    check:
      peerId1 in book
      # All expired entries makes 'contains' false, the raw entry remains.
      peerId2 notin book
      book.entries(peerId2).len == 1

  test "connected peer reads include expired entries":
    let peerStore = makeStore(1.seconds, 1.hours, 24.hours)
    peerStore[AddressBook].set(peerId1, @[addr1], AddressConfidence.Low)
    peerStore[AddressBook].book[peerId1][0].lastUpdated = Moment.now() - 2.seconds

    check:
      peerStore[AddressBook][peerId1].len == 0
      peerId1 notin peerStore[AddressBook]

    peerStore.markPeerConnected(peerId1)

    check:
      peerStore[AddressBook][peerId1] == @[addr1]
      peerId1 in peerStore[AddressBook]

  test "pruneExpired refreshes connected expired entries without notifying":
    let peerStore = makeStore(1.seconds, 1.hours, 24.hours)
    let book = peerStore[AddressBook]
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds

    let recorded = newRecorder(book)
    peerStore.markPeerConnected(peerId1)
    book.pruneExpired()

    check:
      book.entries(peerId1).len == 1
      not book.entries(peerId1)[0].isExpired(book.ttls)
      book[peerId1] == @[addr1]
      recorded[].len == 0

  test "markPeerDisconnected refreshes stale entries before unpinning":
    let peerStore = makeStore(1.seconds, 1.hours, 24.hours)
    let book = peerStore[AddressBook]
    book.set(peerId1, @[addr1], AddressConfidence.Low)

    peerStore.markPeerConnected(peerId1)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    peerStore.markPeerDisconnected(peerId1)

    check:
      book[peerId1] == @[addr1]
      peerId1 in book
      not book.entries(peerId1)[0].isExpired(book.ttls)

    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    book.pruneExpired()

    check:
      book.entries(peerId1).len == 0
      peerId1 notin book

  test "reads on an absent peer return empty and do not crash":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    check:
      book[peerId1].len == 0
      book.entries(peerId1).len == 0
      peerId1 notin book

  test "extend notifies subscribers":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    let recorded = newRecorder(book)
    book.extend(peerId1, @[addr1], AddressConfidence.Low)
    check recorded[] == @[peerId1]

  test "markConnected notifies subscribers":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    let recorded = newRecorder(book)
    book.markConnected(peerId1, addr1)
    check recorded[] == @[peerId1]

  test "set fires a change handler even when clearing an absent peer":
    let book = makeBook(1.hours, 1.hours, 24.hours)
    let recorded = newRecorder(book)
    # Clearing a peer that was never stored changes nothing,
    # yet set still notifies through its unconditional defer.
    # This differs from del and pruneExpired, which notify only on a real change.
    book.set(peerId1, newSeq[MultiAddress]())
    check recorded[] == @[peerId1]

  test "pruneExpired notifies changed peers and skips untouched ones":
    let
      book = makeBook(1.seconds, 1.hours, 24.hours)
      peerId3 = PeerId.random()
    # peerId1 keeps a fresh address but loses an expired one (partial eviction).
    book.set(peerId1, @[addr1], AddressConfidence.Low)
    book.extend(peerId1, @[addr2], AddressConfidence.Medium)
    book.book[peerId1][0].lastUpdated = Moment.now() - 2.seconds
    # peerId2's only address is expired (full eviction).
    book.set(peerId2, @[addr1], AddressConfidence.Low)
    book.book[peerId2][0].lastUpdated = Moment.now() - 2.seconds
    # peerId3 stays fresh and must not be touched.
    book.set(peerId3, @[addr2], AddressConfidence.Low)

    # Register after setup so only the prune notifications are recorded.
    let recorded = newRecorder(book)
    book.pruneExpired()

    check:
      peerId1 in recorded[]
      peerId2 in recorded[]
      peerId3 notin recorded[]

suite "AddressBook TTL pruning loop":
  let
    peerId1 = PeerId.random()
    addr1 = ma("/ip4/1.2.3.4/tcp/1234")

  proc makeStore(low, medium, high: Duration): PeerStore =
    PeerStore.new(
      nil, addressTtls = AddressConfidenceTtls(low: low, medium: medium, high: high)
    )

  proc addExpiredLow(peerStore: PeerStore) =
    # Store a Low address and back-date it past any short low TTL.
    peerStore[AddressBook].set(peerId1, @[addr1], AddressConfidence.Low)
    peerStore[AddressBook].book[peerId1][0].lastUpdated = Moment.now() - 1.seconds

  asyncTest "startAddressPruning runs the loop and prunes an expired entry":
    # low is the smallest positive TTL, so the loop interval tracks it.
    # medium and high are large, proving the cadence follows the minimum.
    let peerStore = makeStore(10.milliseconds, 1.hours, 24.hours)
    defer:
      peerStore.close()

    peerStore.addExpiredLow()

    peerStore.startAddressPruning()
    check not peerStore.pruneHandle.isNil

    checkUntilTimeout:
      peerStore[AddressBook].entries(peerId1).len == 0

  asyncTest "startAddressPruning does not start a loop when all TTLs are zero":
    # All-zero TTLs disable expiry, so the loop is never started.
    let peerStore = makeStore(0.seconds, 0.seconds, 0.seconds)
    peerStore.startAddressPruning()
    check peerStore.pruneHandle.isNil

  asyncTest "startAddressPruning is idempotent":
    let peerStore = makeStore(10.milliseconds, 1.hours, 24.hours)
    defer:
      peerStore.close()

    peerStore.startAddressPruning()
    let handle = peerStore.pruneHandle
    check not handle.isNil

    # A second call must not spawn a second loop or replace the handle.
    peerStore.startAddressPruning()
    check peerStore.pruneHandle == handle

  asyncTest "close cancels the loop and clears the handle":
    let peerStore = makeStore(10.milliseconds, 1.hours, 24.hours)
    peerStore.startAddressPruning()
    let handle = peerStore.pruneHandle
    check not handle.isNil

    peerStore.close()
    check peerStore.pruneHandle.isNil
    # cancelSoon only schedules cancellation, so wait until the loop terminates.
    checkUntilTimeout:
      handle.finished()

  asyncTest "close on a store that never started is a no-op":
    let peerStore = makeStore(10.milliseconds, 1.hours, 24.hours)
    peerStore.close()
    check peerStore.pruneHandle.isNil
