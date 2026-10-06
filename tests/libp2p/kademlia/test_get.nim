# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import ../../../libp2p/[protocols/kademlia, switch, builders]
import ../../tools/[lifecycle, topology, unittest]
import ./utils

suite "KadDHT Get":
  teardown:
    checkTrackers()

  asyncTest "Get from peer":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    kads[0].dataTable.insert(key, value, Timestamp.now())

    check:
      kads[0].containsData(key, value)
      kads[1].containsNoData(key)

    let record = await kads[1].getValue(key, quorumOverride = Opt.some(1))

    check:
      record.get().value == value
      kads[0].containsData(key, value)
      kads[1].containsData(key, value)

  asyncTest "Get value that is locally present":
    let kads = setupKadSwitches(1)
    startAndDeferStop(kads)

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    kads[0].dataTable.insert(key, value, Timestamp.now())

    check:
      kads[0].containsData(key, value)
      (await kads[0].getValue(key, quorumOverride = Opt.some(1))).get().value == value

  asyncTest "Divergent getVal responses from peers":
    let kads = setupKadSwitches(5, DefaultEntryValidator(), DefaultEntrySelector())
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key = kads[0].rtable.selfId
      bestValue = @[1.byte, 2, 3, 4, 5]
      worstValue = @[1.byte, 2, 3, 4, 6]

    kads[1].dataTable.insert(key, bestValue, Timestamp.now())
    kads[2].dataTable.insert(key, worstValue, Timestamp.now())
    kads[3].dataTable.insert(key, bestValue, Timestamp.now())
    kads[4].dataTable.insert(key, bestValue, Timestamp.now())

    check:
      kads[0].containsNoData(key)
      kads[1].containsData(key, bestValue)
      kads[2].containsData(key, worstValue)
      kads[3].containsData(key, bestValue)
      kads[4].containsData(key, bestValue)

    let record = await kads[0].getValue(key, quorumOverride = Opt.some(3))

    # now all have bestvalue
    check:
      record.get().value == bestValue
      kads[0].containsData(key, bestValue)
      kads[1].containsData(key, bestValue)
      kads[2].containsData(key, bestValue)
      kads[3].containsData(key, bestValue)
      kads[4].containsData(key, bestValue)

  asyncTest "Could not achieve quorum":
    let kads = setupKadSwitches(5, DefaultEntryValidator(), DefaultEntrySelector())
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    kads[1].dataTable.insert(key, value, Timestamp.now())

    check:
      kads[0].containsNoData(key)
      kads[1].containsData(key, value)
      kads[2].containsNoData(key)
      kads[3].containsNoData(key)
      kads[4].containsNoData(key)

    let record = await kads[0].getValue(key)
    check record.isErr()
    check record.error() == "Not enough valid records to achieve quorum, needed 5 got 1"

  asyncTest "Update peers with empty values":
    let kads = setupKadSwitches(5, DefaultEntryValidator(), DefaultEntrySelector())
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    kads[1].dataTable.insert(key, value, Timestamp.now())

    check:
      kads[0].containsNoData(key)
      kads[1].containsData(key, value)
      kads[2].containsNoData(key)
      kads[3].containsNoData(key)
      kads[4].containsNoData(key)

    # 1 is enough to make a decision
    let record = await kads[0].getValue(key, quorumOverride = Opt.some(1))

    # peers are updated
    check:
      record.get().value == value
      kads[0].containsData(key, value)
      kads[1].containsData(key, value)
      kads[2].containsData(key, value)
      kads[3].containsData(key, value)
      kads[4].containsData(key, value)

  asyncTest "Get updates routing table with closerPeers (no record)":
    # kads[2] <---> kads[0] (hub) <---> kads[1]
    let kads = setupKadSwitches(
      3, PermissiveValidator(), CandSelector(), @[], 1.seconds, 1.seconds
    )
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    let key = kads[0].rtable.selfId

    check:
      kads[2].hasKey(kads[0].rtable.selfId)
      not kads[2].hasKey(kads[1].rtable.selfId)

    # When kads[0] doesn't have the value, handleGetValue returns only closerPeers
    let record = await kads[2].getValue(key, quorumOverride = Opt.some(1))

    # kads[2] should discover kads[1] through the closerPeers in the response
    check record.isErr()
    checkUntilTimeout:
      kads[2].hasKey(kads[1].rtable.selfId)

  asyncTest "Get updates routing table with closerPeers (with record)":
    # kads[2] <---> kads[0] (hub) <---> kads[1]
    let kads = setupKadSwitches(
      3, PermissiveValidator(), CandSelector(), @[], 1.seconds, 1.seconds
    )
    startAndDeferStop(kads)

    await connectHub(kads[0], kads[1 ..^ 1])

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    kads[0].dataTable.insert(key, value, Timestamp.now())

    check:
      kads[2].hasKey(kads[0].rtable.selfId)
      not kads[2].hasKey(kads[1].rtable.selfId)

    # When kads[0] has the value, handleGetValue returns both record and closerPeers
    let record = await kads[2].getValue(key, quorumOverride = Opt.some(1))

    # kads[2] should discover kads[1] through the closerPeers in the response.
    check record.get().value == value
    checkUntilTimeout:
      kads[2].hasKey(kads[1].rtable.selfId)

  asyncTest "Quorum handling is ignored if quorum is 0 or 1":
    let kads = setupKadSwitches(
      3, PermissiveValidator(), CandSelector(), @[], 1.seconds, 1.seconds
    )
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key = kads[0].rtable.selfId
      valueLocal = @[1.byte, 1, 1, 1, 1]
      valueRemote = @[2.byte, 2, 2, 2, 2]

    # kad2 and kad3 have different values than kad1
    kads[0].dataTable.insert(key, valueLocal, Timestamp.now())
    kads[1].dataTable.insert(key, valueRemote, Timestamp.now())
    kads[2].dataTable.insert(key, valueRemote, Timestamp.now())

    # but when quorum is 0 or 1 we ignore remote values and use local value

    check:
      (await kads[0].getValue(key, quorumOverride = Opt.some(0))).get().value ==
        valueLocal
      (await kads[0].getValue(key, quorumOverride = Opt.some(1))).get().value ==
        valueLocal

  asyncTest "Get value rejects record where Record.key does not match requested key":
    let kad = setupKad()

    let
      key = kad.rtable.selfId
      wrongKey = @[1.byte, 1, 1, 1]
      getValueResponse = Opt.some(
        Message(
          msgType: MessageType.getValue,
          key: key,
          record: Opt.some(
            protobuf.Record(
              key: Key.init(wrongKey), # get value response with mismatched recored key
              value: Opt.some(Value.init([1.byte, 2, 3, 4])),
              timeReceived: Timestamp.now(),
            )
          ),
          closerPeers: @[],
        )
      )

    let mockKad = setupMockKad(getValueResponse = getValueResponse)

    startAndDeferStop(@[kad, mockKad])

    await connect(kad, mockKad)

    check kad.containsNoData(key)

    # Mock node returns a record with wrong Record.key
    let record = await kad.getValue(key, quorumOverride = Opt.some(1))

    # getValue should fail because the only response has mismatched key
    check:
      record.isErr()
      kad.containsNoData(key)
      kad.containsNoData(wrongKey)

  asyncTest "Get value rejects response without record":
    let kad = setupKad()

    let
      key = kad.rtable.selfId
      getValueResponse = Opt.some(
        Message(
          msgType: MessageType.getValue,
          key: key,
          record: Opt.none(protobuf.Record), # get value response with empty record
          closerPeers: @[],
        )
      )

    let mockKad = setupMockKad(getValueResponse = getValueResponse)

    startAndDeferStop(@[kad, mockKad])

    await connect(kad, mockKad)

    check kad.containsNoData(key)

    # Mock node returns a response without record
    let record = await kad.getValue(key, quorumOverride = Opt.some(1))

    check:
      record.isErr()
      kad.containsNoData(key)

  asyncTest "Get value rejects record without value":
    let kad = setupKad()

    let
      key = kad.rtable.selfId
      getValueResponse = Opt.some(
        Message(
          msgType: MessageType.getValue,
          key: key,
          record: Opt.some(
            protobuf.Record(
              key: key,
              value: Opt.none(Value), # get value response with empty record value
              timeReceived: Timestamp.now(),
            )
          ),
          closerPeers: @[],
        )
      )

    let mockKad = setupMockKad(getValueResponse = getValueResponse)

    startAndDeferStop(@[kad, mockKad])

    await connect(kad, mockKad)

    check kad.containsNoData(key)

    # Mock node returns a record without value
    let record = await kad.getValue(key, quorumOverride = Opt.some(1))

    check:
      record.isErr()
      kad.containsNoData(key)

  asyncTest "Get value succeeds with some peers returning mismatched keys":
    let kads = setupKadSwitches(3)

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]
      wrongKey = @[1.byte, 1, 1, 1]
      getValueResponse = Opt.some(
        Message(
          msgType: MessageType.getValue,
          key: key,
          record: Opt.some(
            protobuf.Record(
              key: Key.init(wrongKey), # get value response with mismatched recored key
              value: Opt.some(Value.init(value)),
              timeReceived: Timestamp.now(),
            )
          ),
          closerPeers: @[],
        )
      )

    let mockKad = setupMockKad(getValueResponse = getValueResponse)

    startAndDeferStop(kads & mockKad)

    await connectHub(kads[0], kads[1 ..^ 1] & mockKad)

    # Compliant nodes have valid records
    kads[1].dataTable.insert(key, value, Timestamp.now())
    kads[2].dataTable.insert(key, value, Timestamp.now())
    # mockKad will return mismatched key

    let record = await kads[0].getValue(key, quorumOverride = Opt.some(2))

    check:
      record.isOk()
      record.get().value == value
      mockKad.containsData(key, value) # mock node was updated

  asyncTest "Get value rejects records that fail validation":
    # Use RestrictiveValidator which rejects all records
    let kads = setupKadSwitches(2, RestrictiveValidator(), CandSelector())
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    # Insert directly into dataTable
    kads[1].dataTable.insert(key, value, Timestamp.now())

    check:
      kads[1].containsData(key, value)
      kads[0].containsNoData(key)

    # getValue should fail because RestrictiveValidator rejects the record
    let record = await kads[0].getValue(key, quorumOverride = Opt.some(1))

    check:
      record.isErr()
      kads[0].containsNoData(key)

  asyncTest "Get value succeeds when some peers are offline":
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    # All peers have the record
    kads[1].dataTable.insert(key, value, Timestamp.now())
    kads[2].dataTable.insert(key, value, Timestamp.now())
    kads[3].dataTable.insert(key, value, Timestamp.now())

    # Stop one peer before query
    await kads[3].switch.stop()
    # Query should still succeed with remaining peers (quorum=2)
    let record = await kads[0].getValue(key, quorumOverride = Opt.some(2))

    check:
      record.isOk()
      record.get().value == value

  asyncTest "Get value fails when too many peers are offline":
    let kads = setupKadSwitches(4)
    startAndDeferStop(kads)

    await connectStar(kads)

    let
      key = kads[0].rtable.selfId
      value = @[1.byte, 2, 3, 4, 5]

    # All peers have the record
    kads[1].dataTable.insert(key, value, Timestamp.now())
    kads[2].dataTable.insert(key, value, Timestamp.now())
    kads[3].dataTable.insert(key, value, Timestamp.now())

    # Stop two peers before query
    await kads[2].switch.stop()
    await kads[3].switch.stop()

    # Query should fail - need quorum of 3 but only 1 peer available
    let record = await kads[0].getValue(key, quorumOverride = Opt.some(3))

    check:
      record.isErr()

  asyncTest "Get value retrieves binary data with null and high bytes":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let
      key = kads[0].rtable.selfId
      value = @[0.byte, 0xFF, 0, 0xFF]

    kads[0].dataTable.insert(key, value, Timestamp.now())

    let record = await kads[1].getValue(key, quorumOverride = Opt.some(1))

    check:
      record.isOk()
      record.get().value == value

  asyncTest "GET_VALUE handler drops an expired record instead of serving it":
    let kads = setupKadSwitches(2, cleanupDataEntriesInterval = chronos.hours(1))
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[1].rtable.selfId
    kads[1].dataTable.insert(key, @[1.byte, 2, 3], "2000-01-01T00:00:00Z")

    let record = await kads[0].getValue(key, quorumOverride = Opt.some(1))

    check:
      record.isErr()
      kads[1].containsNoData(key)
