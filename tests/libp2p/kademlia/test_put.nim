# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
import std/times except hours, milliseconds, minutes, seconds
import chronos
import ../../../libp2p/[protocols/kademlia, switch, builders, multihash]
import ../../tools/[lifecycle, unittest]
import ./utils.nim

suite "KadDHT Put":
  teardown:
    checkTrackers()

  asyncTest "PUT_VALUE stores record at both sender and target peer":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    # Both nodes start with empty data tables
    check:
      kads[0].dataTable.len == 0
      kads[1].dataTable.len == 0

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3, 4, 5]
    discard await kads[1].putValue(key, value)

    # After putValue, both nodes should have the record
    check:
      kads[0].containsData(key, value)
      kads[1].containsData(key, value)

  asyncTest "PUT_VALUE requires validation on both sender and receiver":
    let kads = setupKadSwitches(2, validator = RestrictiveValidator())
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3, 4, 5]

    # Both validators reject -> putValue fails, nothing stored
    check:
      (await kads[1].putValue(key, value)).isErr()
      kads[0].dataTable.len == 0

    # Only receiver accepts -> sender validation still fails
    kads[0].config.validator = PermissiveValidator()
    check:
      (await kads[1].putValue(key, value)).isErr()
      kads[0].dataTable.len == 0

    # Both validators accept -> putValue succeeds
    kads[1].config.validator = PermissiveValidator()
    check:
      (await kads[1].putValue(key, value)).isOk()
      kads[0].containsData(key, value)
      kads[1].containsData(key, value)

  asyncTest "PUT_VALUE sets timeReceived in RFC3339 format":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3, 4, 5]
    discard await kads[1].putValue(key, value)

    # Parse the stored timestamp
    let storedTime: string = kads[0].dataTable[key].time
    let now = times.now().utc
    let parsed = storedTime.parse(initTimeFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"), utc())

    # Timestamp should be very recent (within 2 seconds of now)
    let elapsed = now - parsed
    check elapsed < times.initDuration(seconds = 2)

  asyncTest "PUT_VALUE uses selector to choose best value":
    let kads = setupKadSwitches(2, selector = OthersSelector())
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3, 4, 5]
    let emptyVal: seq[byte] = @[]

    # Store initial value
    discard await kads[0].putValue(key, value)
    check kads[1].containsData(key, value)

    # With OthersSelector, new value is rejected in favor of existing
    discard await kads[0].putValue(key, emptyVal)
    check kads[1].containsData(key, value)

    # Switch to CandSelector (accepts first/new value)
    kads[0].config.selector = CandSelector()
    kads[1].config.selector = CandSelector()

    # Now the new value replaces the old one
    discard await kads[0].putValue(key, emptyVal)
    check kads[1].containsData(key, emptyVal)

  asyncTest "PUT_VALUE rejects mismatched Message.key and Record.key":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    # Create two different keys to simulate mismatch
    let msgKey = MultiHash.digest("sha2-256", [byte 0, 1, 2, 3, 4]).get().toKey()
    let recordKey = MultiHash.digest("sha2-256", [byte 0, 0, 0, 0, 0]).get().toKey()
    check msgKey != recordKey

    # Build a malformed PUT_VALUE message with mismatched keys
    let msg = Message(
      msgType: MessageType.putValue,
      key: msgKey,
      record: Record(key: recordKey, value: Value.init([1.byte, 2, 3, 4, 5])),
    )

    # Send directly via handlePutValue to test the validation logic
    let conn = await kads[1].switch.dial(
      kads[0].switch.peerInfo.peerId, kads[0].switch.peerInfo.addrs, kads[0].codec
    )

    await kads[0].handlePutValue(conn, msg)

    # Neither key should have data stored - the request should be rejected
    check:
      kads[0].containsNoData(msgKey)
      kads[0].containsNoData(recordKey)

  asyncTest "PUT_VALUE with no record / no value - malformed message handling":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let conn = await kads[1].switch.dial(
      kads[0].switch.peerInfo.peerId, kads[0].switch.peerInfo.addrs, kads[0].codec
    )

    let key = kads[0].rtable.selfId

    # PUT_VALUE with no record at all
    let msgNoRecord =
      Message(msgType: MessageType.putValue, key: key, record: Opt.none(Record))
    await kads[0].handlePutValue(conn, msgNoRecord)

    # No data should be stored
    check kads[0].containsNoData(key)

    # PUT_VALUE with record but no value
    let msgNoValue = Message(
      msgType: MessageType.putValue,
      key: key,
      record: Record(key: key, value: Opt.none(Value)),
    )

    await kads[0].handlePutValue(conn, msgNoValue)

    # No data should be stored
    check kads[0].containsNoData(key)

  asyncTest "PUT_VALUE response echoes request":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3, 4, 5]

    # Build the PUT_VALUE request message
    let request = Message(
      msgType: MessageType.putValue,
      key: key,
      record: Record(key: key, value: Value.init(value)),
    )

    let conn = await kads[1].switch.dial(
      kads[0].switch.peerInfo.peerId, kads[0].switch.peerInfo.addrs, kads[0].codec
    )

    # Call handlePutValue directly - it writes the response to conn
    await kads[0].handlePutValue(conn, request)

    # Read the echoed response
    let responseBytes = await conn.readLp(MaxMsgSize)
    let response = Message.decode(responseBytes).value()

    # response should be identical to the request
    check response == request

  asyncTest "PUT_VALUE stores binary data with null and high bytes":
    let kads = setupKadSwitches(2)
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId
    let value = @[0.byte, 0xFF, 0, 0xFF] # nulls and high bytes interleaved

    discard await kads[1].putValue(key, value)
    check kads[0].containsData(key, value)

  asyncTest "PUT_VALUE entries expire after recordExpirationInterval":
    # Use a short expiration interval so the test doesn't take long.
    # The stored timestamp has second-level precision, so we use 2s to avoid
    # sub-second rounding causing premature expiry in the containsData check.
    let kads = setupKadSwitches(
      2,
      recordExpirationInterval = 2.seconds,
      cleanupDataEntriesInterval = 100.milliseconds,
    )
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3, 4, 5]
    discard await kads[1].putValue(key, value)

    # Value is present right after insertion
    check:
      kads[0].containsData(key, value)
      kads[1].containsData(key, value)

    # Wait until both the expiration interval AND a cleanup cycle have elapsed
    checkUntilTimeout:
      kads[0].containsNoData(key)
      kads[1].containsNoData(key)

  asyncTest "isExpired returns correct values for various intervals":
    let now = times.now().utc
    let oneHourAgo = now - times.initDuration(hours = 1)
    let twoDaysAgo = now - times.initDuration(hours = 48)

    let freshRecord = EntryRecord(value: @[1.byte], time: now.format(TimestampFormat))
    let oldRecord =
      EntryRecord(value: @[1.byte], time: oneHourAgo.format(TimestampFormat))
    let veryOldRecord =
      EntryRecord(value: @[1.byte], time: twoDaysAgo.format(TimestampFormat))

    # Fresh record should not be expired even with short intervals
    check not isExpired(freshRecord, 30.minutes)
    check not isExpired(freshRecord, 24.hours)

    # 1-hour-old record: expired with 30-minute TTL, not with 2-hour TTL
    check isExpired(oldRecord, 30.minutes)
    check not isExpired(oldRecord, 2.hours)

    # 2-day-old record: always expired for any sane TTL including default 24h
    check isExpired(veryOldRecord, 24.hours)
    check isExpired(veryOldRecord, 2.hours)

    # Record with an unparseable timestamp is treated as expired
    let badRecord = EntryRecord(value: @[1.byte], time: "not-a-timestamp")
    check isExpired(badRecord, 24.hours)

  asyncTest "PUT_VALUE without a key or with an invalid record is not stored":
    let kads = setupKadSwitches(2, validator = RestrictiveValidator())
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let conn = await kads[1].switch.dial(
      kads[0].switch.peerInfo.peerId, kads[0].switch.peerInfo.addrs, kads[0].codec
    )
    defer:
      await conn.close()

    let key = kads[0].rtable.selfId
    let record = Record(key: key, value: Value.init([1.byte, 2, 3]))

    await kads[0].handlePutValue(
      conn, Message(msgType: MessageType.putValue, record: record)
    )
    check kads[0].containsNoData(key)

    await kads[0].handlePutValue(
      conn, Message(msgType: MessageType.putValue, key: key, record: record)
    )
    check kads[0].containsNoData(key)

  asyncTest "RPC handlers survive a reply write on a closed stream":
    let kads = @[
      setupKad(testKadConfig(providerRejection = true)),
      setupKad(testKadConfig(providerRejection = true)),
    ]
    startAndDeferStop(kads)

    await connect(kads[0], kads[1])

    let conn = await kads[1].switch.dial(
      kads[0].switch.peerInfo.peerId, kads[0].switch.peerInfo.addrs, kads[0].codec
    )
    await conn.close()

    let key = kads[0].rtable.selfId
    let value = @[1.byte, 2, 3]

    await kads[0].handlePutValue(
      conn,
      Message(
        msgType: MessageType.putValue,
        key: key,
        record: Record(key: key, value: Value.init(value)),
      ),
    )
    check kads[0].containsData(key, value)

    await kads[0].handleGetValue(conn, Message(msgType: MessageType.getValue, key: key))
    await kads[0].handleFindNode(conn, Message(msgType: MessageType.findNode, key: key))
    await kads[0].handleAddProvider(
      conn,
      Message(
        msgType: MessageType.addProvider,
        key: key,
        providerPeers: @[kads[1].switch.peerInfo.toPeer()],
      ),
    )
    await kads[0].handleGetProviders(
      conn, Message(msgType: MessageType.getProviders, key: key)
    )
