# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

when defined(libp2p_protobuf_metrics):
  import protobuf_serialization
  import
    ../../../libp2p/
      [routing_record, utils/protobuf, utils/protobuf_metrics, crypto/crypto]
  import ../../tools/[unittest, crypto, multiaddress]

  # A type that explicitly opts into metrics tracking.
  type MetricsTestMsg* {.proto2.} = object
    value* {.fieldNumber: 1, required, pint.}: uint64

  Protobuf.serializerFor([MetricsTestMsg], withMetrics = true, domain = "test")

  template counterValue(counter: untyped, label: string): float64 =
    try:
      counter.value(["test." & label])
    except exceptions.KeyError:
      0.0

  proc makePeerRecord(): PeerRecord =
    PeerRecord.init(PeerId.random(rng()).get(), @[ma("/ip4/127.0.0.1/tcp/1234")])

  suite "protobuf_metrics":
    test "PeerRecord encode does not increment sent counter (withMetrics = false)":
      let record = makePeerRecord()
      let before = counterValue(libp2p_protobuf_bytes_sent, "PeerRecord")
      discard encode(record)
      let after = counterValue(libp2p_protobuf_bytes_sent, "PeerRecord")
      check after == before

    test "PeerRecord decode does not increment received counter (withMetrics = false)":
      let record = makePeerRecord()
      let encoded = encode(record)
      let before = counterValue(libp2p_protobuf_bytes_received, "PeerRecord")
      discard PeerRecord.decode(encoded)
      let after = counterValue(libp2p_protobuf_bytes_received, "PeerRecord")
      check after == before

    test "encode increments byte and message counters":
      let msg = MetricsTestMsg(value: 42)
      let before = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let beforeMessages = counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      let encoded = encode(msg)
      let after = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let afterMessages = counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      check after == before + float64(encoded.len)
      check afterMessages == beforeMessages + 1.0

    test "decode increments byte and message counters":
      let msg = MetricsTestMsg(value: 42)
      let encoded = encode(msg)
      let before = counterValue(libp2p_protobuf_bytes_received, "MetricsTestMsg")
      let beforeMessages =
        counterValue(libp2p_protobuf_messages_received, "MetricsTestMsg")
      let decoded = MetricsTestMsg.decode(encoded)
      let after = counterValue(libp2p_protobuf_bytes_received, "MetricsTestMsg")
      let afterMessages =
        counterValue(libp2p_protobuf_messages_received, "MetricsTestMsg")
      check decoded.isOk
      check after == before + float64(encoded.len)
      check afterMessages == beforeMessages + 1.0

    test "encode leaves received byte and message counters unchanged":
      let msg = MetricsTestMsg(value: 42)
      let beforeRead = counterValue(libp2p_protobuf_bytes_received, "MetricsTestMsg")
      let beforeReadMessages =
        counterValue(libp2p_protobuf_messages_received, "MetricsTestMsg")
      discard encode(msg)
      let afterRead = counterValue(libp2p_protobuf_bytes_received, "MetricsTestMsg")
      let afterReadMessages =
        counterValue(libp2p_protobuf_messages_received, "MetricsTestMsg")
      check afterRead == beforeRead
      check afterReadMessages == beforeReadMessages

    test "decode leaves sent byte and message counters unchanged":
      let msg = MetricsTestMsg(value: 42)
      let encoded = encode(msg)
      let beforeWrite = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let beforeWriteMessages =
        counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      discard MetricsTestMsg.decode(encoded)
      let afterWrite = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let afterWriteMessages =
        counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      check afterWrite == beforeWrite
      check afterWriteMessages == beforeWriteMessages

    test "multiple encodes accumulate sent byte and message counters":
      let msg = MetricsTestMsg(value: 42)
      let before = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let beforeMessages = counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      let enc1 = encode(msg)
      let enc2 = encode(msg)
      let after = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let afterMessages = counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      check after == before + float64(enc1.len + enc2.len)
      check afterMessages == beforeMessages + 2.0

    test "multiple decodes accumulate received byte and message counters":
      let msg = MetricsTestMsg(value: 42)
      let encoded = encode(msg)
      let before = counterValue(libp2p_protobuf_bytes_received, "MetricsTestMsg")
      let beforeMessages =
        counterValue(libp2p_protobuf_messages_received, "MetricsTestMsg")
      discard MetricsTestMsg.decode(encoded)
      discard MetricsTestMsg.decode(encoded)
      let after = counterValue(libp2p_protobuf_bytes_received, "MetricsTestMsg")
      let afterMessages =
        counterValue(libp2p_protobuf_messages_received, "MetricsTestMsg")
      check after == before + float64(encoded.len * 2)
      check afterMessages == beforeMessages + 2.0

    test "byte and message counters track type labels independently":
      let msg = MetricsTestMsg(value: 42)
      let beforeMsg = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let beforeMsgMessages =
        counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      let beforeOther = counterValue(libp2p_protobuf_bytes_sent, "PeerRecord")
      let beforeOtherMessages =
        counterValue(libp2p_protobuf_messages_sent, "PeerRecord")
      discard encode(msg)
      let afterMsg = counterValue(libp2p_protobuf_bytes_sent, "MetricsTestMsg")
      let afterMsgMessages =
        counterValue(libp2p_protobuf_messages_sent, "MetricsTestMsg")
      let afterOther = counterValue(libp2p_protobuf_bytes_sent, "PeerRecord")
      let afterOtherMessages = counterValue(libp2p_protobuf_messages_sent, "PeerRecord")
      check afterMsg > beforeMsg
      check afterMsgMessages > beforeMsgMessages
      check afterOther == beforeOther
      check afterOtherMessages == beforeOtherMessages

    test "counter for unregistered label returns zero":
      check counterValue(libp2p_protobuf_bytes_received, "NonExistentType") == 0.0
      check counterValue(libp2p_protobuf_bytes_sent, "NonExistentType") == 0.0
      check counterValue(libp2p_protobuf_messages_sent, "NonExistentType") == 0.0
      check counterValue(libp2p_protobuf_messages_received, "NonExistentType") == 0.0
