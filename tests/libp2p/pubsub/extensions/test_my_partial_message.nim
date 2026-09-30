# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import tables, stew/byteutils
import ../../../../libp2p/results
import ../../../../libp2p/protocols/pubsub/[gossipsub/partial_message]
import ../../../tools/[unittest]
import ./my_partial_message

suite "MyPartialMessage":
  test "partsMetadata":
    var pm = MyPartialMessage(
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable,
      want: @[4, 5, 6],
    )
    check pm.partsMetadata() ==
      MyPartsMetadata.have(@[3, 2, 1]) & MyPartsMetadata.want(@[4, 5, 6])

  test "materializeParts":
    var pm = MyPartialMessage(
      data: {1: "one".toBytes, 2: "two".toBytes, 3: "three".toBytes}.toTable
    )
    var dataRes: LPResult[PartsData]

    # exists: 1
    dataRes = pm.materializeParts(MyPartsMetadata.want(@[1]))
    check dataRes.isOk()
    check dataRes.get() == pm.data[1]

    # does not exist: 5
    dataRes = pm.materializeParts(MyPartsMetadata.want(@[5]))
    check dataRes.isOk()
    check dataRes.get().len == 0

    # exists: 2 + 3
    dataRes = pm.materializeParts(MyPartsMetadata.want(@[2, 3]))
    check dataRes.isOk()
    check dataRes.get() == pm.data[2] & pm.data[3]

    # exists: 2 + 3; ignored: 5, 6, 7, 9, 10
    dataRes = pm.materializeParts(MyPartsMetadata.want(@[2, 5, 6, 7, 3, 9, 10]))
    check dataRes.isOk()
    check dataRes.get() == pm.data[2] & pm.data[3]

    # metadata is not valid
    dataRes = pm.materializeParts(@[1.byte])
    check dataRes.isErr()

  test "store materializeParts":
    let pm = MyPartialMessage(groupId: "g".toBytes, data: {1: "one".toBytes}.toTable)
    let store = MyPartialMessageStore()
    store.messages[pm.groupId] = pm

    check store.materializeParts("t", pm.groupId, MyPartsMetadata.want(@[1])).get() ==
      pm.data[1]
    check store.materializeParts("t", "other".toBytes, MyPartsMetadata.want(@[1])).isErr()

  test "unionPartsMetadata":
    var res: LPResult[PartsData]

    res = unionPartsMetadata(
      MyPartsMetadata.want(@[1]), #
      MyPartsMetadata.want(@[2]),
    )
    check res.isOk()
    check res.get() == MyPartsMetadata.want(@[1, 2])

    res = unionPartsMetadata(
      MyPartsMetadata.want(@[1, 2, 3]), #
      MyPartsMetadata.have(@[1, 2]),
    )
    check res.isOk()
    check res.get() == MyPartsMetadata.have(@[1, 2]) & MyPartsMetadata.want(@[3])

    res = unionPartsMetadata(
      MyPartsMetadata.want(@[1, 2, 3]), #
      MyPartsMetadata.have(@[1, 2]) & MyPartsMetadata.want(@[3]),
    )
    check res.isOk()
    check res.get() == MyPartsMetadata.have(@[1, 2]) & MyPartsMetadata.want(@[3])
