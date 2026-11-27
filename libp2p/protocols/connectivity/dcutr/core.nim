# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import ../../../protocodec
import std/sequtils

import chronos, chronicles
import stew/objects
import protobuf_serialization, protobuf_serialization/std/enums
import results

import
  ../../../multiaddress,
  ../../../connmanager,
  ../../../dial,
  ../../../errors,
  ../../../muxers/muxer,
  ../../../stream/connection,
  ../../../utils/protobuf

export multiaddress

const DcutrCodec* = ProtoCodec("/libp2p/dcutr")

# Implements https://github.com/libp2p/specs/blob/master/relay/DCUtR.md#rpc-messages

type
  MsgType* {.pure.} = enum
    Connect = 100
    Sync = 300

  DcutrMsg* {.proto2.} = object
    msgType* {.fieldNumber: 1, required, ext.}: MsgType
    addrs* {.fieldNumber: 2, ext.}: seq[MultiAddress]

  DcutrError* = object of LPError

func shortLog*(msg: DcutrMsg): auto =
  (msgType: msg.msgType, addresses: msg.addrs.shortLog)

chronicles.formatIt(DcutrMsg):
  shortLog(it)

Protobuf.serializerFor([DcutrMsg], withMetrics = true, domain = "dcutr")

proc expectDcutrConnection*(
    connManager: ConnManager, peerId: PeerId, dir: Direction
): Future[Muxer].Raising([AlreadyExpectingConnectionError, CancelledError]) {.
    raises: [DcutrError]
.} =
  let expected = connManager.expectConnection(peerId, dir)
  if expected.failed() and expected.error() of AlreadyExpectingConnectionError:
    let err = expected.error()
    raise newException(DcutrError, err.msg, err)

  expected

proc send*(
    stream: Stream, msgType: MsgType, addrs: seq[MultiAddress]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  let pb = DcutrMsg(msgType: msgType, addrs: addrs).encode()
  await stream.writeLp(pb)

proc waitExpectedConnection*[T](
    fut: Future[T]
): Future[void].Raising([DialFailedError, CancelledError]) {.raises: [].} =
  let expected = Future[void].Raising([DialFailedError, CancelledError]).init(
      "Dcutr.waitExpectedConnection"
    )

  fut.addCallback proc(udata: pointer) {.raises: [].} =
    if expected.finished:
      return

    if fut.completed():
      expected.complete()
    elif fut.cancelled():
      expected.cancelSoon()
    else:
      let err = fut.error()
      expected.fail(newException(DialFailedError, err.msg, err))

  expected

proc getHolePunchableAddrs*(
    addrs: seq[MultiAddress]
): seq[MultiAddress] {.raises: [LPError].} =
  var res = newSeq[MultiAddress]()
  for a in addrs:
    # This is necessary to also accept addrs like /ip4/198.51.100/tcp/1234/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N
    if [TCP, mapAnd(TCP_DNS, P2PPattern), mapAnd(TCP_IP, P2PPattern)].anyIt(it.match(a)):
      res.add(a[0 .. 1].tryGet())
    elif [QUIC_V1, mapAnd(QUIC_V1_DNS, P2PPattern), mapAnd(QUIC_V1_IP, P2PPattern)].anyIt(
      it.match(a)
    ):
      res.add(a[0 .. 2].tryGet())
  return res
