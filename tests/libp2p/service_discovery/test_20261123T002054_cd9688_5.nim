# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import ../../../libp2p/protocols/kademlia/protobuf
import ../../tools/unittest

suite "Service discovery RPC type numbers":
  test "REGISTER uses protobuf field 1 value 6":
    check Message(msgType: Opt.some(MessageType.register)).encode() == @[8'u8, 6]
    let decoded = Message.decode(@[8'u8, 6])
    check decoded.isOk()
    if decoded.isOk():
      check decoded.get().msgType == Opt.some(MessageType.register)

  test "GET_ADS uses protobuf field 1 value 7":
    check Message(msgType: Opt.some(MessageType.getAds)).encode() == @[8'u8, 7]
    let decoded = Message.decode(@[8'u8, 7])
    check decoded.isOk()
    if decoded.isOk():
      check decoded.get().msgType == Opt.some(MessageType.getAds)
