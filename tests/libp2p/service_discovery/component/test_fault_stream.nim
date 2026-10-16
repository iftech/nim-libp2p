# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import std/strutils
import chronos, results
import
  ../../../../libp2p/[
    multiaddress,
    protocols/service_discovery/connection,
    protocols/service_discovery/types,
    stream/connection,
    switch,
  ]
import ../../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../../tools/[fault_stream, unittest]
import ../utils

proc sendOver(
    stream: FaultStream
): Future[LPResult[kad_protobuf.Message]] {.async: (raises: [CancelledError, LPError]).} =
  let clientNode = setupServiceDiscoveryNode()
  clientNode.switch = FaultSwitch.new(clientNode.switch, stream)
  let peerId = randomPeerId()
  clientNode.switch.peerStore[AddressBook][peerId] = @[makeMultiAddress("127.0.0.1")]
  await clientNode.send(
    peerId,
    kad_protobuf.Message(msgType: kad_protobuf.MessageType.getAds, key: makeServiceId()),
  )

suite "Service Discovery Component - Fault Stream":
  teardown:
    checkTrackers()

  asyncTest "cancelling an RPC interrupts writing and resets the stream":
    let stream = FaultStream.new(onWrite = Fault.Hang)
    defer:
      await stream.close()

    let pending = sendOver(stream)
    await stream.hung.wait()
    await pending.cancelAndWait()
    check:
      pending.cancelled()
      stream.cancels == 1
      stream.wasResetLocally()
      stream.reads == 0

  asyncTest "an RPC whose stream fails names the failed step":
    let failedWrite = FaultStream.new(onWrite = Fault.Fail)
    let eofRead = FaultStream.new()
    let junkReply = FaultStream.new(reply = @[3'u8, 0xFF, 0xFF, 0xFF])
    defer:
      for stream in [failedWrite, eofRead, junkReply]:
        await stream.close()

    check:
      $(await sendOver(failedWrite)).error() ==
        "connection writing failed: fault stream write failed"
      ($(await sendOver(eofRead)).error()).startsWith("connection reading failed")
      ($(await sendOver(junkReply)).error()).startsWith(
        "failed to decode message response"
      )
      not junkReply.wasResetLocally()
