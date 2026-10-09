# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import ../../libp2p/[switch, peerinfo, peerstore, multiaddress, protocols/protocol]
import ../tools/[unittest, multiaddress, switch_builder]

const TestCodec = "/test/proto/1.0.0"

suite "Multistream - Component":
  teardown:
    checkTrackers()

  asyncTest "optimistic stream reads the response after a half-close":
    proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
      try:
        let request = string.fromBytes(await stream.readLp(1024))
        await stream.writeLp("re: " & request)
      except LPStreamError:
        raiseAssert "Unexpected LPStreamError in half-close protocol handler"
      finally:
        await stream.close()

    proc requestAfterHalfClose(address: MultiAddress) {.async.} =
      let switch1 = makeStandardSwitch(address)
      switch1.mount(LPProtocol.new(@[TestCodec], handle))
      let switch2 = makeStandardSwitch(address)
      await switch1.start()
      await switch2.start()
      defer:
        await allFutures(switch1.stop(), switch2.stop())

      await switch2.connect(switch1.peerInfo.peerId, switch1.peerInfo.addrs)
      checkUntilTimeout:
        TestCodec in switch2.peerStore[ProtoBook][switch1.peerInfo.peerId]

      let stream = await switch2.dial(switch1.peerInfo.peerId, TestCodec)

      await stream.writeLp("ping")
      await stream.close()
      check string.fromBytes(await stream.readLp(1024)) == "re: ping"

    await requestAfterHalfClose(TcpAutoAddress)
    await requestAfterHalfClose(QuicAutoAddress)
