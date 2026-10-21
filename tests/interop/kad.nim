# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, stew/byteutils
import ../../libp2p/[switch, builders, peerid, protocols/kademlia, wire]
import ../tools/[crypto, multiaddress]

proc kadInteropTest*(
    ourAddr: string,
    otherAddr: string,
    otherPeerId: PeerId,
    timeout: Duration = 5.minutes,
): Future[bool] {.async.} =
  ## Reusable Kademlia DHT interoperability test
  ## This proc can be used with any peer (nim-based or from other implementations)
  ## The peer at otherAddr must already be running before calling this
  var switch = SwitchBuilder
    .new()
    .withRng(rng())
    .withAddresses(@[ma(ourAddr)])
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

  let kad = KadDHT.new(
    switch,
    bootstrapNodes = @[(otherPeerId, @[ma(otherAddr)])],
    config = KadDHTConfig.new(quorum = 2),
    rng = rng(),
  )

  switch.mount(kad)

  await switch.start()
  defer:
    await switch.stop()

  let key = RecordKey.fromBytes("key".toBytes()).tryGet()
  let value = Value.fromBytes("value".toBytes())

  let res = await kad.putValue(key, value).wait(timeout)
  if res.isErr():
    echo "putValue failed: ", res.error
    return false

  # wait for other peer's kad to store the value
  await sleepAsync(2.seconds)

  # try to get the inserted value from peer
  let getRes = await kad.getValue(key).wait(timeout)
  if getRes.isErr():
    echo "getValue failed: ", getRes.error
    return false

  if getRes.get().value != value:
    echo "getValue did not return correct value"
    return false

  return true
