# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles
import
  ../../../libp2p/protocols/kademlia/
    [types, routing_table, protobuf, get, provider, find]
import ../../../libp2p/[peerid, stream/connection]

type MockKadDHT* = ref object of KadDHT
  findNodeCalls*: seq[Key]
  findNodeTables*: seq[RoutingTable]
  getValueResponse*: Opt[Message]
  handleAddProviderMessage*: Opt[Message]
  handleAddProviderDelay*: Duration
  handleAddProviderCalls*: int
  handleFindNodeDelay*: Duration
  handleFindNodeCalls*: int
  handleFindNodeMalformedResponse*: bool
  findNodeStalls*: bool
  findNodeCancels*: int

proc stallUntilCancelled(kad: MockKadDHT) {.async: (raises: [CancelledError]).} =
  ## A lookup that only ends when the caller gives up on it.
  let stall = Future[void].Raising([CancelledError]).init("MockKadDHT.findNode")
  try:
    await stall
  except CancelledError as e:
    kad.findNodeCancels.inc()
    raise e

method findNode*(
    kad: MockKadDHT, target: Key, rtable: RoutingTable
): Future[seq[PeerId]] {.async: (raises: [CancelledError]).} =
  kad.findNodeCalls.add(target)
  kad.findNodeTables.add(rtable)
  if kad.findNodeStalls:
    await kad.stallUntilCancelled()
  rtable.findClosestPeerIds(target, kad.config.replication)

method findNode*(
    kad: MockKadDHT, target: Key
): Future[seq[PeerId]] {.async: (raises: [CancelledError]).} =
  kad.findNodeCalls.add(target)
  kad.findNodeTables.add(kad.rtable)
  if kad.findNodeStalls:
    await kad.stallUntilCancelled()
  kad.rtable.findClosestPeerIds(target, kad.config.replication)

method handleGetValue*(
    kad: MockKadDHT, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  let response = kad.getValueResponse.valueOr:
    await procCall handleGetValue(KadDHT(kad), stream, msg)
    return

  try:
    await stream.writeLp(response.encode())
  except LPStreamError as exc:
    debug "Failed to send malicious get-value response", stream = stream, err = exc.msg

method handleAddProvider*(
    kad: MockKadDHT, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  kad.handleAddProviderCalls.inc()
  await sleepAsync(kad.handleAddProviderDelay)
  await procCall handleAddProvider(
    KadDHT(kad), stream, kad.handleAddProviderMessage.valueOr(msg)
  )

method handleFindNode*(
    kad: MockKadDHT, stream: Stream, msg: Message
) {.async: (raises: [CancelledError]).} =
  kad.handleFindNodeCalls.inc()
  if kad.handleFindNodeDelay > ZeroDuration:
    await sleepAsync(kad.handleFindNodeDelay)
  if kad.handleFindNodeMalformedResponse:
    try:
      await stream.writeLp(@[0xFF'u8, 0xFF, 0xFF])
    except LPStreamError as exc:
      debug "Failed to send malformed find-node response",
        stream = stream, err = exc.msg
    return
  await procCall handleFindNode(KadDHT(kad), stream, msg)
