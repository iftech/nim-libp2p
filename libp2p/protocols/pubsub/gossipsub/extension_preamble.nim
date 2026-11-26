# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, chronicles, tables, sequtils, algorithm, results, metrics
import ../../../[peerid]
import ../../../crypto/crypto
import ../rpc/messages
import ./[extensions_types, preamblestore, bandwidth]

logScope:
  topics = "libp2p gossipsub"

const preambleMessageSizeThreshold* = 40 * 1024 # 40KiB

declareCounter(
  libp2p_gossipsub_imreceiving_saved_messages,
  "number of duplicates avoided by imreceiving",
)

type
  PreambleExtensionConfig* = object
    maxPreamblePeerBudget*: int = 10
    maxHeIsReceiving*: int = 50
    broadcastRPC*: proc(msg: RPCMsg, peers: seq[PeerId]) {.gcsafe, raises: [].}
    hasSeen*: proc(mid: MessageId): bool {.gcsafe, raises: [].}
    meshAndDirectPeersForTopic*: proc(topic: string): seq[PeerId] {.gcsafe, raises: [].}

  PeerState = ref object
    heIsReceivings*: Table[MessageId, uint32]
    heIsSendings*: Table[MessageId, Moment]
    bandwidthTracking: BandwidthTracking

  PreambleExtension* = ref object of Extension
    rng: Rng
    config: PreambleExtensionConfig
    supportingPeers: seq[PeerId]
    preambleBudgetUsed: Table[PeerId, int]
    peerState: Table[PeerId, PeerState]
    ongoingReceives*: PreambleStore # list of messages we are receiving
    ongoingIWantReceives*: PreambleStore # list of iwant replies we are receiving

proc doAssert(config: PreambleExtensionConfig) =
  doAssert(
    config.maxPreamblePeerBudget > 0,
    "PreambleExtensionConfig.maxPreamblePeerBudget must be positive (> 0)",
  )
  doAssert(
    config.maxHeIsReceiving > 0,
    "PreambleExtensionConfig.maxHeIsReceiving must be positive (> 0)",
  )
  doAssert(
    config.broadcastRPC != nil, "PreambleExtensionConfig.broadcastRPC must be set"
  )
  doAssert(config.hasSeen != nil, "PreambleExtensionConfig.hasSeen must be set")
  doAssert(
    config.meshAndDirectPeersForTopic != nil,
    "PreambleExtensionConfig.meshAndDirectPeersForTopic must be set",
  )

proc new*(
    T: typedesc[PreambleExtension], config: PreambleExtensionConfig, rng: Rng
): PreambleExtension =
  config.doAssert()
  PreambleExtension(rng: rng, config: config)

method isSupported*(
    ext: PreambleExtension, pe: PeerExtensions
): bool {.gcsafe, raises: [].} =
  return pe.preambleExtension

method onNegotiated*(ext: PreambleExtension, peerId: PeerId) {.gcsafe, raises: [].} =
  ext.supportingPeers.add(peerId)

  var peerState = PeerState.new()
  peerState.bandwidthTracking =
    BandwidthTracking(download: ExponentialMovingAverage.init())
  ext.peerState[peerId] = peerState

method onRemovePeer*(ext: PreambleExtension, peerId: PeerId) {.gcsafe, raises: [].} =
  let i = ext.supportingPeers.find(peerId)
  if i != -1:
    ext.supportingPeers.delete(i)

  ext.peerState.del(peerId)

func medianValue(vals: seq[float]): float =
  if vals.len == 0:
    return 0

  let mid = vals.len div 2
  if vals.len mod 2 == 0:
    (vals[mid - 1] + vals[mid]) / 2
  else:
    vals[mid]

func medianDownloadRate(ext: PreambleExtension, peers: seq[PeerId]): float =
  peers
    .filterIt(ext.peerState.hasKey(it))
    .mapIt(ext.peerState.getOrDefault(it).bandwidthTracking.download.value())
    .sorted()
    .medianValue()

proc handlePreamble*(ext: PreambleExtension, peerId: PeerId, preambles: seq[Preamble]) =
  let startTime = Moment.now()
  let peerState =
    try:
      ext.peerState[peerId]
    except KeyError:
      return

  for preamble in preambles:
    let messageId = preamble.messageID.valueOr:
      trace "preamble messageId not set", peerId
      continue
    let topicId = preamble.topicID.valueOr:
      trace "preamble topicID not set", peerId
      continue

    let peerUsedBudget = ext.preambleBudgetUsed.getOrDefault(peerId)
    if peerUsedBudget >= ext.config.maxPreamblePeerBudget:
      return
    ext.preambleBudgetUsed[peerId] = peerUsedBudget + 1

    if ext.config.hasSeen(messageId):
      continue

    if peerState.heIsSendings.hasKey(messageId):
      continue

    if ext.ongoingReceives.hasKey(messageId):
      # TODO: add to conflicts_watch if length is different
      continue

    peerState.heIsSendings[messageId] = startTime

    var toSendPeers = ext.config.meshAndDirectPeersForTopic(topicId)
    var peers = toSendPeers.filterIt(it in ext.supportingPeers)

    let bytesPerSecond = peerState.bandwidthTracking.download.value()
    let transmissionTimeMs =
      calculateReceiveTimeMs(preamble.messageLength.get(0).int64, bytesPerSecond.int64)
    let expires = startTime + transmissionTimeMs.milliseconds

    # We send imreceiving only if received from mesh members
    if peerId notin peers:
      trace "preamble: ignoring out of mesh peer", peerId
      if not ext.ongoingIWantReceives.hasKey(messageId):
        ext.ongoingIWantReceives.insert(
          PreambleInfo.init(preamble, peerId, startTime, expires)
        )
      continue

    ext.ongoingReceives.insert(PreambleInfo.init(preamble, peerId, startTime, expires))

    # Send imreceiving only if received from faster mesh members
    if bytesPerSecond >= ext.medianDownloadRate(toSendPeers) and peers.len > 0:
      ext.config.broadcastRPC(RPCMsg.withIMReceiving(preamble), peers)

proc handleIMReceiving*(
    ext: PreambleExtension, peerId: PeerId, imreceivings: seq[IMReceiving]
) =
  let peerState =
    try:
      ext.peerState[peerId]
    except KeyError:
      return

  for imreceiving in imreceivings:
    let messageId = imreceiving.messageID.valueOr:
      trace "IMReceiving messageId not set", peerId
      continue
    let messageLength = imreceiving.messageLength.valueOr:
      trace "IMReceiving messageLength not set", peerId
      continue

    if peerState.heIsReceivings.len > ext.config.maxHeIsReceiving:
      return

    # Ignore if message length is different
    ext.ongoingReceives.withValue(messageId, pInfo):
      if pInfo.messageLength != messageLength:
        continue

    peerState.heIsReceivings[messageId] = messageLength
    # No need to check mcache. In that case, we might have already transmitted/transmitting

proc addPossiblePeerToQuery(
    ext: PreambleExtension, peerId: PeerId, messageId: MessageId
) =
  ext.ongoingReceives.addPossiblePeerToQuery(messageId, peerId)
  ext.ongoingIWantReceives.addPossiblePeerToQuery(messageId, peerId)

proc handleIDontWant(
    ext: PreambleExtension, peerId: PeerId, iDontWants: seq[ControlIWant]
) =
  try:
    var peerState = ext.peerState[peerId]
    for dontWant in iDontWants:
      for messageId in dontWant.messageIDs:
        peerState.heIsReceivings.del(messageId)
        ext.addPossiblePeerToQuery(peerId, messageId)
  except KeyError:
    discard

proc handleIHave*(ext: PreambleExtension, peerId: PeerId, messageId: MessageId): bool =
  if ext.ongoingReceives.hasKey(messageId) or ext.ongoingIWantReceives.hasKey(messageId):
    ext.addPossiblePeerToQuery(peerId, messageId)
    return true
  return false

method onHandleRPC*(
    ext: PreambleExtension, peerId: PeerId, rpc: RPCMsg
) {.gcsafe, raises: [].} =
  rpc.preambleExtension.ifValue(v):
    ext.handlePreamble(peerId, v.preamble)
    ext.handleIMReceiving(peerId, v.imreceiving)
  rpc.control.ifValue(v):
    ext.handleIDontWant(peerId, v.idontwant)

func filterOutMessagesBelowThreshold(msg: RPCMsg): RPCMsg =
  let preamble = msg.preambleExtension.get().preamble.filterIt(
      it.messageLength.isSome and it.messageLength.get() >= preambleMessageSizeThreshold
    )
  return RPCMsg(preambleExtension: Opt.some(PreambleExtensionRPC(preamble: preamble)))

proc preambleBroadcast*(ext: PreambleExtension, msg: RPCMsg, peers: seq[PeerId]) =
  let msgFiltered = filterOutMessagesBelowThreshold(msg)
  if msgFiltered.preambleExtension.get().preamble.len == 0:
    return

  let broadcastToPeers = peers.filterIt(it in ext.supportingPeers)
  if broadcastToPeers.len == 0:
    return

  ext.config.broadcastRPC(msgFiltered, broadcastToPeers)

proc preambleBroadcastIfNotReceiving*(
    ext: PreambleExtension, msg: RPCMsg, peers: seq[PeerId]
) =
  proc isMsgInIMReceiving(peerId: PeerId): bool =
    try:
      let msgId = msg.preambleExtension.get().preamble[0].messageID.valueOr:
        return false
      let peerState = ext.peerState[peerId]
      if peerState.heIsReceivings.hasKey(msgId):
        libp2p_gossipsub_imreceiving_saved_messages.inc
        return true
    except KeyError:
      return false
    return false

  let broadcastToPeers = peers.filterIt(not isMsgInIMReceiving(it))
  ext.preambleBroadcast(msg, broadcastToPeers)

proc preambleMsgReceived*(
    ext: PreambleExtension, peerId: PeerId, msgId: MessageId, msgLen: int
) =
  if msgLen < preambleMessageSizeThreshold:
    return

  ext.ongoingReceives.del(msgId)
  ext.ongoingIWantReceives.del(msgId)

  try:
    var peerState = ext.peerState[peerId]
    var startTime: Moment
    if peerState.heIsSendings.pop(msgId, startTime):
      peerState.bandwidthTracking.download.update(startTime, msgLen)
  except KeyError:
    discard

func selectPeerAtRandom(
    ext: PreambleExtension, possiblePeers: var seq[PeerId]
): Opt[PeerId] =
  ext.rng.shuffle(possiblePeers)
  for peerId in possiblePeers:
    if peerId in ext.supportingPeers:
      return Opt.some(peerId)
  return Opt.none(PeerId)

proc preambleExpirationTick*(ext: PreambleExtension) =
  let now = Moment.now()

  while true:
    var expired = ext.ongoingReceives.popExpired(now).valueOr:
      break

    var possiblePeers = expired.possiblePeersToQuery()
    let chosenPeer = ext.selectPeerAtRandom(possiblePeers).valueOr:
      trace "no peer available to send IWANT for an expiredOngoingReceive",
        messageID = expired.messageId
      continue

    let startsAt = Moment.now()
    ext.config.broadcastRPC(
      RPCMsg.withControl(ControlMessage.withIWant(expired.messageId)), @[chosenPeer]
    )

    let peerState = ext.peerState.getOrDefault(chosenPeer)
    let bytesPerSecond = peerState.bandwidthTracking.download.value()
    let transmissionTimeMs =
      calculateReceiveTimeMs(expired.messageLength.int64, bytesPerSecond.int64)
    let expires = startsAt + transmissionTimeMs.milliseconds

    expired.startsAt = startsAt
    expired.expiresAt = expires
    expired.sender = chosenPeer
    ext.ongoingIWantReceives.insert(expired)

  while true:
    let expiredIWant = ext.ongoingIWantReceives.popExpired(now).valueOr:
      break
    # TODO: what should we do here?
    discard expiredIWant

method onHeartbeat*(ext: PreambleExtension) {.gcsafe, raises: [].} =
  ext.preambleBudgetUsed.clear()
  ext.preambleExpirationTick()
