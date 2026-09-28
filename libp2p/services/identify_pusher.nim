# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## `IdentifyPusher` orchestrates the IdentifyPush protocol as a Switch Service.
##
## Tracks which connected peers advertise the IdentifyPush codec, keeps that
## set in sync with connect / disconnect / re-identify events, and broadcasts
## our updated `PeerInfo` to every tracked peer when triggered.
##
## ### Lifecycle
##
## - **setup**: Initializes the identify push protocol and mounts it to the switch.
## - **start**: Registers event handlers for peer connect/disconnect and enables
##   automatic broadcasting when peer info changes. Called by the switch after
##   it has been fully started.
## - **stop**: Cleans up event handlers and cancels any pending broadcasts.
##
## ### Broadcasting Behavior
##
## Broadcasting is triggered automatically when:
## - The local `PeerInfo` changes (via observer pattern)
## - A peer connects and supports IdentifyPush
##
## It can also be triggered manually via `broadcast`. Each push is fire-and-forget
## and runs in the background.

{.push raises: [].}

import std/[sets, sequtils]
import chronos, chronicles
import
  ../protocols/identify,
  ../peerinfo,
  ../peerid,
  ../peerstore,
  ../connmanager,
  ../multistream,
  ../stream/connection,
  ../muxers/muxer,
  ../utils/future,
  ../switch

export identify

logScope:
  topics = "libp2p identify"

type
  PushSendFut = Future[void].Raising([CancelledError])

  IdentifyPusher* = ref object of Service
    identifyPush*: IdentifyPush
    pushPeers: HashSet[PeerId]
    started: bool
    ongoingSend: seq[PushSendFut]
    connManager: ConnManager
    peerStore: PeerStore
    peerInfo: PeerInfo
    onIdentifiedHandler: PeerEventHandler
    onLeftHandler: PeerEventHandler
    onPeerInfoUpdated: PeerInfoObserver

proc new*(T: type IdentifyPusher): T =
  T()

proc sendOne(p: IdentifyPusher, peerId: PeerId) {.async: (raises: [CancelledError]).} =
  ## Sends an IdentifyPush message to a single peer.
  ##
  ## Opens a new stream via the peer's muxer, negotiates the IdentifyPush protocol,
  ## and pushes the current peer info. Errors are logged but do not propagate.

  let muxer = p.connManager.selectMuxer(peerId)
  if muxer.isNil:
    return
  var stream: Stream
  var pushCompleted = false
  try:
    stream = await muxer.newStream()
    if stream.isNil:
      trace "could not open new stream", peerId
      return

    if await MultistreamSelect.select(stream, IdentifyPushCodec):
      await p.identifyPush.push(p.peerInfo, stream)
      pushCompleted = true
  except CancelledError as e:
    raise e
  except MuxerError as e:
    trace "failed to open stream for identify push", err = e.msg, peerId
  except MultiStreamError as e:
    trace "multistream negotiation failed for identify push", err = e.msg, peerId
  except LPStreamError as e:
    trace "stream error during identify push", err = e.msg, peerId
  finally:
    if not stream.isNil:
      if pushCompleted:
        await noCancel stream.closeWithEOF()
      else:
        await noCancel stream.reset()

proc broadcast(p: IdentifyPusher) =
  ## Send an IdentifyPush message with our current `peerInfo` to every
  ## connected peer that advertises the IdentifyPush protocol.
  ## Each send runs as a background future; this proc returns immediately
  ## without blocking the caller.
  if not p.started:
    return

  for peerId in p.pushPeers.toSeq():
    let fut = p.sendOne(peerId)
    p.ongoingSend.add(fut)
    fut.addCallback proc(udata: pointer) =
      let idx = p.ongoingSend.find(fut)
      if idx >= 0:
        p.ongoingSend.del(idx)

method setup*(p: IdentifyPusher, switch: Switch) {.raises: [ServiceSetupError].} =
  p.peerStore = switch.peerStore
  p.connManager = switch.connManager
  p.peerInfo = switch.peerInfo

  proc onIncomingPush(info: IdentifyInfo) {.async.} =
    if not p.started:
      return

    p.peerStore.updatePeerInfo(info)
    if IdentifyPushCodec in info.protos:
      p.pushPeers.incl(info.peerId)
    else:
      p.pushPeers.excl(info.peerId)

  p.identifyPush = IdentifyPush.new(onIncomingPush)

  switch.tryMount(p.identifyPush).isOkOr:
    raise newException(
      ServiceSetupError, "IdentifyPusher could not mount IdentifyPush. Reason: " & error
    )

method start*(p: IdentifyPusher, switch: Switch) {.async: (raises: [CancelledError]).} =
  if p.started:
    return

  p.started = true

  proc onPeerInfoUpdated(_: PeerInfo) {.gcsafe, raises: [].} =
    p.broadcast()

  p.onPeerInfoUpdated = onPeerInfoUpdated
  p.peerInfo.addObserver(p.onPeerInfoUpdated)

  proc onIdentified(
      peerId: PeerId, _: PeerEvent
  ) {.async: (raises: [CancelledError]).} =
    if IdentifyPushCodec in p.peerStore[ProtoBook][peerId]:
      p.pushPeers.incl(peerId)
    else:
      p.pushPeers.excl(peerId)

  proc onLeft(peerId: PeerId, _: PeerEvent) {.async: (raises: [CancelledError]).} =
    p.pushPeers.excl(peerId)

  p.onIdentifiedHandler = onIdentified
  p.onLeftHandler = onLeft
  p.connManager.addPeerEventHandler(onIdentified, PeerEventKind.Identified)
  p.connManager.addPeerEventHandler(onLeft, PeerEventKind.Left)
  info "Identify push service started"

method stop*(p: IdentifyPusher, switch: Switch) {.async: (raises: [CancelledError]).} =
  if not p.started:
    return

  info "Stopping identify push service"
  p.started = false

  if not p.onIdentifiedHandler.isNil:
    p.connManager.removePeerEventHandler(
      p.onIdentifiedHandler, PeerEventKind.Identified
    )
    p.onIdentifiedHandler = nil
  if not p.onLeftHandler.isNil:
    p.connManager.removePeerEventHandler(p.onLeftHandler, PeerEventKind.Left)
    p.onLeftHandler = nil
  if not p.onPeerInfoUpdated.isNil:
    p.peerInfo.removeObserver(p.onPeerInfoUpdated)
    p.onPeerInfoUpdated = nil

  let pending = move(p.ongoingSend)
  await pending.cancelAndWait()

  p.pushPeers.clear()
