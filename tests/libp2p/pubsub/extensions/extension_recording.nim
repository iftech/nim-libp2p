# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../../../libp2p/peerid
import ../../../../libp2p/stream/bridgestream
import
  ../../../../libp2p/protocols/pubsub/
    [gossipsub/extensions_types, gossipsub/extension_topic_streams, rpc/messages]

proc makeRPC*(extensions: ControlExtensions = ControlExtensions()): RPCMsg =
  return RPCMsg.withControl(ControlMessage.withExtensions(extensions))

type RecordingExtension* = ref object of Extension
  # basic implementation that records method calls.
  heartbeatCount*: int
  negotiatedPeers*: seq[PeerId]
  removedPeers*: seq[PeerId]
  handledRPC*: seq[RPCMsg]

method isSupported*(
    ext: RecordingExtension, pe: PeerExtensions
): bool {.gcsafe, raises: [].} =
  return pe.testExtension

method onHeartbeat*(ext: RecordingExtension) {.gcsafe, raises: [].} =
  ext.heartbeatCount.inc

method onNegotiated*(ext: RecordingExtension, peerId: PeerId) {.gcsafe, raises: [].} =
  ext.negotiatedPeers.add(peerId)

method onRemovePeer*(ext: RecordingExtension, peerId: PeerId) {.gcsafe, raises: [].} =
  ext.removedPeers.add(peerId)

method onHandleRPC*(
    ext: RecordingExtension, peerId: PeerId, rpc: RPCMsg
) {.gcsafe, raises: [].} =
  ext.handledRPC.add(rpc)

# Topic Streams recording callbacks

type TopicStreamsRecorder* = ref object
  # records the calls TopicStreams makes to its callbacks.
  outgoingStreams*: seq[Stream] # remote end of each dialed stream
  cancelledDials*: int
  received*: AsyncQueue[RPCMsg]
  violations*: int
  penalties*: int

proc new*(T: typedesc[TopicStreamsRecorder]): T =
  return T(received: newAsyncQueue[RPCMsg]())

proc dial*(recorder: TopicStreamsRecorder): TopicStreamDial =
  return proc(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
    let (local, remote) = bridgedConnections()
    recorder.outgoingStreams.add(remote)
    return local

proc pendingDial*(recorder: TopicStreamsRecorder): TopicStreamDial =
  return proc(): Future[Stream] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await newAsyncEvent().wait()
    except CancelledError as exc:
      inc recorder.cancelledDials
      raise exc
    raiseAssert "a pending dial completes only by cancellation"

proc receive*(recorder: TopicStreamsRecorder): TopicStreamReceive =
  return proc(msg: sink RPCMsg, size: int) {.async: (raises: [CancelledError]).} =
    await recorder.received.put(msg)

proc violation*(recorder: TopicStreamsRecorder): proc() {.gcsafe, raises: [].} =
  return proc() {.gcsafe, raises: [].} =
    inc recorder.violations

proc penalize*(recorder: TopicStreamsRecorder): proc() {.gcsafe, raises: [].} =
  return proc() {.gcsafe, raises: [].} =
    inc recorder.penalties

proc new*(
    T: typedesc[TopicStreams],
    recorder: TopicStreamsRecorder,
    config = TopicStreamsConfig(),
    maxMessageSize = 1024,
): T =
  return T.new(
    config,
    maxMessageSize,
    recorder.dial(),
    recorder.receive(),
    recorder.violation(),
    recorder.penalize(),
  )

proc closeOutgoingStreams*(recorder: TopicStreamsRecorder) {.async: (raises: []).} =
  for remote in recorder.outgoingStreams:
    await remote.close()
