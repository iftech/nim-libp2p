# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/sequtils
import pkg/[chronos, chronicles, metrics]

import ../upgrademngrs/upgrade, ../muxers/muxer
import ../connmanager
import ../utils/opt

export Upgrade

logScope:
  topics = "libp2p connection-upgrade"

const MuxerRequired = "a muxer is required for outgoing connections"

type MuxedUpgrade* = ref object of Upgrade
  muxers*: seq[MuxerProvider]
  streamHandler*: StreamHandler
  connManager*: Opt[ConnManager]

func getMuxerByCodec(self: MuxedUpgrade, muxerName: string): Opt[MuxerProvider] =
  if muxerName.len == 0 or muxerName == "na":
    return Opt.none(MuxerProvider)
  for m in self.muxers:
    if muxerName == m.codec:
      return Opt.some(m)
  Opt.none(MuxerProvider)

proc mux(
    self: MuxedUpgrade, secureConn: SecureConn
): Future[LPResult[Muxer]] {.async: (raises: [CancelledError, LPStreamError]).} =
  ## mux secure connection
  trace "Mux negotiation started", secureConn
  if self.muxers.len == 0:
    warn "Mux negotiation skipped", secureConn, reason = "no registered muxers"
    return err(MuxerRequired)

  let negotiated =
    case secureConn.dir
    of Direction.Out:
      await self.ms.trySelect(secureConn, self.muxers.mapIt(it.codec))
    of Direction.In:
      await MultistreamSelect.tryHandle(secureConn, self.muxers.mapIt(it.codec))
  let muxerName = negotiated.valueOr:
    return err($error)
  let muxerProvider = self.getMuxerByCodec(muxerName).valueOr:
    trace "Mux negotiation failed", secureConn, protocol = muxerName
    return err(MuxerRequired)

  trace "Mux negotiation completed", secureConn, protocol = muxerName

  # create new muxer for connection
  let muxer = muxerProvider.newMuxer(secureConn)

  # install stream handler
  muxer.streamHandler = self.streamHandler
  muxer.handler = muxer.handle()
  ok(muxer)

proc tryUpgrade*(
    self: MuxedUpgrade, conn: RawConn, peerId: Opt[PeerId]
): Future[LPResult[Muxer]] {.async: (raises: [CancelledError, LPError]).} =
  trace "Connection upgrade started", conn, direction = conn.dir

  let sconn = ?(await self.trySecure(conn, peerId))
  if sconn == nil:
    return err("unable to secure connection, stopping upgrade")

  let muxer = ?(await self.mux(sconn))

  when defined(libp2p_agents_metrics):
    conn.shortAgent = muxer.connection.shortAgent

  if sconn.closed():
    await sconn.close()
    return err("Connection closed or missing peer info, stopping upgrade")

  trace "Connection upgrade completed", conn, secureConn = sconn, direction = conn.dir
  ok(muxer)

method upgrade*(
    self: MuxedUpgrade, conn: RawConn, peerId: Opt[PeerId]
): Future[Muxer] {.async: (raises: [CancelledError, LPError]).} =
  (await self.tryUpgrade(conn, peerId)).valueOrRaise(UpgradeFailedError)

proc new*(
    T: type MuxedUpgrade,
    muxers: seq[MuxerProvider],
    secureManagers: openArray[Secure] = [],
    ms: MultistreamSelect,
    connManager: Opt[ConnManager] = Opt.none(ConnManager),
): T =
  let upgrader =
    T(muxers: muxers, secureManagers: @secureManagers, ms: ms, connManager: connManager)

  upgrader.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
    trace "Protocol stream handler started", stream
    try:
      upgrader.connManager.ifValue(connManager):
        let ready = await connManager.waitForPeerReady(stream.peerId)
        if not ready:
          debug "Timed out waiting for peer ready before handling stream", stream
          return
      await upgrader.ms.handle(stream) # handle incoming stream
    except CancelledError:
      return
    finally:
      await stream.closeWithEOF()
    trace "Protocol stream handler completed", stream

  return upgrader

proc new*(
    T: type MuxedUpgrade,
    muxers: seq[MuxerProvider],
    secureManagers: openArray[Secure] = [],
    ms: MultistreamSelect,
    connManager: ConnManager,
): T =
  T.new(muxers, secureManagers, ms, connManager.toOpt())
