# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push gcsafe.}
{.push raises: [].}

import std/sequtils
import pkg/[chronos, chronicles, metrics]

import
  ../stream/connection,
  ../protocols/secure/secure,
  ../protocols/identify,
  ../muxers/muxer,
  ../multistream,
  ../connmanager,
  ../errors,
  results

export connmanager, connection, identify, secure, multistream

declarePublicCounter(
  libp2p_failed_upgrades_incoming, "incoming connections failed upgrades"
)
declarePublicCounter(
  libp2p_failed_upgrades_outgoing, "outgoing connections failed upgrades"
)

logScope:
  topics = "libp2p connection-upgrade"

type
  UpgradeFailedError* = object of LPError

  Upgrade* = ref object of RootObj
    ms*: MultistreamSelect
    secureManagers*: seq[Secure]

method upgrade*(
    self: Upgrade, conn: RawConn, peerId: Opt[PeerId]
): Future[Muxer] {.async: (raises: [CancelledError, LPError], raw: true), base.} =
  raiseAssert("[Upgrade.upgrade] abstract method not implemented!")

proc trySecure*(
    self: Upgrade, conn: RawConn, peerId: Opt[PeerId]
): Future[LPResult[SecureConn]] {.async: (raises: [CancelledError, LPError]).} =
  if self.secureManagers.len <= 0:
    return err("No secure managers registered")

  let negotiated =
    if conn.dir == Out:
      await self.ms.trySelect(conn, self.secureManagers.mapIt(it.codec))
    else:
      await MultistreamSelect.tryHandle(conn, self.secureManagers.mapIt(it.codec))
  let codec = negotiated.valueOr:
    return err($error)
  if codec.len == 0:
    return err("Unable to negotiate a secure channel")

  trace "Secure upgrade started", conn, protocol = codec
  let secureProtocol = self.secureManagers.filterIt(it.codec == codec)

  # ms.select should deal with the correctness of this
  # let's avoid duplicating checks but detect if it fails to do it properly
  doAssert(secureProtocol.len > 0)

  ok(await secureProtocol[0].secure(conn, peerId))

proc secure*(
    self: Upgrade, conn: RawConn, peerId: Opt[PeerId]
): Future[SecureConn] {.async: (raises: [CancelledError, LPError]).} =
  (await self.trySecure(conn, peerId)).valueOrRaise(UpgradeFailedError)
