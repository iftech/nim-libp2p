# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}
{.push raises: [].}

import std/importutils
import chronos
import ../../../libp2p/[transports/tcptransport, transports/tortransport, wire]
import ../../tools/[unittest, multiaddress]

proc failNextAccept(server: TcpTransport, failure: ref CatchableError) =
  privateAccess(TcpTransport)
  # Inject a completed listener failure without exhausting process descriptors.
  let pending = typeof(server.acceptFuts[0]).init("test failed accept")
  pending.fail(failure)
  server.acceptFuts = @[pending]

suite "Transport accept results":
  teardown:
    checkTrackers()

  asyncTest "TCP retryable failures preserve their cause and allow another accept":
    for failure in [
      (ref CatchableError)(newException(TransportTooManyError, "descriptor limit")),
      (ref CatchableError)(newException(TransportAbortedError, "connection aborted")),
    ]:
      let server = TcpTransport.new(upgrade = Upgrade())
      let client = TcpTransport.new(upgrade = Upgrade())
      await server.start(@[TcpAutoAddress])
      defer:
        await allFutures(client.stop(), server.stop())

      server.failNextAccept(failure)
      let failed = await server.accept()
      check failed.isErr
      check failed.error.kind == TransportAcceptErrorKind.Retryable
      check failed.error.message == $failure.name & ": " & failure.msg

      let accepting = server.accept()
      let outgoing = await client.dial(server.addrs[0])
      let incoming = (await accepting).get()
      check not incoming.isNil
      await allFutures(outgoing.close(), incoming.close())

  asyncTest "TCP closed and fatal listener failures are returned as errors":
    for (failure, kind) in [
      (
        (ref CatchableError)(newException(TransportUseClosedError, "listener closed")),
        TransportAcceptErrorKind.Closed,
      ),
      (
        (ref CatchableError)(newException(TransportOsError, "listener failed")),
        TransportAcceptErrorKind.Fatal,
      ),
    ]:
      let server = TcpTransport.new(upgrade = Upgrade())
      await server.start(@[TcpAutoAddress])
      defer:
        await server.stop()
      server.failNextAccept(failure)
      let accepted = await server.accept()
      check accepted.isErr
      check accepted.error.kind == kind
      check accepted.error.message == $failure.name & ": " & failure.msg

  asyncTest "TCP rejects a connection whose addresses cannot be read":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()
    let accepting = server.servers[0].accept()
    let peer = await connect(server.addrs[0])
    defer:
      await peer.closeWait()
    let accepted = await accepting
    await accepted.closeWait()
    let pending = typeof(server.acceptFuts[0]).init("test closed connection")
    pending.complete(accepted)
    server.acceptFuts = @[pending]

    let rejected = await server.accept()
    check rejected.isErr
    check rejected.error.kind == TransportAcceptErrorKind.Retryable

  asyncTest "Tor propagates TCP accept failures before accessing the connection":
    privateAccess(TorTransport)
    let server = TorTransport.new(initTAddress("127.0.0.1:9050"), upgrade = Upgrade())
    await server.start(
      @[
        ma(
          "/ip4/127.0.0.1/tcp/0/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80"
        )
      ]
    )
    defer:
      await server.stop()
    server.tcpTransport.failNextAccept(
      newException(TransportAbortedError, "connection aborted")
    )
    let accepted = await server.accept()
    check accepted.isErr
    check accepted.error.kind == TransportAcceptErrorKind.Retryable
    check accepted.error.message == "TransportAbortedError: connection aborted"
