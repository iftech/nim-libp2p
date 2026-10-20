# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}
{.push raises: [].}

import std/importutils
import chronos
import ../../../libp2p/[transports/tcptransport, transports/tortransport, wire]
import ../../tools/[unittest, multiaddress]

proc failNextAccept[E: CatchableError](server: TcpTransport, failure: ref E) =
  privateAccess(TcpTransport)
  # Inject a completed failure before acceptance starts, without using real descriptors.
  let pending = typeof(server.acceptFuts[0]).init("test failed accept")
  pending.fail(failure)
  server.acceptFuts = @[pending]

suite "Transport accept retries":
  teardown:
    checkTrackers()

  for failure in ["descriptor exhaustion", "connection abort"]:
    asyncTest "TCP retries " & failure & " within one accept call with backoff":
      let server = TcpTransport.new(upgrade = Upgrade())
      let client = TcpTransport.new(upgrade = Upgrade())
      await server.start(@[TcpAutoAddress])
      defer:
        await allFutures(client.stop(), server.stop())

      if failure == "descriptor exhaustion":
        server.failNextAccept(newException(TransportTooManyError, "descriptor limit"))
      else:
        server.failNextAccept(newException(TransportAbortedError, "connection aborted"))
      let started = Moment.now()
      let accepting = server.accept()
      let outgoing = await client.dial(server.addrs[0])
      defer:
        await outgoing.close()
      let incoming = await accepting
      defer:
        await incoming.close()
      check not incoming.isNil
      check Moment.now() - started >= 100.milliseconds

  asyncTest "TCP terminal failures preserve their exception and cause":
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()

    let closed = newException(TransportUseClosedError, "listener closed")
    server.failNextAccept(closed)
    try:
      discard await server.accept()
      check false
    except TransportClosedError as exc:
      check exc.parent == closed

    # The failed call pre-arms another listener accept.
    privateAccess(TcpTransport)
    await server.acceptFuts.cancelAndWait()
    let fatal = newException(TransportOsError, "listener failed")
    server.failNextAccept(fatal)
    try:
      discard await server.accept()
      check false
    except TcpTransportError as exc:
      check exc.parent == fatal

  asyncTest "a TCP listener failure does not strand the other listeners":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    let client = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress, TcpAutoAddress])
    defer:
      await allFutures(client.stop(), server.stop())
    server.failNextAccept(newException(TransportAbortedError, "connection aborted"))
    server.acceptFuts.add(server.servers[1].accept())

    for address in [server.addrs[1], server.addrs[0]]:
      let accepting = server.accept()
      let outgoing = await client.dial(address)
      let incoming = await accepting
      check not incoming.isNil
      await allFutures(outgoing.close(), incoming.close())

  asyncTest "TCP skips a connection whose addresses cannot be read":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    let client = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await allFutures(client.stop(), server.stop())
    let accepting = server.servers[0].accept()
    let peer = await connect(server.addrs[0])
    defer:
      await peer.closeWait()
    let accepted = await accepting
    await accepted.closeWait()
    let pending = typeof(server.acceptFuts[0]).init("test closed connection")
    pending.complete(accepted)
    server.acceptFuts = @[pending]

    let retrying = server.accept()
    let outgoing = await client.dial(server.addrs[0])
    let incoming = await retrying
    check not incoming.isNil
    await allFutures(outgoing.close(), incoming.close())

  asyncTest "TCP cancellation during retry backoff remains cancellation":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()
    server.failNextAccept(newException(TransportTooManyError, "descriptor limit"))
    let accepting = server.accept()
    check not server.acceptFuts[0].finished
    await accepting.cancelAndWait()
    check accepting.cancelled

  asyncTest "stopping TCP during retry backoff raises a closed error":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()
    server.failNextAccept(newException(TransportAbortedError, "connection aborted"))
    let accepting = server.accept()
    check not server.acceptFuts[0].finished
    await server.stop()
    expect TransportClosedError:
      discard await accepting.wait(200.milliseconds)

  asyncTest "Tor waits through TCP retries and returns a usable connection":
    privateAccess(TorTransport)
    let server = TorTransport.new(initTAddress("127.0.0.1:9050"), upgrade = Upgrade())
    let client = TcpTransport.new(upgrade = Upgrade())
    let tcpAddress = TcpAutoAddress
    await server.start(
      @[
        ma(
          $tcpAddress &
            "/onion3/a2mncbqsbullu7thgm4e6zxda2xccmcgzmaq44oayhdtm6rav5vovcad:80"
        )
      ]
    )
    defer:
      await allFutures(client.stop(), server.stop())
    server.tcpTransport.failNextAccept(
      newException(TransportAbortedError, "connection aborted")
    )
    let accepting = server.accept()
    let outgoing = await client.dial(server.tcpTransport.addrs[0])
    let incoming = await accepting
    check not incoming.isNil
    check incoming.observedAddr.isNone
    await allFutures(outgoing.close(), incoming.close())
