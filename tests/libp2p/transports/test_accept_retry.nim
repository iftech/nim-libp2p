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

proc failNextAccept[E: CatchableError](server: TcpTransport, failure: typedesc[E]) =
  server.failNextAccept(newException(E, $E))

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
        server.failNextAccept(TransportTooManyError)
      else:
        server.failNextAccept(TransportAbortedError)
      let started = Moment.now()
      let accepting = server.accept()
      let outgoing = await client.dial(server.addrs[0])
      defer:
        await outgoing.close()
      let incoming = await accepting
      defer:
        await incoming.close()
      check not incoming.isNil
      check Moment.now() - started >= AcceptRetryDelay

  asyncTest "TCP terminal failures preserve their exception and cause":
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()

    let closed = newException(TransportUseClosedError, "listener closed")
    server.failNextAccept(closed)
    let closedAccept = server.accept()
    expect TransportClosedError:
      discard await closedAccept
    check closedAccept.error.parent == closed

    # The failed call pre-arms another listener accept.
    privateAccess(TcpTransport)
    await server.acceptFuts.cancelAndWait()
    let fatal = newException(TransportOsError, "listener failed")
    server.failNextAccept(fatal)
    let fatalAccept = server.accept()
    expect TcpTransportError:
      discard await fatalAccept
    check fatalAccept.error.parent == fatal

  asyncTest "a TCP listener failure does not strand the other listeners":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    let client = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress, TcpAutoAddress])
    defer:
      await allFutures(client.stop(), server.stop())
    server.failNextAccept(TransportAbortedError)
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

  asyncTest "TCP can be cancelled during retry backoff":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()
    server.failNextAccept(TransportTooManyError)
    let accepting = server.accept()
    check not server.acceptFuts[0].finished
    await accepting.cancelAndWait()

  asyncTest "stopping TCP during retry backoff raises a closed error":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()
    server.failNextAccept(TransportAbortedError)
    let accepting = server.accept()
    check not server.acceptFuts[0].finished
    await server.stop()
    expect TransportClosedError:
      discard await accepting

  asyncTest "stopping TCP before an accepted socket is registered closes it":
    privateAccess(TcpTransport)
    let server = TcpTransport.new(upgrade = Upgrade())
    await server.start(@[TcpAutoAddress])
    defer:
      await server.stop()
    let rawAccept = server.servers[0].accept()
    let outgoing = await connect(server.addrs[0])
    defer:
      await outgoing.closeWait()
    let incoming = await rawAccept
    let pending = typeof(server.acceptFuts[0]).init("test acceptance")
    server.acceptFuts = @[pending]
    let accepting = server.accept()
    var stopping: Future[void]
    proc beginStop(data: pointer) {.gcsafe, raises: [].} =
      stopping = server.stop()

    # Stop after the helper returns the socket, before accept registers it.
    pending.addCallback(
      proc(data: pointer) {.gcsafe, raises: [].} =
        callSoon(beginStop)
    )
    pending.complete(incoming)
    expect TransportClosedError:
      discard await accepting
    await stopping
    check incoming.closed

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
    server.tcpTransport.failNextAccept(TransportAbortedError)
    let accepting = server.accept()
    let outgoing = await client.dial(server.tcpTransport.addrs[0])
    let incoming = await accepting
    check not incoming.isNil
    check incoming.observedAddr.isNone
    await allFutures(outgoing.close(), incoming.close())
