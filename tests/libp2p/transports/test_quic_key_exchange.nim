# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/importutils
import chronos, boringssl, lsquic
import lsquic/context/[context, client]
import ../../../libp2p/[transports/quictransport, muxers/muxer]
import ../../tools/unittest
import ./utils

var negotiatedGroup {.threadvar.}: uint16

proc recordGroup(ssl: ptr SSL, event: cint, ret: cint) {.cdecl, raises: [].} =
  if (event and SSL_CB_HANDSHAKE_DONE) != 0:
    negotiatedGroup = SSL_get_group_id(ssl)

suite "QUIC key exchange":
  teardown:
    checkTrackers()

  for peer in ["none", "server", "client"]:
    let classicalPeer = peer
    asyncTest "negotiated group with classical-only peer: " & classicalPeer:
      privateAccess(QuicMuxer)
      privateAccess(QuicTransport)
      privateAccess(QuicEndpoint)
      let server = await createQuicTransport(isServer = true)
      let dialer = await createQuicTransport(isServer = true)
      defer:
        await allFutures(server.stop(), dialer.stop())

      let serverCtx = server.listeners[0].serverContext.sslCtx
      negotiatedGroup = 0
      SSL_CTX_set_info_callback(serverCtx, recordGroup)
      if classicalPeer == "server":
        require SSL_CTX_set1_groups_list(serverCtx, "X25519") == 1
      elif classicalPeer == "client":
        # The client context is normally created lazily by the first dial.
        let endpoint = dialer.listeners[0]
        endpoint.clientContext = ClientContext
          .new(endpoint.tlsConfig, endpoint.engineConfig)
          .expect("client context")
        endpoint.clientContext.fd = endpoint.udp.fd.cint
        require SSL_CTX_set1_groups_list(endpoint.clientContext.sslCtx, "X25519") == 1

      let acceptFut = server.accept()
      defer:
        await acceptFut.cancelAndWait()
      let outgoing = await dialer.dial("", server.addrs[0])
      let incoming = await acceptFut
      let serverMuxer = QuicMuxer.new(incoming)
      let clientMuxer = QuicMuxer.new(outgoing)
      defer:
        await allFutures(serverMuxer.close(), clientMuxer.close())

      let echoed = newFuture[void]("QUIC key exchange echo")
      serverMuxer.streamHandler = proc(stream: MuxedStream) {.async: (raises: []).} =
        try:
          let request = await stream.readLp(32)
          await stream.writeLp(request)
          echoed.complete()
        except CatchableError as exc:
          echoed.fail(exc)
        finally:
          await stream.close()
      serverMuxer.handleFut = serverMuxer.handle()
      let stream = await clientMuxer.newStream()
      defer:
        await stream.close()
      let payload = @[byte 1, 2, 3, 4]
      await stream.writeLp(payload)
      check (await stream.readLp(32)) == payload
      await echoed

      let expected =
        if classicalPeer == "none": SSL_GROUP_X25519_MLKEM768 else: SSL_GROUP_X25519
      check negotiatedGroup == expected.uint16
