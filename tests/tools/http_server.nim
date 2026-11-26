# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos

type TestHttpServer* = ref object
  ## Answers every request with one fixed body over plain HTTP, whatever its method.
  server: StreamServer
  accepted: seq[StreamTransport]
  url*: string

proc startTestHttpServer*(body: string): TestHttpServer =
  let self = TestHttpServer()
  let response =
    "HTTP/1.1 200 OK\r\nContent-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" &
    body

  proc serve(server: StreamServer, client: StreamTransport) {.async: (raises: []).} =
    self.accepted.add(client)
    try:
      discard await client.write(response)
      # read and discarded: an unread request stalls the sender
      discard await client.read()
    except CancelledError:
      discard
    except TransportUseClosedError:
      # `stop` closed the connection while the read was still pending
      discard
    except TransportError as exc:
      raiseAssert "test http server: " & exc.msg

  self.server = createStreamServer(initTAddress("127.0.0.1:0"), serve, {ReuseAddr})
  self.server.start()

  # `local` carries the address the socket really bound, port 0 resolved.
  self.url = "http://" & $self.server.local & "/"
  self

proc connectionCount*(self: TestHttpServer): int =
  self.accepted.len

proc stop*(self: TestHttpServer) {.async: (raises: []).} =
  self.server.stop2().isOkOr:
    raiseAssert "test http server stop failed"
  await self.server.closeWait()
  # closing a connection before the client has read the response resets it on
  # Windows, so they stay open until now
  await noCancel allFutures(self.accepted.mapIt(it.closeWait()))
