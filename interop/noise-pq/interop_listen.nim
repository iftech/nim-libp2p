# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Standalone interop listener for NoiseHFS
## (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`).
##
## Accepts one connection, completes the handshake as responder, sends one
## encrypted greeting and reads the reply, prints identity/greeting lines on
## a fixed stdout contract, and exits. Companion to interop_dial.nim - used
## to let another language's implementation dial into nim-libp2p to verify
## wire compatibility from the other direction.
##
## Usage:
##   nim c -r interop_listen.nim [port]   (default 9998)

import chronos
import stew/byteutils
import ./interop_common
import
  ../../libp2p/[
    stream/connection,
    transports/transport,
    transports/tcptransport,
    multiaddress,
    peerid,
    crypto/crypto,
    crypto/rng,
    protocols/secure/noisehfs,
    upgrademngrs/upgrade,
  ]

proc main() {.async.} =
  let
    port = portFromArgs("usage: interop_listen [port]")
    rng = newRng()
    privKey = PrivateKey.random(Ed25519, rng).get()
    noiseHFS = NoiseHFS.new(rng, privKey)
    transport = TcpTransport.new(upgrade = Upgrade())
    listenMa = MultiAddress.init("/ip4/127.0.0.1/tcp/" & $port).valueOr:
      raise newException(ValueError, "invalid listen address: " & $error)

  emit("LOCAL " & $PeerId.init(privKey).get())
  await transport.start(@[listenMa])
  emit("READY " & $port)

  # accept() returns nil for a connection that went away before it could be
  # handed over (a runner probing the port for readiness does exactly that):
  # keep waiting for the real dialer.
  var conn = await transport.accept()
  while conn.isNil:
    conn = await transport.accept()

  let sconn = await noiseHFS.secure(conn, Opt.none(PeerId))
  emit("PEER " & $sconn.peerId)

  await sconn.write(GreetingPrefix & "Nim\n")
  emit("SENT " & GreetingPrefix & "Nim")
  let reply = firstLine(string.fromBytes(await sconn.readMessage()))
  emit("RECV " & reply)
  requireGreeting(reply)

  await sconn.close()
  await conn.close()
  await transport.stop()
  # INTEROP_OK must be the very last thing this process prints: emit it only
  # once every cleanup step above has completed without raising. If any of
  # them raises, the top-level except below prints ERROR and exits 1 instead
  # - and never reaches this line.
  emit("INTEROP_OK")

try:
  waitFor(main())
except CatchableError as e:
  stderr.writeLine("ERROR " & e.msg)
  quit(1)
