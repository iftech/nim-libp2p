# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Standalone interop dialer for NoiseHFS
## (`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`).
##
## Dials a peer speaking the same protocol and completes a real handshake
## over TCP, independent of the rest of the nim-libp2p test suite. Used to
## verify wire-format compatibility against other language implementations
## of the same profile (see NOISE_HFS_SPEC.md).
##
## Every listener now exchanges one encrypted greeting each way, so the
## dialer always reads one post-handshake message and replies with
## "hello from Nim", exercising the transport cipher states rather than
## just the handshake.
##
## Usage:
##   nim c -r interop_dial.nim [port]   (default port 9998)

import std/[os, strutils]
import chronos
import stew/byteutils
import ./interop_common
import
  ../../libp2p/[
    stream/connection,
    transports/transport,
    transports/tcptransport,
    multiaddress,
    peerinfo,
    peerid,
    crypto/crypto,
    crypto/rng,
    protocols/secure/noisehfs,
    upgrademngrs/upgrade,
  ]

const
  # How long the dialer waits for the peer to close after it replies.
  PeerCloseTimeout = 5.seconds

proc main() {.async.} =
  var port = 9998
  if paramCount() == 1:
    let arg = paramStr(1)
    if arg.len > 0 and arg.allCharsInSet(Digits):
      port = parseInt(arg)
    else:
      quit("usage: interop_dial [port]", 1)
  elif paramCount() > 1:
    quit("usage: interop_dial [port]", 1)

  let
    rng = newRng()
    # Ed25519, not the crypto module's default ECDSA: several peer libp2p
    # implementations (e.g. py-libp2p as of this writing) only implement
    # protobuf key-type deserializers for a subset of libp2p's key types.
    privKey = PrivateKey.random(Ed25519, rng).get()
    noiseHFS = NoiseHFS.new(rng, privKey)
    transport = TcpTransport.new(upgrade = Upgrade())
    remoteMa = MultiAddress.init("/ip4/127.0.0.1/tcp/" & $port).get()

  emit("LOCAL " & $PeerId.init(privKey).get())
  stderr.writeLine("DIALING port " & $port)
  let conn = await transport.dial(remoteMa)
  let sconn = await noiseHFS.secure(conn, Opt.none(PeerId))

  emit("PEER " & $sconn.peerId)

  # Completing the handshake only proves both sides agreed on the handshake
  # hash and the KEM shared secret; it does not prove the two transport
  # cipher states came out of split() with the same key/nonce orientation.
  # A swapped cs1/cs2 still yields a successful handshake and only fails
  # here, on the first real data frame.
  let incoming = firstLine(string.fromBytes(await sconn.readMessage()))
  emit("RECV " & incoming)
  requireGreeting(incoming)
  await sconn.write(GreetingPrefix & "Nim\n")
  emit("SENT " & GreetingPrefix & "Nim")

  # Wait for the peer to close rather than tearing down straight away: an
  # abortive close can discard the frame just written before the peer reads it.
  try:
    discard await sconn.readMessage().wait(PeerCloseTimeout)
  except CatchableError:
    discard

  await sconn.close()
  await conn.close()
  # No transport.stop() here: this transport is dial-only and was never
  # start()ed, so stop() would take the "already stopped" cleanup path,
  # which only re-closes connections we already closed above and logs a
  # warning through chronicles - straight to stdout by default, corrupting
  # the stdout contract for no benefit.

  # INTEROP_OK must be the very last thing this process prints: emit it only
  # once the peer-close wait and both closes above have completed without
  # raising. If any of them raises, the top-level except below prints ERROR
  # and exits 1 instead - and never reaches this line.
  emit("INTEROP_OK")

try:
  waitFor(main())
except CatchableError as exc:
  stderr.writeLine("ERROR " & exc.msg)
  quit(1)
