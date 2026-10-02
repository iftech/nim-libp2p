# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, stew/byteutils
import
  ../../../libp2p/[
    errors,
    stream/connection,
    transports/transport,
    transports/tcptransport,
    multiaddress,
    peerinfo,
    crypto/crypto,
    crypto/mlkem768,
    protocols/secure/noise,
    protocols/secure/noisehfs,
    protocols/secure/secure,
    upgrademngrs/upgrade,
  ]
import ../../tools/[unittest, crypto]

suite "NoiseHFS":
  teardown:
    checkTrackers()

  let ma = MultiAddress.init("/ip4/0.0.0.0/tcp/0").get()

  test "protocol id matches the published XXhfs profile identifier":
    check NoiseHFSCodec == "/noise-mlkem768-hfs/0.2.0"
    check ProtocolXXHFSName == "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256"

  asyncTest "e2e: handle write + NoiseHFS":
    let
      server = @[ma]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverInfo = PeerInfo.new(serverPrivKey, server)
      serverNoise = NoiseHFS.new(rng(), serverPrivKey)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(server)

    proc acceptHandler() {.async.} =
      let conn = await transport1.accept()
      let sconn = await serverNoise.secure(conn, Opt.none(PeerId))
      try:
        await sconn.write("Hello!")
      finally:
        await sconn.close()
        await conn.close()

    let
      acceptFut = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = NoiseHFS.new(rng(), clientPrivKey)
      conn = await transport2.dial(transport1.addrs[0])

    let sconn = await clientNoise.secure(conn, Opt.some(serverInfo.peerId))

    var msg = newSeq[byte](6)
    await sconn.readExactly(addr msg[0], 6)

    await sconn.close()
    await conn.close()
    await acceptFut
    await transport1.stop()
    await transport2.stop()

    check string.fromBytes(msg) == "Hello!"

  asyncTest "e2e: rejects a peer id mismatch":
    let
      server = @[ma]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverNoise = NoiseHFS.new(rng(), serverPrivKey)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(server)

    proc acceptHandler() {.async.} =
      var conn: RawConn
      try:
        conn = await transport1.accept()
        discard await serverNoise.secure(conn, Opt.none(PeerId))
      except LPStreamError:
        discard
      finally:
        if not conn.isNil:
          await conn.close()

    let
      handlerWait = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = NoiseHFS.new(rng(), clientPrivKey)
      wrongPeer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get(), server)
      conn = await transport2.dial(transport1.addrs[0])

    expect NoiseHFSHandshakeError:
      discard await clientNoise.secure(conn, Opt.some(wrongPeer.peerId))

    await conn.close()
    await handlerWait
    await transport1.stop()
    await transport2.stop()

suite "MLKEM768":
  test "encapsulate/decapsulate round-trip recovers the shared secret":
    let keyPair = mlkem768.generateKeyPair()
    let encapRes = mlkem768.encapsulate(keyPair.publicKey).valueOr:
      raiseAssert "encapsulate should succeed against a freshly generated key"
    let decapSecret = mlkem768.decapsulate(encapRes.ciphertext, keyPair).valueOr:
      raiseAssert "decapsulate should succeed for a matching ciphertext"

    check decapSecret == encapRes.sharedSecret

  test "encapsulate rejects a malformed public key length":
    let tooShort: seq[byte] = newSeq[byte](10)
    check mlkem768.encapsulate(tooShort).isErr

  test "decapsulate rejects a malformed ciphertext length":
    let keyPair = mlkem768.generateKeyPair()
    let tooShort: seq[byte] = newSeq[byte](10)
    check mlkem768.decapsulate(tooShort, keyPair).isErr

  test "decapsulate with the wrong key does not crash and yields a different secret":
    # FIPS 203 implicit rejection: a well-formed ciphertext decapsulated with
    # an unrelated private key must not raise, and must not (except with
    # negligible probability) reproduce the original shared secret.
    let
      keyPairA = mlkem768.generateKeyPair()
      keyPairB = mlkem768.generateKeyPair()
      encapRes = mlkem768.encapsulate(keyPairA.publicKey).valueOr:
        raiseAssert "encapsulate should succeed"
      wrongSecret = mlkem768.decapsulate(encapRes.ciphertext, keyPairB).valueOr:
        raiseAssert "decapsulate must not fail on a well-formed ciphertext"

    check wrongSecret != encapRes.sharedSecret

  test "two key pairs produce different public keys":
    let
      keyPairA = mlkem768.generateKeyPair()
      keyPairB = mlkem768.generateKeyPair()

    check keyPairA.publicKey != keyPairB.publicKey
