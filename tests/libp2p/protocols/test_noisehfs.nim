# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
import chronos, chronicles, json_serialization, stew/byteutils
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
    protocols/protocol,
    protocols/secure/noise,
    protocols/secure/noisehfs,
    protocols/secure/secure,
    upgrademngrs/upgrade,
    utils/redact,
  ]
import ../../tools/[unittest, crypto, futures, multiaddress, switch_builder]

const
  TestCodec = "/test/proto/1.0.0"
  jsonMarker = Json.encode(Redacted)

type TestProto = ref object of LPProtocol

proc new(T: typedesc[TestProto]): T =
  let p = T()
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    try:
      let msg = string.fromBytes(await stream.readLp(1024))
      check "Hello!" == msg
      await stream.writeLp("Hello!")
    except LPStreamError:
      raiseAssert "LPStreamError while handling connection"
    finally:
      await stream.close()

  p.codec = TestCodec
  p.handler = handle
  p

proc hybridSwitch(hfsFirst = true): Switch =
  ## A switch with both NoiseHFS and classical Noise mounted. `hfsFirst`
  ## flips the order of the two builder calls, which must not matter.
  var b = SwitchBuilder.new().withRng(rng())
  b =
    if hfsFirst:
      b.withNoiseHFS().withNoise()
    else:
      b.withNoise().withNoiseHFS()
  b.withAddress(TcpWildcardAddress).withTcpTransport().withMplex().build()

proc securedWith(dialer, listener: Switch): Future[string] {.async.} =
  ## Dials `listener` from `dialer`, exchanges one message, and returns the
  ## secure channel codec multistream-select settled on for the connection.
  let conn =
    await dialer.dial(listener.peerInfo.peerId, listener.peerInfo.addrs, TestCodec)
  await conn.writeLp("Hello!")
  check string.fromBytes(await conn.readLp(1024)) == "Hello!"
  await conn.close()

  let muxer = dialer.connManager.getConnections()[listener.peerInfo.peerId][0]
  SecureConn(muxer.connection).stream.protocol

suite "NoiseHFS":
  teardown:
    checkTrackers()

  let ma = TcpWildcardAddress

  test "protocol id matches the published XXhfs profile identifier":
    check NoiseHFSCodec == "/noise-mlkem768-hfs/0.2.0"
    check ProtocolXXHFSName == "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256"

  test "NoiseHFS is redacted via `$`, Chronicles and Json.encode":
    let noiseHFS = NoiseHFS.new(rng(), PrivateKey.random(ECDSA, rng()).get())
    check:
      $noiseHFS == Redacted
      Json.encode(noiseHFS) == jsonMarker
      chroniclesFormatItIMPL(noiseHFS) == Redacted

  asyncTest "e2e: both directions carry data over NoiseHFS":
    # A handshake that completes only proves both sides agree on the
    # handshake hash. Each side must also decrypt what the other encrypts:
    # that is what catches the two transport cipher states being swapped.
    let
      server = @[ma]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverInfo = PeerInfo.new(serverPrivKey, server)
      serverNoise = NoiseHFS.new(rng(), serverPrivKey)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(server)

    proc acceptHandler(): Future[string] {.async.} =
      let conn = await transport1.accept()
      let sconn = await serverNoise.secure(conn, Opt.none(PeerId))
      try:
        await sconn.write("Hello!")
        var reply = newSeq[byte](8)
        await sconn.readExactly(addr reply[0], reply.len)
        return string.fromBytes(reply)
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
    await sconn.readExactly(addr msg[0], msg.len)
    await sconn.write("Hi back!")
    let serverReceived = await acceptFut

    await sconn.close()
    await conn.close()
    await transport1.stop()
    await transport2.stop()

    check string.fromBytes(msg) == "Hello!"
    check serverReceived == "Hi back!"

  asyncTest "e2e: rejects a peer id mismatch and restores the connection timeout":
    let
      server = @[ma]
      serverPrivKey = PrivateKey.random(ECDSA, rng()).get()
      serverNoise = NoiseHFS.new(rng(), serverPrivKey)

    let transport1: TcpTransport = TcpTransport.new(upgrade = Upgrade())
    asyncSpawn transport1.start(server)

    proc acceptHandler() {.async.} =
      # The responder cannot see the mismatch: the initiator checks the
      # identity only after sending its last handshake message, so this
      # side's handshake completes and it is left holding a secured
      # connection that must still be closed.
      let conn = await transport1.accept()
      let sconn = await serverNoise.secure(conn, Opt.none(PeerId))
      await sconn.close()
      await conn.close()

    let
      handlerWait = acceptHandler()
      transport2: TcpTransport = TcpTransport.new(upgrade = Upgrade())
      clientPrivKey = PrivateKey.random(ECDSA, rng()).get()
      clientNoise = NoiseHFS.new(rng(), clientPrivKey)
      wrongPeer = PeerInfo.new(PrivateKey.random(ECDSA, rng()).get(), server)
      conn = await transport2.dial(transport1.addrs[0])
      timeoutBefore = conn.timeout

    expect NoiseHandshakeError:
      discard await clientNoise.secure(conn, Opt.some(wrongPeer.peerId))

    check conn.timeout == timeoutBefore

    await conn.close()
    await handlerWait
    await transport1.stop()
    await transport2.stop()

  asyncTest "e2e: two hybrid switches negotiate NoiseHFS, whatever the builder order":
    for (dialerHfsFirst, listenerHfsFirst) in [
      (true, true), (false, false), (true, false), (false, true)
    ]:
      let
        listener = hybridSwitch(listenerHfsFirst)
        dialer = hybridSwitch(dialerHfsFirst)
      listener.mount(TestProto.new())
      await listener.start()
      await dialer.start()

      check (await dialer.securedWith(listener)) == NoiseHFSCodec

      await allFuturesRaising(listener.stop(), dialer.stop())

  asyncTest "e2e: a hybrid switch falls back to /noise with a classical-only peer":
    block: # hybrid dials classical
      let
        listener = makeStandardSwitch(TcpWildcardAddress)
        dialer = hybridSwitch()
      listener.mount(TestProto.new())
      await listener.start()
      await dialer.start()

      check (await dialer.securedWith(listener)) == NoiseCodec

      await allFuturesRaising(listener.stop(), dialer.stop())

    block: # classical dials hybrid
      let
        listener = hybridSwitch()
        dialer = makeStandardSwitch(TcpWildcardAddress)
      listener.mount(TestProto.new())
      await listener.start()
      await dialer.start()

      check (await dialer.securedWith(listener)) == NoiseCodec

      await allFuturesRaising(listener.stop(), dialer.stop())

  asyncTest "e2e: a NoiseHFS-only switch does not fall back to /noise":
    let
      listener = makeStandardSwitch(TcpWildcardAddress)
      dialer = SwitchBuilder
        .new()
        .withRng(rng())
        .withNoiseHFS()
        .withAddress(TcpWildcardAddress)
        .withTcpTransport()
        .withMplex()
        .build()
    listener.mount(TestProto.new())
    await listener.start()
    await dialer.start()

    expect DialFailedError:
      discard
        await dialer.dial(listener.peerInfo.peerId, listener.peerInfo.addrs, TestCodec)

    await allFuturesRaising(listener.stop(), dialer.stop())

  asyncTest "e2e: early muxer negotiation works over NoiseHFS":
    let
      listener = hybridSwitch()
      dialer = hybridSwitch()
    listener.mount(TestProto.new())
    await listener.start()
    await dialer.start()

    check (await dialer.securedWith(listener)) == NoiseHFSCodec

    let
      initiatorMuxer = dialer.connManager.getConnections()[listener.peerInfo.peerId][0]
      responderMuxer = listener.connManager.getConnections()[dialer.peerInfo.peerId][0]
    check SecureConn(initiatorMuxer.connection).earlyMuxer == "/mplex/6.7.0"
    check SecureConn(responderMuxer.connection).earlyMuxer == "/mplex/6.7.0"

    await allFuturesRaising(listener.stop(), dialer.stop())

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

  test "key pair and encapsulation result are redacted":
    let keyPair = mlkem768.generateKeyPair()
    let encapRes = mlkem768.encapsulate(keyPair.publicKey).valueOr:
      raiseAssert "encapsulate should succeed"

    check:
      $keyPair == Redacted
      Json.encode(keyPair) == jsonMarker
      chroniclesFormatItIMPL(keyPair) == Redacted
      $encapRes == Redacted
      Json.encode(encapRes) == jsonMarker
      chroniclesFormatItIMPL(encapRes) == Redacted

  test "a key pair works from an odd address":
    # BoringSSL's key structs need 2-byte alignment. A key pair embedded
    # after a single byte must still be usable.
    type Shifted = object
      pad: byte
      keyPair: MLKEM768KeyPair

    var shifted = Shifted(pad: 1, keyPair: mlkem768.generateKeyPair())
    let encapRes = mlkem768.encapsulate(shifted.keyPair.publicKey).valueOr:
      raiseAssert "encapsulate should succeed"
    let decapSecret = mlkem768.decapsulate(encapRes.ciphertext, shifted.keyPair).valueOr:
      raiseAssert "decapsulate should succeed for a matching ciphertext"

    check decapSecret == encapRes.sharedSecret
