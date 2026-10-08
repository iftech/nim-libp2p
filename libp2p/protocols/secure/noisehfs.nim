# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## NoiseHFS: a post-quantum hybrid variant of the libp2p Noise handshake.
##
## Implements `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, applying the
## Noise Hybrid Forward Secrecy extension (`e1`/`ekem1` tokens) to the
## classical XX pattern:
##
##   -> e, e1
##   <- e, ee, ekem1, s, es
##   -> s, se
##
## The three DH tokens (ee, es, se) provide the same classical security as
## plain `/noise`. The `e1`/`ekem1` tokens additionally mix an ML-KEM-768
## shared secret into the chaining key, so the session remains confidential
## even if X25519 is later broken by a quantum adversary, and remains
## confidential even if ML-KEM-768 is broken, since neither component's
## failure weakens the other's contribution.
##
## This module reuses noise.nim's `SymmetricState`/`CipherState`/`KeyPair`
## and message framing unchanged; only the extra KEM tokens and the
## top-level connection encrypter are new. See `NOISE_HFS_SPEC.md` for the
## full wire format and design rationale.
##
## https://github.com/noiseprotocol/noise_hfs_spec

{.push raises: [].}

import chronos, results, chronicles
import protobuf_serialization, protobuf_serialization/pkg/results
import nimcrypto/utils
import ../../stream/connection
import ../../peerid
import ../../peerinfo
import ../../utils/[opt, bytesview]
import ../../crypto/[crypto, chacha20poly1305, curve25519, mlkem768]
import secure, noise

logScope:
  topics = "libp2p noisehfs"

const
  # Working identifier for this profile; not yet IANA/libp2p-specs
  # registered. See NOISE_HFS_SPEC.md for the standardization status.
  NoiseHFSCodec* = "/noise-mlkem768-hfs/0.2.0"

  ProtocolXXHFSName* = "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256"

type
  HandshakeStateHFS = object
    ss: SymmetricState
    s: noise.KeyPair # local static DH keypair
    e: noise.KeyPair # local ephemeral DH keypair
    rs: Curve25519Key # remote static DH public key
    re: Curve25519Key # remote ephemeral DH public key
    e1: MLKEM768KeyPair # local ephemeral KEM keypair
    re1: MLKEM768PublicKeyBytes # remote ephemeral KEM public key

  NoiseHFS* = ref object of Secure
    rng: Rng
    localPrivateKey: PrivateKey
    localPublicKey: seq[byte]
    noiseKeys: noise.KeyPair
    commonPrologue: seq[byte]

  NoiseHFSHandshakeError* = object of NoiseHandshakeError

proc init(_: type[HandshakeStateHFS]): HandshakeStateHFS =
  HandshakeStateHFS(ss: SymmetricState.init(ProtocolXXHFSName))

proc handshakeXXHFSOutbound(
    p: NoiseHFS, conn: RawConn, p2pSecret: seq[byte]
): Future[HandshakeResult] {.async: (raises: [CancelledError, LPStreamError]).} =
  var hs = HandshakeStateHFS.init()

  try:
    hs.ss.mixHash(p.commonPrologue)
    hs.s = p.noiseKeys

    block: # -> e, e1
      hs.e = genKeyPair(p.rng)
      hs.ss.mixHash(hs.e.publicKey)

      hs.e1 = mlkem768.generateKeyPair()
      hs.ss.mixHash(hs.e1.publicKey)

      let hbytes = hs.ss.encryptAndHash([])
      conn.sendHSMessage(hs.e.publicKey.getBytes, @(hs.e1.publicKey), hbytes)

    var remoteP2psecret: seq[byte]
    block: # <- e, ee, ekem1, s, es
      var msg = BytesView.init(await conn.receiveHSMessage())

      if msg.len < Curve25519Key.len:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS e, expected more data")
      hs.re[0 .. Curve25519Key.high] = msg.toOpenArray(0, Curve25519Key.high)
      hs.ss.mixHash(hs.re)
      msg.consume(Curve25519Key.len)

      hs.ss.mixKey(dh(hs.e.privateKey, hs.re)) # ee

      let ekem1Len = MLKEM768CiphertextLen + ChaChaPolyTag.len
      if msg.len < ekem1Len:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS ekem1, expected more data")
      let ciphertext = hs.ss.decryptAndHash(msg.toOpenArray(0, ekem1Len - 1))
      msg.consume(ekem1Len)

      var sharedSecret = mlkem768.decapsulate(ciphertext, hs.e1).valueOr:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS ekem1, invalid ciphertext")
      hs.ss.mixKey(sharedSecret) # after decrypt, mirroring the sender's order
      burnMem(sharedSecret)

      let rsLen =
        if hs.ss.cs.hasKey:
          Curve25519Key.len + ChaChaPolyTag.len
        else:
          Curve25519Key.len
      if msg.len < rsLen:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS s, expected more data")
      hs.rs[0 .. Curve25519Key.high] = hs.ss.decryptAndHash(msg.toOpenArray(0, rsLen - 1))
      msg.consume(rsLen)

      hs.ss.mixKey(dh(hs.e.privateKey, hs.rs)) # es (initiator)

      remoteP2psecret = hs.ss.decryptAndHash(msg.data())

    block: # -> s, se
      let sbytes = hs.ss.encryptAndHash(hs.s.publicKey)
      hs.ss.mixKey(dh(hs.s.privateKey, hs.re)) # se (initiator)
      let hbytes = hs.ss.encryptAndHash(p2pSecret)

      conn.sendHSMessage(sbytes, hbytes)

    let (cs1, cs2) = hs.ss.split()
    return
      HandshakeResult(cs1: cs1, cs2: cs2, remoteP2psecret: remoteP2psecret, rs: hs.rs)
  finally:
    burnMem(hs)

proc handshakeXXHFSInbound(
    p: NoiseHFS, conn: RawConn, p2pSecret: seq[byte]
): Future[HandshakeResult] {.async: (raises: [CancelledError, LPStreamError]).} =
  var hs = HandshakeStateHFS.init()

  try:
    hs.ss.mixHash(p.commonPrologue)
    hs.s = p.noiseKeys

    block: # <- e, e1
      var msg = BytesView.init(await conn.receiveHSMessage())

      if msg.len < Curve25519Key.len:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS e, expected more data")
      hs.re[0 .. Curve25519Key.high] = msg.toOpenArray(0, Curve25519Key.high)
      hs.ss.mixHash(hs.re)
      msg.consume(Curve25519Key.len)

      if msg.len < MLKEM768PublicKeyLen:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS e1, expected more data")
      hs.re1[0 .. MLKEM768PublicKeyLen - 1] = msg.toOpenArray(0, MLKEM768PublicKeyLen - 1)
      hs.ss.mixHash(hs.re1)
      msg.consume(MLKEM768PublicKeyLen)

      # we might use this early data one day, keeping it here for clarity
      let earlyData {.used.} = hs.ss.decryptAndHash(msg.data())

    block: # -> e, ee, ekem1, s, es
      hs.e = genKeyPair(p.rng)
      hs.ss.mixHash(hs.e.publicKey)
      let ebytes = hs.e.publicKey.getBytes

      hs.ss.mixKey(dh(hs.e.privateKey, hs.re)) # ee

      var encapRes = mlkem768.encapsulate(hs.re1).valueOr:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS ekem1, invalid remote e1")
      let ekem1bytes = hs.ss.encryptAndHash(encapRes.ciphertext)
      hs.ss.mixKey(encapRes.sharedSecret) # after encrypt, per the wire spec
      burnMem(encapRes.sharedSecret)

      let sbytes = hs.ss.encryptAndHash(hs.s.publicKey)
      hs.ss.mixKey(dh(hs.s.privateKey, hs.re)) # es (responder)
      let hbytes = hs.ss.encryptAndHash(p2pSecret)

      conn.sendHSMessage(ebytes, ekem1bytes, sbytes, hbytes)

    var remoteP2psecret: seq[byte]
    block: # <- s, se
      var msg = BytesView.init(await conn.receiveHSMessage())
      let rsLen =
        if hs.ss.cs.hasKey:
          Curve25519Key.len + ChaChaPolyTag.len
        else:
          Curve25519Key.len
      if msg.len < rsLen:
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS s, expected more data")
      hs.rs[0 .. Curve25519Key.high] = hs.ss.decryptAndHash(msg.toOpenArray(0, rsLen - 1))
      msg.consume(rsLen)

      hs.ss.mixKey(dh(hs.e.privateKey, hs.rs)) # se (responder)

      remoteP2psecret = hs.ss.decryptAndHash(msg.data())

    let (cs1, cs2) = hs.ss.split()
    return
      HandshakeResult(cs1: cs1, cs2: cs2, remoteP2psecret: remoteP2psecret, rs: hs.rs)
  finally:
    burnMem(hs)

method handshake*(
    p: NoiseHFS, conn: RawConn, initiator: bool, peerId: Opt[PeerId]
): Future[SecureConn] {.async: (raises: [CancelledError, LPStreamError]).} =
  trace "Starting NoiseHFS handshake", conn, initiator

  let timeout = conn.timeout
  conn.timeout = HandshakeTimeout

  let signedPayload =
    p.localPrivateKey.sign(PayloadString & p.noiseKeys.publicKey.getBytes)
  if signedPayload.isErr():
    raise (ref NoiseHFSHandshakeError)(
      msg: "Failed to sign public key: " & $signedPayload.error()
    )

  let msg = NoiseHandshakePayloadMsg(
    identityKey: Opt.some(p.localPublicKey),
    identitySig: Opt.some(signedPayload.get().getBytes()),
  )

  var handshakeRes =
    if initiator:
      await handshakeXXHFSOutbound(p, conn, msg.encode())
    else:
      await handshakeXXHFSInbound(p, conn, msg.encode())

  var secure =
    try:
      var
        remoteMsg: NoiseHandshakePayloadMsg
        remotePubKey: PublicKey
        remoteSig: Signature

      remoteMsg = NoiseHandshakePayloadMsg.decode(handshakeRes.remoteP2psecret).valueOr:
        raise newException(NoiseHFSHandshakeError, error)

      if remoteMsg.identityKey.isNone or remoteMsg.identitySig.isNone:
        raise newException(
          NoiseHFSHandshakeError, "NoiseHandshakePayloadMsg fields must be set"
        )

      if not remotePubKey.init(remoteMsg.identityKey.get()):
        raise (ref NoiseHFSHandshakeError)(
          msg: "Failed to decode remote public key. (initiator: " & $initiator & ")"
        )
      if not remoteSig.init(remoteMsg.identitySig.get()):
        raise (ref NoiseHFSHandshakeError)(
          msg: "Failed to decode remote signature. (initiator: " & $initiator & ")"
        )

      let verifyPayload = PayloadString & handshakeRes.rs.getBytes
      if not remoteSig.verify(verifyPayload, remotePubKey):
        raise (ref NoiseHFSHandshakeError)(msg: "NoiseHFS handshake signature verify failed.")
      else:
        trace "Remote signature verified", conn

      let pid = PeerId.init(remotePubKey).valueOr:
        raise (ref NoiseHFSHandshakeError)(msg: "Invalid remote peer id: " & $error)

      trace "Remote peer id", pid = $pid

      peerId.ifValue(targetPid):
        if not targetPid.validate():
          raise (ref NoiseHFSHandshakeError)(msg: "Failed to validate expected peerId.")

        if pid != targetPid:
          raise (ref NoiseHFSHandshakeError)(
            msg: "NoiseHFS handshake, peer id don't match! " & $pid & " != " & $targetPid
          )
      conn.peerId = pid

      var tmp =
        NoiseConnection.new(conn, conn.peerId, conn.observedAddr, conn.localAddr)
      if initiator:
        tmp.readCs = handshakeRes.cs2
        tmp.writeCs = handshakeRes.cs1
      else:
        tmp.readCs = handshakeRes.cs1
        tmp.writeCs = handshakeRes.cs2
      tmp
    finally:
      burnMem(handshakeRes)

  trace "NoiseHFS handshake completed!", initiator, peer = shortLog(secure.peerId)

  conn.timeout = timeout

  return secure

method init*(p: NoiseHFS) {.gcsafe.} =
  procCall Secure(p).init()
  p.codec = NoiseHFSCodec

proc new*(
    T: typedesc[NoiseHFS],
    rng: Rng,
    privateKey: PrivateKey,
    commonPrologue: seq[byte] = @[],
): T =
  let pkBytes = privateKey
    .getPublicKey()
    .expect("Expected valid Private Key")
    .getBytes()
    .expect("Couldn't get public Key bytes")

  var noiseHFS = NoiseHFS(
    rng: rng,
    localPrivateKey: privateKey,
    localPublicKey: pkBytes,
    noiseKeys: genKeyPair(rng),
    commonPrologue: commonPrologue,
  )

  noiseHFS.init()
  noiseHFS
