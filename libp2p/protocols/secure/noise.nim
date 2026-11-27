# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, results, chronicles
import protobuf_serialization, protobuf_serialization/pkg/results
import stew/[endians2, byteutils]
import nimcrypto/[utils, sha2, hmac]
import ../../stream/[connection]
import ../../peerid
import ../../peerinfo
import ../../utils/[opt, bytesview, redact]

import secure, noisecommon, ../../crypto/[crypto, chacha20poly1305, curve25519]

# The shared primitives live in `noisecommon`. Re-export what was already
# public here, and keep the key-bearing state and handshake helpers internal.
export noisecommon except
  KeyPair, CipherState, SymmetricState, HandshakeResult, HandshakeTimeout, genKeyPair,
  dh, hasKey, init, mixKey, mixHash, encryptAndHash, decryptAndHash, toHandshakeResult,
  receiveHSMessage, sendHSMessage, encodeHandshakePayload, newNoiseConnection, `$`,
  writeValue

when defined(libp2p_dump):
  import ../../utils/debug

logScope:
  topics = "libp2p noise"

const
  # https://godoc.org/github.com/libp2p/go-libp2p-noise#pkg-constants
  NoiseCodec* = "/noise"

  ProtocolXXName = "Noise_XX_25519_ChaChaPoly_SHA256"

type
  # https://noiseprotocol.org/noise.html#the-handshakestate-object
  HandshakeState = object
    ss: SymmetricState
    s: noisecommon.KeyPair
    e: noisecommon.KeyPair
    rs: Curve25519Key
    re: Curve25519Key

  Noise* = ref object of Secure
    rng: Rng
    localPrivateKey: PrivateKey
    localPublicKey: seq[byte]
    noiseKeys: noisecommon.KeyPair
    commonPrologue: seq[byte]
    muxers: seq[string]
    outgoing: bool

redactType(HandshakeState, exported = false)
redactType(Noise)

proc init(_: type[HandshakeState]): HandshakeState =
  HandshakeState(ss: SymmetricState.init(ProtocolXXName))

template write_e(): untyped =
  trace "Noise write e"
  # Sets e (which must be empty) to GENERATE_KEYPAIR().
  # Appends e.public_key to the buffer. Calls MixHash(e.public_key).
  hs.e = genKeyPair(p.rng)
  hs.ss.mixHash(hs.e.publicKey)

  hs.e.publicKey.getBytes

template write_s(): untyped =
  trace "Noise write s"
  # Appends EncryptAndHash(s.public_key) to the buffer.
  hs.ss.encryptAndHash(hs.s.publicKey)

template dh_ee(): untyped =
  trace "Noise dh ee"
  # Calls MixKey(DH(e, re)).
  hs.ss.mixKey(dh(hs.e.privateKey, hs.re))

template dh_es(): untyped =
  trace "Noise dh es"
  # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
  when initiator:
    hs.ss.mixKey(dh(hs.e.privateKey, hs.rs))
  else:
    hs.ss.mixKey(dh(hs.s.privateKey, hs.re))

template dh_se(): untyped =
  trace "Noise dh se"
  # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
  when initiator:
    hs.ss.mixKey(dh(hs.s.privateKey, hs.re))
  else:
    hs.ss.mixKey(dh(hs.e.privateKey, hs.rs))

# might be used for other token/handshakes
template dh_ss(): untyped {.used.} =
  trace "Noise dh ss"
  # Calls MixKey(DH(s, rs)).
  hs.ss.mixKey(dh(hs.s.privateKey, hs.rs))

template read_e(): untyped =
  trace "Noise read e", size = msg.len

  if msg.len < Curve25519Key.len:
    raise (ref NoiseHandshakeError)(msg: "Noise E, expected more data")

  # Sets re (which must be empty) to the next DHLEN bytes from the message.
  # Calls MixHash(re.public_key).
  hs.re[0 .. Curve25519Key.high] = msg.toOpenArray(0, Curve25519Key.high)
  hs.ss.mixHash(hs.re)

  Curve25519Key.len

template read_s(): untyped =
  trace "Noise read s", size = msg.len
  # Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True,
  # or to the next DHLEN bytes otherwise.
  # Sets rs (which must be empty) to DecryptAndHash(temp).
  let rsLen =
    if hs.ss.hasKey:
      if msg.len < Curve25519Key.len + ChaChaPolyTag.len:
        raise (ref NoiseHandshakeError)(msg: "Noise S, expected more data")
      Curve25519Key.len + ChaChaPolyTag.len
    else:
      if msg.len < Curve25519Key.len:
        raise (ref NoiseHandshakeError)(msg: "Noise S, expected more data")
      Curve25519Key.len
  hs.rs[0 .. Curve25519Key.high] = hs.ss.decryptAndHash(msg.toOpenArray(0, rsLen - 1))

  rsLen

proc handshakeXXOutbound(
    p: Noise, conn: RawConn, p2pSecret: seq[byte]
): Future[HandshakeResult] {.async: (raises: [CancelledError, LPStreamError]).} =
  const initiator = true
  var hs = HandshakeState.init()

  try:
    hs.ss.mixHash(p.commonPrologue)
    hs.s = p.noiseKeys
    var remoteP2psecret: seq[byte]

    block: # -> e
      let ebytes = write_e()
      # IK might use this btw!
      let hbytes = hs.ss.encryptAndHash([])

      conn.sendHSMessage(ebytes, hbytes)

    block: # <- e, ee, s, es
      var msg = BytesView.init(await conn.receiveHSMessage())
      msg.consume(read_e())
      dh_ee()
      msg.consume(read_s())
      dh_es()
      remoteP2psecret = hs.ss.decryptAndHash(msg.data())

    block: # -> s, se
      let sbytes = write_s()
      dh_se()
      # last payload must follow the encrypted way of sending
      let hbytes = hs.ss.encryptAndHash(p2pSecret)

      conn.sendHSMessage(sbytes, hbytes)

    return hs.ss.toHandshakeResult(remoteP2psecret, hs.rs)
  finally:
    burnMem(hs)

proc handshakeXXInbound(
    p: Noise, conn: RawConn, p2pSecret: seq[byte]
): Future[HandshakeResult] {.async: (raises: [CancelledError, LPStreamError]).} =
  const initiator = false

  var hs = HandshakeState.init()

  try:
    hs.ss.mixHash(p.commonPrologue)
    hs.s = p.noiseKeys
    var remoteP2psecret: seq[byte]

    block: # <- e
      var msg = BytesView.init(await conn.receiveHSMessage())
      msg.consume(read_e())
      # we might use this early data one day, keeping it here for clarity
      let earlyData {.used.} = hs.ss.decryptAndHash(msg.data())

    block: # -> e, ee, s, es
      let ebytes = write_e()
      dh_ee()
      let sbytes = write_s()
      dh_es()
      let hbytes = hs.ss.encryptAndHash(p2pSecret)

      conn.sendHSMessage(ebytes, sbytes, hbytes)

    block: # <- s, se
      var msg = BytesView.init(await conn.receiveHSMessage())
      msg.consume(read_s())
      dh_se()
      remoteP2psecret = hs.ss.decryptAndHash(msg.data())

    return hs.ss.toHandshakeResult(remoteP2psecret, hs.rs)
  finally:
    burnMem(hs)

method handshake*(
    p: Noise, conn: RawConn, initiator: bool, peerId: Opt[PeerId]
): Future[SecureConn] {.async: (raises: [CancelledError, LPStreamError]).} =
  trace "Noise handshake started", conn, initiator

  let timeout = conn.timeout
  conn.timeout = HandshakeTimeout

  let payload = encodeHandshakePayload(
    p.localPrivateKey, p.localPublicKey, p.noiseKeys.publicKey, p.muxers
  )

  var handshakeRes =
    if initiator:
      await handshakeXXOutbound(p, conn, payload)
    else:
      await handshakeXXInbound(p, conn, payload)

  let secure = newNoiseConnection(conn, handshakeRes, initiator, peerId, p.muxers)

  trace "Noise handshake completed", initiator, peerId = secure.peerId

  conn.timeout = timeout

  return secure

proc new*(
    T: typedesc[Noise],
    rng: Rng,
    privateKey: PrivateKey,
    outgoing: bool = true,
    commonPrologue: seq[byte] = @[],
    muxers: seq[string] = @[],
): T =
  let pkBytes = privateKey
    .getPublicKey()
    .expect("Expected valid Private Key")
    .getBytes()
    .expect("Couldn't get public Key bytes")

  let noise = T.new(NoiseCodec)
  noise.rng = rng
  noise.outgoing = outgoing
  noise.localPrivateKey = privateKey
  noise.localPublicKey = pkBytes
  noise.noiseKeys = genKeyPair(rng)
  noise.commonPrologue = commonPrologue
  noise.muxers = muxers
  noise
