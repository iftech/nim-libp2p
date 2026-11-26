# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Primitives shared by the Noise handshake patterns in this directory
## (`noise.nim`, `noisehfs.nim`): the cipher and symmetric state objects,
## handshake message framing, the libp2p handshake payload, and the secured
## connection type.
##
## This is an internal module. `noise.nim` re-exports only the symbols that
## were already part of its public API; the key-bearing state objects keep
## their fields private so nothing outside this module can rewind a nonce or
## overwrite a key on a live connection.

{.push raises: [].}

import std/strformat
import chronos, results, chronicles
import protobuf_serialization, protobuf_serialization/pkg/results
import stew/[endians2, byteutils]
import nimcrypto/[utils, sha2, hmac]
import ../../stream/[connection]
import ../../peerid
import ../../utils/[opt, shortlog, bytesview, protobuf, redact]

import secure, ../../crypto/[crypto, chacha20poly1305, curve25519, hkdf]

when defined(libp2p_dump):
  import ../../utils/debug

logScope:
  topics = "libp2p noise"

const
  PayloadString = toBytes("noise-libp2p-static-key:")

  # Empty is a special value which indicates k has not yet been initialized.
  EmptyKey = default(ChaChaPolyKey)
  NonceMax = uint64.high - 1 # max is reserved
  NoiseSize = 32
  MaxPlainSize = int(uint16.high - NoiseSize - ChaChaPolyTag.len)

  HandshakeTimeout* = 1.minutes
  MaxEarlyMuxerProtocols = 100

type
  KeyPair* = object
    privateKey*: Curve25519Key
    publicKey*: Curve25519Key

  # https://noiseprotocol.org/noise.html#the-cipherstate-object
  CipherState* = object
    k: ChaChaPolyKey
    n: uint64

  # https://noiseprotocol.org/noise.html#the-symmetricstate-object
  SymmetricState* = object
    cs: CipherState
    ck: ChaChaPolyKey
    h: MDigest[256]

  HandshakeResult* = object
    cs1: CipherState
    cs2: CipherState
    remoteP2psecret: seq[byte]
    rs: Curve25519Key

  NoiseExtensionsMsg* {.proto2.} = object
    streamMuxers* {.fieldNumber: 2.}: seq[string]

  NoiseConnection* = ref object of SecureConn
    readCs: CipherState
    writeCs: CipherState

  NoiseError* = object of LPStreamError
  NoiseHandshakeError* = object of NoiseError
  NoiseDecryptTagError* = object of NoiseError
  NoiseOversizedPayloadError* = object of NoiseError
  NoiseNonceMaxError* = object of NoiseError # drop connection on purpose

  NoiseHandshakePayloadMsg* {.proto2.} = object
    identityKey* {.fieldNumber: 1.}: Opt[seq[byte]]
    identitySig* {.fieldNumber: 2.}: Opt[seq[byte]]
    extensions* {.fieldNumber: 4.}: Opt[NoiseExtensionsMsg]

redactType(KeyPair)
redactType(CipherState)
redactType(SymmetricState)
redactType(HandshakeResult)

# Utility

Protobuf.serializerFor(
  [NoiseExtensionsMsg, NoiseHandshakePayloadMsg], withMetrics = true, domain = "noise"
)

func matchMuxers(local, remote: seq[string], initiator: bool): string =
  let
    preferred = if initiator: local else: remote
    supported = if initiator: remote else: local

  for muxer in preferred:
    if muxer in supported:
      return muxer

func shortLog*(conn: NoiseConnection): auto =
  try:
    if conn == nil:
      "NoiseConnection(nil)"
    else:
      &"{shortLog(conn.peerId)}:{conn.oid}"
  except ValueError as exc:
    raiseAssert(exc.msg)

chronicles.formatIt(NoiseConnection):
  shortLog(it)

proc genKeyPair*(rng: Rng): KeyPair =
  let privateKey = Curve25519Key.random(rng)
  KeyPair(privateKey: privateKey, publicKey: privateKey.public())

proc hashProtocol(name: string): MDigest[256] =
  # If protocol_name is less than or equal to HASHLEN bytes in length,
  # sets h to protocol_name with zero bytes appended to make HASHLEN bytes.
  # Otherwise sets h = HASH(protocol_name).

  var h: MDigest[256]
  if name.len <= 32:
    h.data[0 .. name.high] = name.toBytes
  else:
    h = sha256.digest(name)
  h

proc dh*(priv: Curve25519Key, pub: Curve25519Key): Curve25519Key =
  var key = pub
  Curve25519.mul(key, priv)
  key

# Cipherstate

proc hasKey(cs: CipherState): bool =
  cs.k != EmptyKey

proc encrypt(
    state: var CipherState, data: var openArray[byte], ad: openArray[byte]
): ChaChaPolyTag {.noinit, raises: [NoiseNonceMaxError].} =
  var nonce: ChaChaPolyNonce
  var tag: ChaChaPolyTag
  nonce[4 ..< 12] = toBytesLE(state.n)

  ChaChaPoly.encrypt(state.k, nonce, tag, data, ad)

  inc state.n
  if state.n > NonceMax:
    raise (ref NoiseNonceMaxError)(msg: "Noise max nonce value reached")
  tag

proc encryptWithAd(
    state: var CipherState, ad, data: openArray[byte]
): seq[byte] {.raises: [NoiseNonceMaxError].} =
  var buf = newSeqOfCap[byte](data.len + sizeof(ChaChaPolyTag))
  buf.add(data)

  let tag = encrypt(state, buf, ad)

  buf.add(tag)

  trace "Noise frame encrypted", messageSize = buf.len, nonce = state.n - 1
  buf

proc decryptWithAd(
    state: var CipherState, ad, data: openArray[byte]
): seq[byte] {.raises: [NoiseDecryptTagError, NoiseNonceMaxError].} =
  var
    tagIn = data.toOpenArray(data.len - ChaChaPolyTag.len, data.high).intoChaChaPolyTag
    tagOut: ChaChaPolyTag
    nonce: ChaChaPolyNonce
    buf = data[0 .. (data.high - ChaChaPolyTag.len)]
  nonce[4 ..< 12] = toBytesLE(state.n)
  ChaChaPoly.decrypt(state.k, nonce, tagOut, buf, ad)
  if tagIn != tagOut:
    debug "Noise frame authentication failed", messageSize = data.len
    raise (ref NoiseDecryptTagError)(msg: "decryptWithAd failed tag authentication.")
  inc state.n
  if state.n > NonceMax:
    raise (ref NoiseNonceMaxError)(msg: "Noise max nonce value reached")
  trace "Noise frame decrypted", messageSize = data.len
  buf

# Symmetricstate

proc init*(_: type[SymmetricState], protocolName: string): SymmetricState =
  let h = protocolName.hashProtocol
  SymmetricState(h: h, ck: h.data.intoChaChaPolyKey, cs: CipherState(k: EmptyKey))

proc mixKey*(ss: var SymmetricState, ikm: ChaChaPolyKey) =
  var temp_keys: array[2, ChaChaPolyKey]
  sha256.hkdf(ss.ck, ikm, [], temp_keys)
  ss.ck = temp_keys[0]
  ss.cs = CipherState(k: temp_keys[1])
  trace "Noise handshake key mixed"

proc mixHash*(ss: var SymmetricState, data: openArray[byte]) =
  var ctx: sha256
  ctx.init()
  ctx.update(ss.h.data)
  ctx.update(data)
  ss.h = ctx.finish()
  trace "Noise handshake hash mixed"

# We might use this for other handshake patterns/tokens
proc mixKeyAndHash(ss: var SymmetricState, ikm: openArray[byte]) {.used.} =
  var temp_keys: array[3, ChaChaPolyKey]
  sha256.hkdf(ss.ck, ikm, [], temp_keys)
  ss.ck = temp_keys[0]
  ss.mixHash(temp_keys[1])
  ss.cs = CipherState(k: temp_keys[2])

proc encryptAndHash*(
    ss: var SymmetricState, data: openArray[byte]
): seq[byte] {.raises: [NoiseNonceMaxError].} =
  # according to spec if key is empty leave plaintext
  let encrypted =
    if ss.cs.hasKey:
      ss.cs.encryptWithAd(ss.h.data, data)
    else:
      @data
  ss.mixHash(encrypted)
  encrypted

proc decryptAndHash*(
    ss: var SymmetricState, data: openArray[byte]
): seq[byte] {.raises: [NoiseDecryptTagError, NoiseNonceMaxError].} =
  # according to spec if key is empty leave plaintext
  let decrypted =
    if ss.cs.hasKey and data.len > ChaChaPolyTag.len:
      ss.cs.decryptWithAd(ss.h.data, data)
    else:
      @data
  ss.mixHash(data)
  decrypted

proc split(ss: var SymmetricState): tuple[cs1, cs2: CipherState] =
  var temp_keys: array[2, ChaChaPolyKey]
  sha256.hkdf(ss.ck, [], [], temp_keys)
  return (CipherState(k: temp_keys[0]), CipherState(k: temp_keys[1]))

proc hasKey*(ss: SymmetricState): bool =
  ss.cs.hasKey

proc toHandshakeResult*(
    ss: var SymmetricState, remoteP2psecret: sink seq[byte], rs: Curve25519Key
): HandshakeResult =
  ## Ends a handshake: derives the two transport cipher states with `Split()`
  ## and bundles them with the peer's decrypted handshake payload and static
  ## key.
  let (cs1, cs2) = ss.split()
  HandshakeResult(cs1: cs1, cs2: cs2, remoteP2psecret: remoteP2psecret, rs: rs)

proc readFrame(
    sconn: RawConn
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
  var besize {.noinit.}: array[2, byte]
  await sconn.readExactly(addr besize[0], besize.len)
  let size = uint16.fromBytesBE(besize).int
  trace "Noise handshake frame received", sconn, messageSize = size
  if size == 0:
    return

  var buffer = newSeqUninit[byte](size)
  await sconn.readExactly(addr buffer[0], buffer.len)
  return buffer

proc receiveHSMessage*(
    sconn: RawConn
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  readFrame(sconn)

template sendHSMessage*(sconn: RawConn, parts: varargs[seq[byte]]): untyped =
  # sends message (message frame) using multiple seq[byte] that 
  # concatenated represent entire mesage.

  var msgSize: int
  for p in parts:
    msgSize += p.len

  trace "Noise handshake frame sending", sconn, messageSize = msgSize
  doAssert msgSize <= uint16.high.int

  await sconn.write(@(msgSize.uint16.toBytesBE))
  for p in parts:
    await sconn.write(p)

method readMessage*(
    sconn: NoiseConnection
): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
  while true: # Discard 0-length payloads
    let frame = await sconn.stream.readFrame()
    sconn.activity = true
    if frame.len > ChaChaPolyTag.len:
      let res = sconn.readCs.decryptWithAd([], frame)
      if res.len > 0:
        when defined(libp2p_dump):
          dumpMessage(sconn, FlowDirection.Incoming, res)
        return res

    when defined(libp2p_dump):
      dumpMessage(sconn, FlowDirection.Incoming, [])
    trace "Received 0-length message", sconn

proc encryptFrame(
    sconn: NoiseConnection, cipherFrame: var openArray[byte], src: openArray[byte]
) {.raises: [NoiseNonceMaxError].} =
  # Frame consists of length + cipher data + tag
  doAssert src.len <= MaxPlainSize
  doAssert cipherFrame.len == 2 + src.len + sizeof(ChaChaPolyTag)

  cipherFrame[0 ..< 2] = toBytesBE(uint16(src.len + sizeof(ChaChaPolyTag)))
  cipherFrame[2 ..< 2 + src.len()] = src

  let tag = encrypt(sconn.writeCs, cipherFrame.toOpenArray(2, 2 + src.len() - 1), [])

  cipherFrame[2 + src.len() ..< cipherFrame.len] = tag

method write*(
    sconn: NoiseConnection, message: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  # Fast path: `{.async.}` would introduce a copy of `message`
  const FramingSize = 2 + sizeof(ChaChaPolyTag)

  let frames = (message.len + MaxPlainSize - 1) div MaxPlainSize

  var
    cipherFrames = newSeqUninit[byte](message.len + frames * FramingSize)
    left = message.len
    offset = 0
    woffset = 0

  while left > 0:
    let chunkSize = min(MaxPlainSize, left)

    try:
      encryptFrame(
        sconn,
        cipherFrames.toOpenArray(woffset, woffset + chunkSize + FramingSize - 1),
        message.toOpenArray(offset, offset + chunkSize - 1),
      )
    except NoiseNonceMaxError as exc:
      debug "Noise nonce exceeded"
      let fut = newFuture[void]("noise.write.nonce")
      fut.fail(exc)
      return fut

    when defined(libp2p_dump):
      dumpMessage(
        sconn,
        FlowDirection.Outgoing,
        message.toOpenArray(offset, offset + chunkSize - 1),
      )

    left = left - chunkSize
    offset += chunkSize
    woffset += chunkSize + FramingSize

  sconn.activity = true

  # Write all `cipherFrames` in a single write, to avoid interleaving /
  # sequencing issues
  sconn.stream.write(move(cipherFrames))

method closeImpl*(s: NoiseConnection) {.async: (raises: []).} =
  await procCall SecureConn(s).closeImpl()

  burnMem(s.readCs)
  burnMem(s.writeCs)

proc encodeHandshakePayload*(
    localPrivateKey: PrivateKey,
    localPublicKey: seq[byte],
    staticKey: Curve25519Key,
    muxers: seq[string],
): seq[byte] {.raises: [NoiseHandshakeError].} =
  ## Builds the libp2p handshake payload: the identity key, its signature
  ## over the Noise static key, and the early muxer list.
  # https://github.com/libp2p/specs/tree/master/noise#libp2p-data-in-handshake-messages
  let signedPayload = localPrivateKey.sign(PayloadString & staticKey.getBytes)
  if signedPayload.isErr():
    raise signedPayload.error().toException(
        NoiseHandshakeError, "Failed to sign public key"
      )

  let msg = NoiseHandshakePayloadMsg(
    identityKey: Opt.some(localPublicKey),
    identitySig: Opt.some(signedPayload.get().getBytes()),
    extensions:
      if muxers.len > 0:
        Opt.some(NoiseExtensionsMsg(streamMuxers: muxers))
      else:
        Opt.none(NoiseExtensionsMsg),
  )
  msg.encode()

proc newNoiseConnection*(
    conn: RawConn,
    handshakeRes: var HandshakeResult,
    initiator: bool,
    peerId: Opt[PeerId],
    muxers: seq[string],
): NoiseConnection {.raises: [NoiseHandshakeError].} =
  ## Authenticates the peer from its handshake payload and wraps `conn` in a
  ## `NoiseConnection` keyed with the transport cipher states. `handshakeRes`
  ## is wiped before returning, on every path.
  try:
    var
      remoteMsg: NoiseHandshakePayloadMsg
      remotePubKey: PublicKey
      remoteSig: Signature

    remoteMsg = NoiseHandshakePayloadMsg
      .decode(handshakeRes.remoteP2psecret)
      .valueOrRaise(NoiseHandshakeError)

    if remoteMsg.identityKey.isNone or remoteMsg.identitySig.isNone:
      raise
        newException(NoiseHandshakeError, "NoiseHandshakePayloadMsg fields must be set")

    if not remotePubKey.init(remoteMsg.identityKey.get()):
      raise (ref NoiseHandshakeError)(
        msg: "Failed to decode remote public key. (initiator: " & $initiator & ")"
      )
    if not remoteSig.init(remoteMsg.identitySig.get()):
      raise (ref NoiseHandshakeError)(
        msg: "Failed to decode remote signature. (initiator: " & $initiator & ")"
      )

    let verifyPayload = PayloadString & handshakeRes.rs.getBytes
    if not remoteSig.verify(verifyPayload, remotePubKey):
      raise (ref NoiseHandshakeError)(msg: "Noise handshake signature verify failed.")
    else:
      trace "Remote Noise signature verified", conn

    let pid = PeerId.init(remotePubKey).valueOr:
      raise error.toException(NoiseHandshakeError, "Invalid remote peer id")

    trace "Remote Noise peer identified", peerId = pid

    peerId.ifValue(targetPid):
      if not targetPid.validate():
        raise (ref NoiseHandshakeError)(msg: "Failed to validate expected peerId.")

      if pid != targetPid:
        var failedKey: PublicKey
        discard extractPublicKey(targetPid, failedKey)
        trace "Noise handshake peer identity rejected",
          initiator,
          dealt_peer = conn,
          dealt_key = $failedKey,
          received_peer = $pid,
          received_key = $remotePubKey
        raise (ref NoiseHandshakeError)(
          msg: "Noise handshake, peer id don't match! " & $pid & " != " & $targetPid
        )
    conn.peerId = pid

    var tmp = NoiseConnection.new(conn, conn.peerId, conn.observedAddr, conn.localAddr)
    remoteMsg.extensions.ifValue(extensions):
      if extensions.streamMuxers.len <= MaxEarlyMuxerProtocols:
        tmp.earlyMuxer = matchMuxers(muxers, extensions.streamMuxers, initiator)
    if initiator:
      tmp.readCs = handshakeRes.cs2
      tmp.writeCs = handshakeRes.cs1
    else:
      tmp.readCs = handshakeRes.cs1
      tmp.writeCs = handshakeRes.cs2
    tmp
  finally:
    burnMem(handshakeRes)
