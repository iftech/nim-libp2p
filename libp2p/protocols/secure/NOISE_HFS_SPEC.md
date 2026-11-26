# NoiseHFS: post-quantum hybrid Noise for nim-libp2p

Status: experimental. The suite is specified in libp2p/specs PR #727
(Stage 1A Working Draft, by royzah). Protocol identifier
`/noise-mlkem768-hfs/0.2.0` is what this implementation ships, not a
spec-endorsed identifier: #727 writes `/noise-mlkem768-hfs/0.1.0` and lists
the identifier string as the first of its open issues, and nothing is
registered with IANA. This implementation will follow whatever #727 settles
on.

## Motivation

The classical `/noise` handshake (`Noise_XX_25519_ChaChaPoly_SHA256`) relies
on X25519, which is broken by Shor's algorithm on a sufficiently large
quantum computer. Traffic recorded today can be decrypted retroactively once
such hardware exists (store-now-decrypt-later). `NoiseHFS` adds a
post-quantum key encapsulation mechanism (KEM) alongside the existing X25519
Diffie-Hellman exchange, so the session stays confidential even if either
component is later broken, without dropping backward compatibility: a
hybrid-capable node can mount both `NoiseHFS` and `Noise`, and multistream-select
negotiates the best protocol either side supports.

## Algorithm suite

`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`

| Primitive | Choice |
|---|---|
| Classical DH | X25519 |
| PQC KEM | ML-KEM-768 (FIPS 203), raw - no composite/combiner wrapper |
| AEAD | ChaCha20-Poly1305 |
| Hash | SHA-256 |

Raw ML-KEM-768 is used instead of a composite KEM (e.g. X-Wing) because the
XXhfs pattern's three DH tokens (`ee`, `es`, `se`) already provide classical
security; embedding a second X25519 operation inside the KEM slot would be
redundant. This mirrors the analysis in `NOISE-HFS` and in the reference
implementations this profile was designed to be wire-compatible with
(ChainSafe/js-libp2p-noise PR #665, libp2p/py-libp2p PR #1310, and
libp2p/rust-libp2p PR #6481 by royzah - see "Interoperability status" below
for the current state of that alignment).

## Handshake pattern

Applying the Noise HFS extension (`e1`/`ekem1` tokens) to the classical XX
pattern:

```
Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256:

  -> e, e1
  <- e, ee, ekem1, s, es
  -> s, se
```

This keeps XX's three-message structure - no extra round trip versus a pure
post-quantum KEM pattern (e.g. PQNoise's `pqXX`, which needs four messages
because KEM is inherently asymmetric).

| Token | Operation |
|---|---|
| `e` | Generate/send X25519 ephemeral public key |
| `e1` | Generate/send ML-KEM-768 ephemeral encapsulation key |
| `ee` | `MixKey(DH(e_local, e_remote))` |
| `ekem1` | Encapsulate to `re1`; `EncryptAndHash(ciphertext)` then `MixKey(sharedSecret)` |
| `s` | Encrypt and send X25519 static public key |
| `es` | `MixKey(DH(e, rs))` if initiator, `MixKey(DH(s, re))` if responder |
| `se` | `MixKey(DH(s, re))` if initiator, `MixKey(DH(e, rs))` if responder |

### Wire format (empty `NoiseHandshakePayload`)

```
Message A (initiator -> responder):
  [32 B]   e.publicKey                       (plaintext)
  [1184 B] e1.publicKey (ML-KEM-768 ek)       (plaintext)
  [0 B]    payload

Message B (responder -> initiator):
  [32 B]   e.publicKey                       (plaintext)
  [1104 B] EncryptAndHash(ekem1 ciphertext)   (1088 B ct + 16 B AEAD tag)
  [48 B]   EncryptAndHash(s.publicKey)        (32 B key + 16 B AEAD tag)
  [var]    EncryptAndHash(payload)

Message C (initiator -> responder):
  [48 B]   EncryptAndHash(s.publicKey)
  [var]    EncryptAndHash(payload)
```

Total overhead versus classical XX with an empty payload: 192 B -> 2,480 B
(+2,288 B), entirely in messages A and B.

### `ekem1` token ordering

The responder's `ekem1` step must run in exactly this order:

```
1. (ciphertext, sharedSecret) = Encapsulate(re1)
2. ekem1Bytes = EncryptAndHash(ciphertext)   # under the ee-derived key
3. MixKey(sharedSecret)                      # AFTER encrypting the ciphertext
```

and the initiator's read side mirrors it:

```
1. ciphertext = DecryptAndHash(ekem1Bytes)
2. sharedSecret = Decapsulate(ciphertext, e1.privateKey)
3. MixKey(sharedSecret)
```

Swapping steps 2 and 3 on either side produces divergent chaining keys and
breaks the handshake. The ordering ensures the responder's static key (`s`)
and Message B's payload are protected by a key derived from both `ee` and the
KEM shared secret, not `ee` alone.

### ML-KEM-768 implicit rejection

Per FIPS 203 6.4, `Decaps()` never fails, even for a ciphertext produced for
a different key - it returns a pseudorandom shared secret derived from an
implicit rejection value instead. A tampered or mismatched ciphertext
therefore does not raise at the KEM layer; the resulting divergent shared
secret causes every subsequent AEAD operation to fail authentication instead,
so the handshake still aborts. Because the ciphertext itself is AEAD-tagged
before `MixKey` runs, outright tampering is caught by that tag before
decapsulation is even attempted.

## Implementation

- `libp2p/crypto/mlkem768.nim` - raw ML-KEM-768 bound directly to the
  `MLKEM768_*` C API already vendored into nim-libp2p through its
  `boringssl` dependency (`crypto/mlkem/mlkem.cc`), rather than pulling in a
  separate PQC library. This is the same ML-KEM-768 implementation shipped in
  Chrome's TLS stack.
- `libp2p/protocols/secure/noisecommon.nim` - what `/noise` and NoiseHFS
  share: `SymmetricState`/`CipherState`/`KeyPair`, handshake message
  framing, the signed handshake payload with peer authentication, and the
  secured connection type. Internal: `noise.nim` re-exports only what was
  already public there.
- `libp2p/protocols/secure/noisehfs.nim` - the `NoiseHFS` connection
  encrypter. Only the `e1`/`ekem1` token handling and the top-level
  connection encrypter are new.
- `libp2p/builders.nim` - `SecureProtocol.NoiseHFS` and
  `SwitchBuilder.withNoiseHFS()`, so a switch can mount `NoiseHFS` alongside
  the default `Noise` and let multistream-select negotiate per peer.

## Negotiation and downgrade

When a switch mounts both protocols, NoiseHFS is proposed first, so two
hybrid-capable peers use it and a classical-only peer still gets `/noise`.

That fallback is not downgrade-protected. multistream-select runs in the
clear before any handshake, and the protocol it selects is not bound into
the Noise transcript, so an attacker who can modify traffic while the
connection is being set up can make both peers settle on `/noise`. A node
that must not open a classical session mounts NoiseHFS alone
(`withNoiseHFS()` without `withNoise()`); it then fails to connect to
classical-only peers instead of falling back.

## Interoperability status

The suite is specified in libp2p/specs PR #727, a Stage 1A Working Draft.
The other implementations of the same profile are TypeScript
(ChainSafe/js-libp2p-noise PR #665), Python (libp2p/py-libp2p PR #1310) and
Rust (libp2p/rust-libp2p PR #6481).

Latest cross-implementation result: **48 of 48 runs passed** in a 4x4
matrix on 2026-09-19, every ordered (listener, dialer) pairing of JS,
Python, Nim and Rust, each against itself included, three runs each. A run
passes only if both harnesses exit 0 with `INTEROP_OK`, each side's `PEER`
matches the other side's `LOCAL`, and each side decrypts the other's
greeting. Results, the exact commit of each implementation (`versions.txt`)
and per-run logs:
<https://github.com/paschal533/pq-noise-artifacts/tree/main/interop/results/20260919T223056Z>.

Limits of that result:

- It ran Nim at `b3f203d`, with `interop/noise-pq/interop_listen` and
  `interop_dial`. Later commits on this branch are not covered until the
  matrix is rerun.
- The runs were over loopback TCP on one machine.
- The harnesses start the handshake directly on TCP, without
  multistream-select, so protocol id negotiation is not covered there. In
  this repository it is covered Nim-to-Nim by
  `tests/libp2p/protocols/test_noisehfs.nim`.
