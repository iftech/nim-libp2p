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
- `libp2p/protocols/secure/noisehfs.nim` - the `NoiseHFS` connection
  encrypter. Reuses `noise.nim`'s `SymmetricState`/`CipherState`/`KeyPair`
  and message framing unchanged (`readFrame`, `sendHSMessage`, `dh`,
  `mixKey`, `mixHash`, `encryptAndHash`, `decryptAndHash`, `split`); only the
  `e1`/`ekem1` token handling and the top-level connection encrypter are new.
- `libp2p/builders.nim` - `SecureProtocol.NoiseHFS` and
  `SwitchBuilder.withNoiseHFS()`, so a switch can mount `NoiseHFS` alongside
  the default `Noise` and let multistream-select negotiate per peer.

## Interoperability status

The suite is specified in libp2p/specs PR #727, a Stage 1A Working Draft
opened by royzah on 2026-07-06 and still open. A separate and longer draft,
libp2p/specs PR #716 by this implementation's author, was closed on
2026-09-18 in favour of #727; its text remains readable at
<https://github.com/paschal533/specs/tree/master/noise-pq>.

This profile's wire format matches the other implementations of
`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`: TypeScript
(ChainSafe/js-libp2p-noise PR #665), Python (libp2p/py-libp2p PR #1310) and
Rust (libp2p/rust-libp2p PR #6481, with the interop harness in
royzah/rust-libp2p PR #1).

This nim-libp2p implementation has been verified standalone (KEM round-trip,
implicit-rejection behaviour, and a full two-node TCP handshake with peer
authentication - see `tests/libp2p/protocols/test_noisehfs.nim`).

Cross-implementation interop is verified by a bidirectional 4x4 matrix run on
2026-09-17 with the neutral runner in `pq-noise-artifacts`: every ordered
(listener, dialer) pairing of JS, Python, Nim and Rust, including Nim against
itself, three repetitions each, **48 of 48 runs passed**. A run passes only if
both harnesses exit 0 with `INTEROP_OK`, each side's `PEER` matches the other
side's `LOCAL`, and each side decrypts the other's greeting, one encrypted
transport message in each direction, so both `split()` cipher states are
exercised. Nim was tested at `824cce0` with `interop/noise-pq/interop_listen`
and `interop/noise-pq/interop_dial`. The runs were over loopback TCP on one
machine, and the harnesses start the handshake directly, without
multistream-select, so protocol id negotiation is not covered. Matrix, results
and per-run logs:
<https://github.com/paschal533/pq-noise-artifacts/tree/main/interop/results/20260919T223056Z>.

The 2026-07-11 run against py-libp2p's listener, recorded in
`interop/noise-pq/README.md`, predates the rename and covered the handshake
only; the matrix supersedes it.
