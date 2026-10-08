# NoiseHFS interop scripts

Standalone dial/listen scripts for `Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`
(protocol id `/noise-mlkem768-hfs/0.2.0`, which is what these harnesses and
the other three implementations ship; the suite's Working Draft,
libp2p/specs#727, writes `0.1.0` and lists the identifier string as an open
issue), independent of the rest of the nim-libp2p test suite. See `../../libp2p/protocols/secure/NOISE_HFS_SPEC.md`
for the wire format.

## Usage

```bash
nim c -d:release --outdir:. interop_listen.nim
nim c -d:release --outdir:. interop_dial.nim
./interop_listen [port]   # accepts one connection, then exits (default 9998)
./interop_dial [port]     # dials 127.0.0.1:port (default 9998)
```

The listener speaks first: both harnesses always exchange one encrypted
greeting line each way (`hello from Nim\n`), exercising both transport
cipher states from `split()`, not just the handshake. Stdout follows one
contract shared by all four implementations of this profile, one key per
line:

```
READY <port>          (listeners only)
LOCAL <peer-id>
PEER <peer-id>
SENT hello from <Impl>
RECV <line>
INTEROP_OK            (last line, exit 0)
```

Anything else goes to stderr. Any failure prints `ERROR <msg>` to stderr and
exits 1. Cross-implementation orchestration - running the 4x4 matrix against
JS, Python and Rust - lives in the neutral matrix runner, not in this repo:
<https://github.com/paschal533/pq-noise-artifacts/tree/main/interop>.

## Verified interop

**nim-libp2p <-> py-libp2p, 2026-07-11**

`interop_dial.nim` against py-libp2p's `scripts/interop_listen_mlkem768.py`
(libp2p/py-libp2p, branch `feat/pqc-noise-xxhfs`), both on the raw
ML-KEM-768 (not X-Wing) revision:

```
# py-libp2p side
READY 9999
Connection from 127.0.0.1:56421
PEER 12D3KooWLitocTge1Lm2TmS3THHfrMWfV3d6UJZpPZNweL3c6CFD

# nim-libp2p side
DIALING port 9999
HANDSHAKE_OK remotePeer=12D3KooWJGqi39m6ykyVhs8K1c1z8eeb4nFEqVxHLPopHdm8rV9h
```

Both sides completed the full three-message XXhfs handshake - X25519 DH,
ML-KEM-768 encapsulate/decapsulate, ChaCha20-Poly1305 AEAD, and Ed25519 peer
identity signature verification - with no changes needed to either
implementation's wire format. The differing peer ids above are expected:
each side reports the *other* side's freshly-generated identity, not its
own.

Note: the identity key used here is Ed25519, not the crypto module's
default ECDSA - as of this writing, py-libp2p's protobuf key-type
deserializer only implements Secp256k1, RSA, and Ed25519, so an ECDSA
identity key fails at the peer-identity-verification step with an unrelated
`MissingDeserializerError`, after the actual Noise/KEM handshake has already
succeeded. That's a py-libp2p key-type support gap, not a NoiseHFS wire
compatibility issue.

**nim-libp2p <-> js-libp2p-noise, 2026-09-05**

Both roles, against ChainSafe/js-libp2p-noise PR #665 (branch
`feat/pqc-xxhfs-noise`) on Node.js v22.17.1.

nim-libp2p listening, `scripts/noise-hfs-dial.mjs` dialling:

```
# nim-libp2p side                      # js-libp2p-noise side
READY 9101                             PEER 12D3KooWJdMEZoTchgFtZDD1FYUEqRHtpas54b4fBShsrqPidVyb
HANDSHAKE_OK remotePeer=12D3KooWN1LK85XfPFGzKq3gjTnm12e4tZn84GeSkNpQf6Fve4hS
```

js-libp2p-noise listening, `interop_dial --chat` dialling, with a message
exchanged in each direction after the handshake. The `--chat` flag has since
been removed: both harnesses now always exchange one greeting each way.

```
# js-libp2p-noise side                        # nim-libp2p side
Listener peer ID: 12D3KooWEBXx...uTxUxX2x     DIALING port 8000
Handshake complete! Remote peer: 12D3KooW...  HANDSHAKE_OK remotePeer=12D3KooWEBXx...uTxUxX2x
Sent: "hello from JS"                         RECV hello from JS
Received: "hello from Nim"                    SENT hello from Nim
INTEROP SUCCESS
```

Note that the peer id nim-libp2p reports here is exactly the id the JS listener
printed for itself. To report it, nim-libp2p had to decrypt the JS static key
and payload, which the AEAD only allows if both sides computed the same `h`
(the handshake hash is the associated data), and then verify the Ed25519
identity signature, which covers that static key. The message exchange covers both
transport keys: nim decrypting the JS frame exercises one `split()` output, JS
decrypting the nim frame exercises the other.

**nim-libp2p <-> rust-libp2p, 2026-09-05**

Against royzah/rust-libp2p PR #1 (branch `feat/noise-mlkem-hfs`), built with
`cargo build -p libp2p-noise --example noise_hfs_listener --features mlkem-hfs`:

```
# rust-libp2p side                     # nim-libp2p side
READY 9103                             DIALING port 9103
connection from 127.0.0.1:62444        HANDSHAKE_OK remotePeer=12D3KooWFXYW...Dd8atwd
PEER 12D3KooWHQEvXV28iyrSzHzwbYmLcRpk2zBHyk22ayGLxe91BdB9
```

Only this direction was recorded here: the listener example in this pairing
was ours (royzah/rust-libp2p#1). royzah/rust-libp2p#1 now has both a
listener and a dialer harness on the shared contract, so this pairing is no
longer limited to nim-libp2p as the initiator.

This run also predates royzah's current code: it used our
`royzah/rust-libp2p#1` branch, whose `Cargo.lock` pins `royzah/snow` at commit
`407dd90` of 14 June 2026, which still spelled the suite `ML-KEM-768`. royzah
renamed it to `MLKEM768` on 17 August 2026 (snow `858dc27`; rust-libp2p
`1ae21ce`, later rebased as `e7a1286`), and the rename was on the
libp2p/rust-libp2p#6481 branch by 22 August 2026 at the latest, so this
5 September run was already behind the pull request.

## Coverage

Historical record, superseded. The runs recorded above and the June 2026
runs in the table below checked the handshake only: apart from the
js-libp2p-noise listener run above, no transport message was exchanged. The
June 2026 claims are corrected under "Earlier claims, corrected" in the
pq-noise-artifacts README. Current coverage is the 17 September 2026 matrix,
in which every ordered pair of the four implementations, including each one
against itself, passed 3 of 3 runs with one encrypted greeting each way:
<https://github.com/paschal533/pq-noise-artifacts/tree/main/interop/results/20260917T134954Z>.

With the two runs above, all six pairings across the four implementations of
this profile - TypeScript, Python, Rust and Nim - have now completed a live
handshake:

| | TypeScript | Python | Rust | Nim |
|---|---|---|---|---|
| **TypeScript** | - | 2026-06-24 | 2026-06-24 | 2026-09-05 |
| **Python** | 2026-06-24 | - | 2026-06-24 | 2026-07-11 |
| **Rust** | 2026-06-24 | 2026-06-24 | - | 2026-09-05 |
| **Nim** | 2026-09-05 | 2026-07-11 | 2026-09-05 | - |
