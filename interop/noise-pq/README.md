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

Anything else goes to stderr, including the library's Chronicles logs
(`config.nims` in this directory redirects them). Any failure prints
`ERROR <msg>` to stderr and exits 1. The port must be in 1..65535.

The identity key is Ed25519, not the crypto module's default ECDSA: when
these programs were written (July 2026) py-libp2p did not deserialize ECDSA
identity keys.

## Results

These two programs are the Nim side of a 4x4 matrix with the TypeScript,
Python and Rust implementations of the same profile. The runner lives
outside this repository:
<https://github.com/paschal533/pq-noise-artifacts/tree/main/interop>.

The current result, the commit of each implementation and the limits of the
run are in the "Interoperability status" section of
`../../libp2p/protocols/secure/NOISE_HFS_SPEC.md`.
