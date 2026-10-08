# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Opaque BoringSSL `MLKEM768_{public,private}_key` struct sizes, plus a
## compile-time guard that they still match BoringSSL's real layout.
##
## Sizes copied from BoringSSL's `include/openssl/mlkem.h`. These layouts
## are BoringSSL-internal and unstable across versions; they must never be
## serialized, only ever passed back into the MLKEM768_* C API by pointer.
##
## Kept in this standalone module rather than inline in `mlkem768.nim`: the
## guard below needs `#include <openssl/mlkem.h>`, which declares the real,
## strongly-typed `MLKEM768_*` function prototypes. `mlkem768.nim` declares
## its own loosely-typed (`byte*`) `importc` prototypes for those same
## functions; having both sets of declarations land in the same generated C
## file is a hard conflict for the C compiler. This module never calls into
## boringssl itself, so it never emits those prototypes and can safely
## include the real header just for `sizeof`.

const
  mlkem768PublicKeyOpaqueLen* = 512 * (3 + 9) + 32 + 32 # 6208
  mlkem768PrivateKeyOpaqueLen* = 512 * (3 + 3 + 9) + 32 + 32 + 32 # 7776

# Guards the sizes above against a future BoringSSL bump silently changing
# the opaque layouts: if the real C structs ever grow past our fixed-size
# buffers, this fails the C build instead of letting
# MLKEM768_generate_key/_encap/_decap write out of bounds.
const opaqueSizeAsserts =
  "#include <openssl/mlkem.h>\n" &
  "_Static_assert(sizeof(struct MLKEM768_public_key) == " &
  $mlkem768PublicKeyOpaqueLen &
  ", \"BoringSSL MLKEM768_public_key size changed - update mlkem768PublicKeyOpaqueLen\");\n" &
  "_Static_assert(sizeof(struct MLKEM768_private_key) == " &
  $mlkem768PrivateKeyOpaqueLen &
  ", \"BoringSSL MLKEM768_private_key size changed - update mlkem768PrivateKeyOpaqueLen\");\n"
{.emit: opaqueSizeAsserts.}
