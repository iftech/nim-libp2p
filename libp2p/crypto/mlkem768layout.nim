# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Opaque BoringSSL `MLKEM768_{public,private}_key` struct sizes, plus
## compile-time guards that the layouts mirrored in Nim still match
## BoringSSL's real ones.
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
## include the real header just for these layout checks.

const
  mlkem768PublicKeyOpaqueLen* = 512 * (3 + 9) + 32 + 32 # 6208
  mlkem768PrivateKeyOpaqueLen* = 512 * (3 + 3 + 9) + 32 + 32 + 32 # 7776

# Guards the layouts mirrored on the Nim side against a future BoringSSL
# bump silently changing them, by failing the C build instead:
# - size: if the real key structs outgrew our fixed-size buffers,
#   MLKEM768_generate_key/_encap/_decap would write out of bounds;
# - alignment: `mlkem768.nim` gives the buffers `uint16` alignment, which
#   must stay enough for the real structs;
# - `CBS`: `mlkem768.nim` builds a `{data, len}` view by hand instead of
#   calling the header-only `CBS_init`, so that shape must still match.
const opaqueLayoutAsserts =
  "#include <stddef.h>\n" & "#include <stdint.h>\n" & "#include <openssl/bytestring.h>\n" &
  "#include <openssl/mlkem.h>\n" &
  "_Static_assert(sizeof(struct MLKEM768_public_key) == " & $mlkem768PublicKeyOpaqueLen &
  ", \"BoringSSL MLKEM768_public_key size changed - update mlkem768PublicKeyOpaqueLen\");\n" &
  "_Static_assert(sizeof(struct MLKEM768_private_key) == " & $mlkem768PrivateKeyOpaqueLen &
  ", \"BoringSSL MLKEM768_private_key size changed - update mlkem768PrivateKeyOpaqueLen\");\n" &
  "_Static_assert(_Alignof(struct MLKEM768_public_key) <= _Alignof(uint16_t), " &
  "\"BoringSSL MLKEM768_public_key needs more than uint16_t alignment\");\n" &
  "_Static_assert(_Alignof(struct MLKEM768_private_key) <= _Alignof(uint16_t), " &
  "\"BoringSSL MLKEM768_private_key needs more than uint16_t alignment\");\n" &
  "_Static_assert(sizeof(CBS) == sizeof(const uint8_t *) + sizeof(size_t), " &
  "\"BoringSSL CBS layout changed - update CbsView in mlkem768.nim\");\n" &
  "_Static_assert(offsetof(CBS, data) == 0 && offsetof(CBS, len) == sizeof(const uint8_t *), " &
  "\"BoringSSL CBS layout changed - update CbsView in mlkem768.nim\");\n"
{.emit: opaqueLayoutAsserts.}
