# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import typetraits
import bearssl/[rand, hash]
import results
import ../utils/redact

type Rng* = ref object
  drbg: ref HmacDrbgContext

redactType(Rng)

proc newRng*(): Rng =
  ## Create a new randomness source for libp2p.
  ##
  ## BearSSL remains the temporary backend in this migration phase.
  let seeder = prngSeederSystem(nil)
  if seeder == nil:
    return nil

  let rng = Rng(drbg: (ref HmacDrbgContext)())
  hmacDrbgInit(rng.drbg[], addr sha256Vtable, nil, 0)
  if seeder(PrngClassPointerConst(addr rng.drbg[].vtable)) == 0:
    return nil
  rng

proc newBearSslRng*(drbg: ref HmacDrbgContext): Rng =
  ## Wrap an existing BearSSL HMAC-DRBG context.
  ##
  ## This is a temporary compatibility API for the BearSSL to BoringSSL
  ## migration. New code should use `newRng`.
  if isNil(drbg):
    return nil
  Rng(drbg: drbg)

template bearSslDrbg*(
    rng: Rng
): untyped {.deprecated: "BearSSL is being replaced; use Rng.generate".} =
  rng.drbg[]

template bearSslDrbgRef*(
    rng: Rng
): untyped {.deprecated: "BearSSL is being replaced; use Rng.generate".} =
  rng.drbg

template bearSslPrng*(rng: Rng): untyped =
  PrngClassPointerConst(addr rng.drbg[].vtable)

proc generate*[T](rng: Rng, v: var T) =
  ## Fill `v` with random data. `v` must be a simple type.
  doAssert not isNil(rng), "Rng is nil"
  static:
    doAssert supportsCopyMem(T)

  when sizeof(v) > 0:
    when T is bool:
      var tmp: byte
      hmacDrbgGenerate(rng.drbg[], addr tmp, uint sizeof(tmp))
      v = (tmp and 1'u8) == 1
    else:
      hmacDrbgGenerate(rng.drbg[], addr v, uint sizeof(v))

proc generate*[V](rng: Rng, v: var openArray[V]) =
  ## Fill `v` with random data. `V` must be a simple type.
  doAssert not isNil(rng), "Rng is nil"
  static:
    doAssert supportsCopyMem(V) and sizeof(V) > 0

  when V is bool:
    for b in v.mitems:
      rng.generate(b)
  else:
    if v.len > 0:
      hmacDrbgGenerate(rng.drbg[], addr v[0], uint v.len * sizeof(V))

template generate*[V](rng: Rng, v: var seq[V]) =
  rng.generate(v.toOpenArray(0, v.high()))

proc generateBytes*(rng: Rng, n: int): seq[byte] =
  if n <= 0:
    return @[]

  var buf = newSeqUninit[byte](n)
  rng.generate(buf)
  buf

proc generate*(rng: Rng, T: type): T {.noinit.} =
  ## Create a new instance of `T` filled with random data.
  var v {.noinit.}: T
  rng.generate(v)
  v

proc randBelow(rng: Rng, value: var uint32, max: uint32): int =
  let threshold = (0'u32 - max) mod max
  # Reject values below the threshold to avoid modulo bias.
  while value < threshold:
    rng.generate(value)
  int(value mod max)

proc shuffle*[T](rng: Rng, x: var openArray[T]) =
  if x.len <= 1:
    return

  var randValues = newSeqUninit[uint32](len(x) - 1)
  rng.generate(randValues)

  for i in countdown(x.high, 1):
    let y = rng.randBelow(randValues[i - 1], uint32(i + 1))
    swap(x[i], x[y])

proc randBelow(rng: Rng, max: uint32): int =
  ## Return a uniformly random integer in [0, max) using 32-bit rejection sampling.
  var value: uint32
  rng.generate(value)
  rng.randBelow(value, max)

proc rand*(rng: Rng, low, high: int): int =
  ## Return a uniformly random integer in the inclusive range [`low`, `high`].
  doAssert low <= high, "random range must not be empty"

  let width =
    if low >= 0 or high < 0:
      uint64(high - low) + 1
    else:
      uint64(-(low + 1)) + uint64(high) + 2
  doAssert width <= uint64(uint32.high), "random range is too large"

  low + rng.randBelow(width.uint32)

proc pick*[T](rng: Rng, x: openArray[T], n: int): Opt[seq[T]] =
  doAssert n >= 0, "n must be non-negative"
  if x.len == 0:
    return Opt.none(seq[T])
  if n == 0:
    return Opt.some(newSeq[T]())

  var indices = newSeq[int](x.len)
  for i in 0 ..< x.len:
    indices[i] = i

  let count = min(n, x.len)
  var output = newSeq[T](count)
  for i in 0 ..< count:
    let j = i + rng.randBelow((x.len - i).uint32)
    swap(indices[i], indices[j])
    output[i] = x[indices[i]]
  Opt.some(output)

proc pickOne*[T](rng: Rng, x: openArray[T]): Opt[T] =
  if x.len == 0:
    return Opt.none(T)

  Opt.some(x[rng.randBelow(x.len.uint32)])
