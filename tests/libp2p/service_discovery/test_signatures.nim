# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

import chronos, results
import protobuf_serialization
import ../../../libp2p/[crypto/crypto, protocols/kademlia/protobuf]
import ../../tools/[crypto, unittest]
import ./utils

suite "Ticket - sign and verify":
  test "sign succeeds and verify passes with matching key":
    let key = PrivateKey.random(rng()).get()
    var t = makeTicket()
    check:
      t.sign(key).isOk()
      t.verify(key.getPublicKey().get())

  test "verify fails with a different key":
    let key = PrivateKey.random(rng()).get()
    let wrongKey = PrivateKey.random(rng()).get()
    let t = signedTicket(key)
    check not t.verify(wrongKey.getPublicKey().get())

  test "verify fails on empty signature (unsigned ticket)":
    let key = PrivateKey.random(rng()).get()
    let t = makeTicket() # never signed → signature = @[]
    check not t.verify(key.getPublicKey().get())

  test "verify fails with corrupted signature bytes":
    let key = PrivateKey.random(rng()).get()
    var t = signedTicket(key)
    var sig = t.signature.get()
    sig[0] = sig[0] xor 0xFF
    t.signature = Opt.some(sig)
    check not t.verify(key.getPublicKey().get())

suite "Ticket - tamper detection":
  # The signature covers: advertisement || tInit || tMod || tWaitFor
  # Mutating any covered field must break verification.

  test "tampered advertisement bytes":
    let key = PrivateKey.random(rng()).get()
    var t = signedTicket(key)
    var ad = t.advertisement.get()
    ad[0] = ad[0] xor 0xFF
    t.advertisement = Opt.some(ad)
    check not t.verify(key.getPublicKey().get())

  test "tampered tInit":
    let key = PrivateKey.random(rng()).get()
    var t = signedTicket(key)
    t.tInit = t.tInit.get() + 1
    check not t.verify(key.getPublicKey().get())

  test "tampered tMod":
    let key = PrivateKey.random(rng()).get()
    var t = signedTicket(key)
    t.tMod = t.tMod.get() + 1
    check not t.verify(key.getPublicKey().get())

  test "tampered tWaitFor":
    let key = PrivateKey.random(rng()).get()
    var t = signedTicket(key)
    t.tWaitFor = t.tWaitFor.get() + 1.secs
    check not t.verify(key.getPublicKey().get())

suite "Ticket - boundary values":
  test "all-zero time fields sign and verify correctly":
    # tInit=0, tMod=0, tWaitFor=0 are valid; must not be treated as unsigned
    let key = PrivateKey.random(rng()).get()
    var t = Ticket(
      advertisement: @[0xAB'u8],
      tInit: 0'i64,
      tMod: 0'i64,
      tWaitFor: ZeroDuration,
      signature: Opt.none(seq[byte]),
    )
    check:
      t.sign(key).isOk()
      t.verify(key.getPublicKey().get())

  test "empty advertisement bytes sign and verify correctly":
    let key = PrivateKey.random(rng()).get()
    var t = Ticket(
      advertisement: @[],
      tInit: 1000'i64,
      tMod: 2000'i64,
      tWaitFor: 300.secs,
      signature: Opt.none(seq[byte]),
    )
    check:
      t.sign(key).isOk()
      t.verify(key.getPublicKey().get())

  test "re-signing overwrites previous signature":
    # Signing twice must not leave a ticket that verifies against the first key
    let key1 = PrivateKey.random(rng()).get()
    let key2 = PrivateKey.random(rng()).get()
    var t = makeTicket()
    check:
      t.sign(key1).isOk()
      t.sign(key2).isOk()
      not t.verify(key1.getPublicKey().get())
      t.verify(key2.getPublicKey().get())

suite "Ticket - timestamp encoding":
  test "Unix seconds use int64 varints and survive signing round-trip":
    let key = PrivateKey.random(rng()).get()
    var ticket = Ticket(tInit: 1_700_000_000'i64, tMod: 1_700_000_001'i64)
    check Protobuf.encode(ticket) ==
      @[0x10'u8, 0x80, 0xE2, 0xCF, 0xAA, 0x06, 0x18, 0x81, 0xE2, 0xCF, 0xAA, 0x06]
    check ticket.toBytes() ==
      @[0'u8, 0, 0, 0, 0x65, 0x53, 0xF1, 0, 0, 0, 0, 0, 0x65, 0x53, 0xF1, 1, 0, 0, 0, 0]
    check ticket.sign(key)
    let decoded = Protobuf.decode(Protobuf.encode(ticket), Ticket)
    check:
      decoded.tInit == ticket.tInit
      decoded.tMod == ticket.tMod
      decoded.verify(key.getPublicKey().get())

  test "absent timestamps remain distinct from explicit Unix epoch":
    let absent = Protobuf.decode(Protobuf.encode(Ticket()), Ticket)
    let epoch = Protobuf.decode(@[0x10'u8, 0, 0x18, 0], Ticket)
    check:
      absent.tInit.isNone()
      absent.tMod.isNone()
      epoch.tInit == Opt.some(0'i64)
      epoch.tMod == Opt.some(0'i64)
      Protobuf.encode(epoch) == @[0x10'u8, 0, 0x18, 0]
