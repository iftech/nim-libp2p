# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import stew/endians2, results
import ../../../interop/gossipsub/src/[interop_partial_message]
import ../../tools/[unittest]

const
  MetadataLen = 1
  PositionLen = sizeof(uint64)
  PositionsPerPart = PartLen div PositionLen ## 128 positions per part

suite "GossipSub Interop - InteropPartialMessage":
  test "partsMetadata returns 1-byte bitmap":
    let pm = InteropPartialMessage.new(0)
    check pm.partsMetadata() == @[0b00000000'u8]

    pm.fillParts(InteropPartsMetadata.init(0b10101010))
    check pm.partsMetadata() == @[0b10101010'u8]

  test "interopUnionPartsMetadata performs OR":
    let res = interopUnionPartsMetadata(@[0b00001111'u8], @[0b11110000'u8])
    check res.isOk()
    check res.get() == @[0b11111111'u8]

  test "interopUnionPartsMetadata treats empty as bitmap 0":
    let res = interopUnionPartsMetadata(@[0b00000101'u8], @[])
    check res.isOk()
    check res.get() == @[0b00000101'u8]

  test "interopUnionPartsMetadata rejects wrong length":
    check interopUnionPartsMetadata(@[1'u8, 2'u8], @[3'u8]).isErr()
    check interopUnionPartsMetadata(@[1'u8, 2'u8], @[]).isErr()

  test "bitmap tracks present parts":
    let pm = InteropPartialMessage.new(1)
    check:
      pm.partsMetadata() == @[0b00000000'u8]
      pm.partsPresent() == 0
      not pm.isComplete()

    pm.fillParts(InteropPartsMetadata.init(0b00000101)) # parts 0 and 2
    check:
      pm.partsMetadata() == @[0b00000101'u8]
      pm.partsPresent() == 2
      not pm.isComplete()

  test "isComplete when all 8 parts present":
    let pm = InteropPartialMessage.new(1)
    pm.fillParts(InteropPartsMetadata.init(0b11111111))
    check:
      pm.partsMetadata() == @[0b11111111'u8]
      pm.partsPresent() == 8
      pm.isComplete()

  test "fillParts generates deterministic data":
    let pm = InteropPartialMessage.new(100)
    pm.fillParts(InteropPartsMetadata.init(0b00000001)) # part 0 only

    check pm.parts[0].len == PartLen

    # Part 0, position 0: start = 100
    let pos0 = fromBytesBE(uint64, pm.parts[0].toOpenArray(0, PositionLen - 1))
    check pos0 == 100'u64

    # Part 0, position 1: start + 1 = 101
    let pos1 =
      fromBytesBE(uint64, pm.parts[0].toOpenArray(PositionLen, 2 * PositionLen - 1))
    check pos1 == 101'u64

    # Part 0, last position (PositionsPerPart - 1): start + (PositionsPerPart - 1)
    let posLast = fromBytesBE(
      uint64,
      pm.parts[0].toOpenArray(
        (PositionsPerPart - 1) * PositionLen, PositionsPerPart * PositionLen - 1
      ),
    )
    check posLast == uint64(100 + PositionsPerPart - 1)

  test "fillParts offset per part":
    let pm = InteropPartialMessage.new(0)
    pm.fillParts(InteropPartsMetadata.init(0b00000011)) # parts 0 and 1

    # Part 0 starts at counter = 0
    let p0p0 = fromBytesBE(uint64, pm.parts[0].toOpenArray(0, PositionLen - 1))
    check p0p0 == 0'u64

    # Part 1 starts at counter = 0 + 1*PositionsPerPart
    let p1p0 = fromBytesBE(uint64, pm.parts[1].toOpenArray(0, PositionLen - 1))
    check p1p0 == uint64(PositionsPerPart)

  test "fillParts last position value":
    let pm = InteropPartialMessage.new(0)
    pm.fillParts(InteropPartsMetadata.init(0b10000000)) # part 7 only

    # Part 7 starts at counter = 0 + 7*PositionsPerPart
    let p7p0 = fromBytesBE(uint64, pm.parts[7].toOpenArray(0, PositionLen - 1))
    check p7p0 == uint64(7 * PositionsPerPart)

    # Part 7, last position: 7*PositionsPerPart + (PositionsPerPart - 1) = NumParts*PositionsPerPart - 1
    let p7last = fromBytesBE(
      uint64,
      pm.parts[7].toOpenArray(
        (PositionsPerPart - 1) * PositionLen, PositionsPerPart * PositionLen - 1
      ),
    )
    check p7last == uint64(NumParts * PositionsPerPart - 1)

suite "GossipSub Interop - Wire Format":
  test "materializeParts encodes parts peer doesn't have":
    let pm = InteropPartialMessage.new(42)
    pm.fillParts(InteropPartsMetadata.init(0b00000111)) # parts 0, 1, 2

    # Peer has part 0 (bitmap = 0b00000001), needs parts 1 and 2
    let res = pm.materializeParts(@[0b00000001'u8])
    check res.isOk()

    let data = res.get()
    # Format: [bitmap: 1][part1: PartLen][part2: PartLen][groupId: GroupIdLen]
    check data.len == MetadataLen + 2 * PartLen + GroupIdLen

    # Response bitmap should be 0b00000110 (parts 1 and 2)
    check data[0] == 0b00000110'u8

    # Group ID at end
    let gid = fromBytesBE(uint64, data[data.len - GroupIdLen ..< data.len])
    check gid == 42'u64

  test "materializeParts returns empty when peer has all":
    let pm = InteropPartialMessage.new(42)
    pm.fillParts(InteropPartsMetadata.init(0b00000011)) # parts 0, 1

    # Peer has both parts
    let res = pm.materializeParts(@[0b00000011'u8])
    check res.isOk()
    check res.get().len == 0

  test "materializeParts skips parts we don't have":
    let pm = InteropPartialMessage.new(42)
    pm.fillParts(InteropPartsMetadata.init(0b00000001)) # only part 0

    # Peer has nothing
    let res = pm.materializeParts(@[0b00000000'u8])
    check res.isOk()

    let data = res.get()
    check data.len == MetadataLen + PartLen + GroupIdLen
    check data[0] == 0b00000001'u8

  test "materializeParts with empty metadata sends all available parts":
    let pm = InteropPartialMessage.new(42)
    pm.fillParts(InteropPartsMetadata.init(0b00000101)) # parts 0 and 2

    let res = pm.materializeParts(@[])
    check res.isOk()

    let data = res.get()
    check data.len == MetadataLen + 2 * PartLen + GroupIdLen
    check data[0] == 0b00000101'u8

  test "materializeParts rejects metadata of wrong length":
    let pm = InteropPartialMessage.new(42)
    pm.fillParts(InteropPartsMetadata.init(0b00000001))
    check pm.materializeParts(@[0'u8, 0'u8]).isErr()

  test "extend decodes wire format":
    let sender = InteropPartialMessage.new(42)
    sender.fillParts(InteropPartsMetadata.init(0b00000011)) # parts 0, 1

    # Encode parts for a peer with nothing
    let encoded = sender.materializeParts(@[0b00000000'u8]).get()

    # Receiver decodes
    let receiver = InteropPartialMessage.new(42)
    let res = receiver.extend(encoded)
    check res.isOk()
    check receiver.partsMetadata() == @[0b00000011'u8]
    check receiver.parts[0] == sender.parts[0]
    check receiver.parts[1] == sender.parts[1]

  test "extend ignores parts already present":
    let sender = InteropPartialMessage.new(42)
    sender.fillParts(InteropPartsMetadata.init(0b00000011)) # parts 0 and 1

    # Encode for a peer that has nothing — both parts appear in the wire stream
    let encoded = sender.materializeParts(@[0b00000000'u8]).get()

    let receiver = InteropPartialMessage.new(42)
    receiver.fillParts(InteropPartsMetadata.init(0b00000001))
      # has part 0 with deterministic data

    # Overwrite part 0 with sentinel bytes so we can detect if extend touches it
    let sentinel = newSeq[byte](PartLen)
    receiver.parts[0] = sentinel

    let res = receiver.extend(encoded)
    check res.isOk()
    check receiver.partsMetadata() == @[0b00000011'u8]
    check receiver.parts[0] == sentinel # part 0 not overwritten by extend
    check receiver.parts[1] == sender.parts[1]

  test "extend correctly reads part after a duplicate — offset advances past duplicate":
    let sender = InteropPartialMessage.new(42)
    sender.fillParts(InteropPartsMetadata.init(0b00000101)) # parts 0 and 2

    # Encode for a peer that has nothing — wire contains [part0][part2] contiguously
    let encoded = sender.materializeParts(@[0b00000000'u8]).get()
    check encoded.len == MetadataLen + 2 * PartLen + GroupIdLen

    let receiver = InteropPartialMessage.new(42)
    receiver.fillParts(InteropPartsMetadata.init(0b00000001)) # already has part 0

    let res = receiver.extend(encoded)
    check res.isOk()
    check receiver.partsMetadata() == @[0b00000101'u8]
    check receiver.parts[2] == sender.parts[2]
      # part 2 read from correct offset, not part 0's bytes

  test "extend rejects wrong group ID":
    let sender = InteropPartialMessage.new(42)
    sender.fillParts(InteropPartsMetadata.init(0b00000001))

    let encoded = sender.materializeParts(@[0b00000000'u8]).get()

    let receiver = InteropPartialMessage.new(99) # different group ID
    let res = receiver.extend(encoded)
    check res.isErr()

  test "extend rejects data too short":
    let receiver = InteropPartialMessage.new(42)
    let res = receiver.extend(@[0'u8]) # way too short
    check res.isErr()

  test "extend accumulates across multiple calls":
    let pm1 = InteropPartialMessage.new(42)
    pm1.fillParts(InteropPartsMetadata.init(0b00000001)) # part 0

    let pm2 = InteropPartialMessage.new(42)
    pm2.fillParts(InteropPartsMetadata.init(0b00000010)) # part 1

    let receiver = InteropPartialMessage.new(42)

    let enc1 = pm1.materializeParts(@[0b00000000'u8]).get()
    check receiver.extend(enc1).isOk()
    check receiver.partsMetadata() == @[0b00000001'u8]

    let enc2 = pm2.materializeParts(@[0b00000001'u8]).get()
    check receiver.extend(enc2).isOk()
    check receiver.partsMetadata() == @[0b00000011'u8]

  test "extend rejects bitmap claiming more parts than data contains":
    # bitmap claims 3 parts (bits 0,1,2) but partData holds only 2*PartLen bytes
    # groupId tail is all-zero, matching InteropPartialMessage.new(0)
    var wire = newSeq[byte](MetadataLen + 2 * PartLen + GroupIdLen)
    wire[0] = 0b00000111'u8 # 3 bits set
    let receiver = InteropPartialMessage.new(0)
    check receiver.extend(wire).isErr()

  test "extend rejects duplicate bitmap entries without corresponding part bytes":
    # bitmap claims part 0 is present, but the wire has no part bytes at all.
    # receiver already has part 0, so the duplicate branch must still reject this.
    var wire = newSeq[byte](MetadataLen + GroupIdLen)
    wire[0] = 0b00000001'u8

    let receiver = InteropPartialMessage.new(0)
    receiver.fillParts(InteropPartsMetadata.init(0b00000001))

    check receiver.extend(wire).isErr()

  test "extend rejects partData length not a multiple of PartLen":
    # Wire has one extra byte beyond a full part
    var wire = newSeq[byte](MetadataLen + PartLen + 1 + GroupIdLen)
    wire[0] = 0b00000001'u8
    let receiver = InteropPartialMessage.new(0)
    check receiver.extend(wire).isErr()

  test "extend accepts empty bitmap with no part data":
    # bitmap=0, no parts in the stream
    var wire = newSeq[byte](MetadataLen + GroupIdLen)
    wire[0] = 0b00000000'u8
    let receiver = InteropPartialMessage.new(0)
    check receiver.extend(wire).isOk()
    check receiver.partsMetadata() == @[0b00000000'u8]
