# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## InteropPartialMessage — bitmap-based partial message.
##
## Wire format:
##   - Metadata: 1-byte bitmap, bit i == part i present
##   - Partial message: [bitmap: 1 byte][parts: N * 1024 bytes][groupId: 8 bytes]
##   - GroupId: 8 bytes, big-endian uint64
##   - Deterministic data: start = BE(groupId), part i position j = start + i*128 + j

import results, stew/endians2
import ../../../libp2p/[protocols/pubsub/gossipsub/partial_message]

const
  MetadataLen = 1 # uint8
  PartLen* = 1024
  NumParts* = 8 ## parts per message
  GroupIdLen* = 8 ## big-endian uint64
  PositionsPerPart = PartLen div sizeof(uint64) ## 128 uint64

type InteropPartsMetadata* = object
  bitmap: uint8 ## bit i == part i present

func init*(_: typedesc[InteropPartsMetadata], bitmap: uint8): InteropPartsMetadata =
  InteropPartsMetadata(bitmap: bitmap)

func convert*(
    _: typedesc[InteropPartsMetadata], metadata: PartsMetadata
): Result[InteropPartsMetadata, string] =
  if metadata.len == 0:
    return ok(InteropPartsMetadata(bitmap: 0'u8))

  if metadata.len != MetadataLen:
    return err("invalid metadata length, expected 0 or 1 byte")

  ok(InteropPartsMetadata.init(metadata[0]))

func hasBit*(metadata: InteropPartsMetadata, i: int): bool =
  doAssert i in 0 ..< NumParts
  (metadata.bitmap and (1'u8 shl uint8(i))) != 0

proc setBit*(metadata: var InteropPartsMetadata, i: int) =
  doAssert i in 0 ..< NumParts
  metadata.bitmap = metadata.bitmap or (1'u8 shl uint8(i))

func isComplete*(metadata: InteropPartsMetadata): bool =
  metadata.bitmap == 0b11111111

func partsPresent*(metadata: InteropPartsMetadata): int =
  var count = 0
  for i in 0 ..< NumParts:
    if metadata.hasBit(i):
      inc count
  count

func bytesForBitmap(metadata: InteropPartsMetadata): int =
  metadata.partsPresent() * PartLen

type InteropPartialMessage* = ref object
  metadata: InteropPartsMetadata
  parts*: array[NumParts, seq[byte]]
  groupIdBytes*: array[GroupIdLen, byte]

func new*(_: typedesc[InteropPartialMessage], groupId: uint64): InteropPartialMessage =
  InteropPartialMessage(groupIdBytes: toBytesBE(groupId))

proc fromBytes*(
    _: typedesc[InteropPartialMessage], groupIdBytes: seq[byte]
): InteropPartialMessage =
  doAssert groupIdBytes.len == GroupIdLen, "groupId must be 8 bytes"
  var groupIdArr: array[GroupIdLen, byte]
  copyMem(addr groupIdArr[0], addr groupIdBytes[0], GroupIdLen)
  InteropPartialMessage(groupIdBytes: groupIdArr)

func isComplete*(pm: InteropPartialMessage): bool =
  pm.metadata.isComplete()

func partsPresent*(pm: InteropPartialMessage): int =
  pm.metadata.partsPresent()

proc makePart(groupId: uint64, partIndex: int): seq[byte] =
  ## Generate deterministic data for a single part.
  ## Part i, position j: value == groupId + i*128 + j
  var part = newSeq[byte](PartLen)
  var counter = groupId + uint64(partIndex) * PositionsPerPart
  for j in 0 ..< PositionsPerPart:
    let pos = j * sizeof(uint64)
    part[pos ..< pos + sizeof(uint64)] = @(toBytesBE(counter))
    counter.inc
  part

proc fillParts*(pm: InteropPartialMessage, metadata: InteropPartsMetadata) =
  ## Fill parts with deterministic data.
  let groupId = fromBytesBE(uint64, pm.groupIdBytes)
  for i in 0 ..< NumParts:
    if not metadata.hasBit(i):
      continue
    pm.parts[i] = makePart(groupId, i)
    pm.metadata.setBit(i)

proc extend*(pm: InteropPartialMessage, data: seq[byte]): Result[void, string] =
  ## Decode wire format and add new parts.
  ## Wire format: [bitmap: 1 byte][parts: N * 1024 bytes][groupId: 8 bytes]
  if data.len < MetadataLen + GroupIdLen:
    return err("data too short")

  let msgMetadata = InteropPartsMetadata.init(data[0])
  let groupIdStart = data.len - GroupIdLen
  let partData = data[MetadataLen ..< groupIdStart]

  # Verify group ID
  if data[groupIdStart ..< data.len] != @(pm.groupIdBytes):
    return err("group ID mismatch")

  if partData.len != bytesForBitmap(msgMetadata):
    return err("invalid data length")

  var offset = 0
  for i in 0 ..< NumParts:
    if not msgMetadata.hasBit(i):
      continue # not in message

    if pm.metadata.hasBit(i):
      offset += PartLen
      continue # already have this part, step past them

    if offset + PartLen > partData.len:
      return err("not enough data for part")

    pm.parts[i] = partData[offset ..< offset + PartLen]
    pm.metadata.setBit(i)
    offset += PartLen

  ok()

proc groupId*(pm: InteropPartialMessage): GroupId {.gcsafe, raises: [].} =
  @(pm.groupIdBytes)

proc partsMetadata*(pm: InteropPartialMessage): PartsMetadata =
  @[pm.metadata.bitmap]

proc materializeParts*(
    pm: InteropPartialMessage, metadata: PartsMetadata
): Result[PartsData, string] =
  ## Encode parts that the peer doesn't have.
  ## metadata is the peer's 1-byte bitmap (what parts they have).
  ## Returns: [bitmap][parts...][groupId] for parts we have that they don't.
  let peerMetadata = InteropPartsMetadata.convert(metadata).valueOr:
    return err(error)

  var responseMetadata = InteropPartsMetadata()
  var data = newSeq[byte](MetadataLen) # placeholder for bitmap byte

  for i in 0 ..< NumParts:
    if peerMetadata.hasBit(i):
      continue # peer has this part

    if not pm.metadata.hasBit(i):
      continue # we don't have this part

    responseMetadata.setBit(i)
    data.add(pm.parts[i])

  if responseMetadata.partsPresent() == 0:
    return ok(newSeq[byte]()) # nothing to send

  data[0] = responseMetadata.bitmap
  data.add(@(pm.groupIdBytes))
  ok(data)

proc interopUnionPartsMetadata*(
    a, b: PartsMetadata
): Result[PartsMetadata, string] {.gcsafe, raises: [].} =
  let metaA = InteropPartsMetadata.convert(a).valueOr:
    return err(error)

  let metaB = InteropPartsMetadata.convert(b).valueOr:
    return err(error)

  ok(@[metaA.bitmap or metaB.bitmap])
