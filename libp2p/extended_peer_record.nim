# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## This module implements Routing Records.

{.push raises: [].}

import std/[sequtils, times, hashes]
import pkg/results
import protobuf_serialization, protobuf_serialization/pkg/results
import multiaddress, multicodec, peerid, signed_envelope, routing_record, utils/protobuf

export peerid, multiaddress, signed_envelope, routing_record

const
  ## Maximum allowed size (in bytes) for the `data` field inside a `ServiceInfo`.
  ## Larger values are rejected at advertisement creation and on receipt.
  MaxServiceDataSize* = 33

  ## Maximum allowed size (in bytes) for an encoded `SignedExtendedPeerRecord`
  ## (the full XPR advertisement that is stored and gossiped for a service).
  MaxXPRSize* = 1024

type
  ServiceInfo* {.proto2.} = object
    id* {.fieldNumber: 1, required.}: string
    data* {.fieldNumber: 2.}: Opt[seq[byte]]

  ExtendedPeerRecord* {.proto3.} = object
    peerId* {.fieldNumber: 1, ext.}: PeerId
    seqNo* {.fieldNumber: 2, pint.}: uint64
    addresses* {.fieldNumber: 3.}: seq[AddressInfo]
    services* {.fieldNumber: 4.}: seq[ServiceInfo]

proc validateDecoded(
    T: typedesc[ExtendedPeerRecord], xpr: ExtendedPeerRecord
): LPResult[void] =
  if xpr.peerId.len == 0:
    return err("missing peer id")

  xpr.addresses.checkAddresses()

Protobuf.serializerFor([ExtendedPeerRecord])

proc init*(
    T: typedesc[ExtendedPeerRecord],
    peerId: PeerId,
    addresses: seq[MultiAddress],
    seqNo = getTime().toUnix().uint64,
    services: seq[ServiceInfo] = @[],
): T =
  T(
    peerId: peerId,
    seqNo: seqNo,
    addresses: addresses.mapIt(AddressInfo(address: it)),
    services: services,
  )

## Functions related to signed peer records
type SignedExtendedPeerRecord* = SignedPayload[ExtendedPeerRecord]

proc payloadDomain*(T: typedesc[ExtendedPeerRecord]): string =
  $multiCodec("libp2p-peer-record")

proc payloadType*(T: typedesc[ExtendedPeerRecord]): seq[byte] =
  @[(byte) 0x03, (byte) 0x01]

proc checkValid*(spr: SignedExtendedPeerRecord): Result[void, EnvelopeError] =
  if not spr.data.peerId.match(spr.envelope.publicKey):
    err(EnvelopeInvalidSignature)
  else:
    ok()

proc isValid*(si: ServiceInfo): bool =
  si.data.get(@[]).len <= MaxServiceDataSize

proc isValid*(xpr: SignedExtendedPeerRecord): bool =
  for svc in xpr.data.services:
    if not svc.isValid():
      return false
  let encoded = xpr.encode()
  if encoded.len == 0 or encoded.len > MaxXPRSize:
    return false
  true

proc build*(
    T: typedesc[SignedExtendedPeerRecord],
    privateKey: PrivateKey,
    record: ExtendedPeerRecord,
): LPResult[SignedExtendedPeerRecord] =
  for svc in record.services:
    if not svc.isValid():
      return err(
        "ServiceInfo.data exceeds maximum size of " & $MaxServiceDataSize & " bytes"
      )

  let signed = SignedExtendedPeerRecord.init(privateKey, record).valueOr:
    return err("failed to create signed extended peer record: " & $error)

  if not signed.isValid():
    return err("encoded XPR exceeds maximum size of " & $MaxXPRSize & " bytes")

  ok(signed)

# This is for internal use only
proc hash*(service: ServiceInfo): Hash =
  return service.id.hash()
