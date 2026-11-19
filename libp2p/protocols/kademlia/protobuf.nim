# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/hashes
import chronos, chronicles
import ../../utils/[opt, shortlog]
import results
import ../../multiaddress
import stew/endians2
import ../../crypto/crypto
import protobuf_serialization
import protobuf_serialization/pkg/results
import protobuf_serialization/std/enums
import ../../utils/[protobuf, protobuf_chronos_sec, protobuf_distinct_seq]
import ./key_value

distinctByteSeqSerialization(Key)
distinctByteSeqSerialization(Value)

type
  Record* {.proto2.} = object
    key* {.fieldNumber: 1, ext.}: Opt[Key]
    value* {.fieldNumber: 2, ext.}: Opt[Value]
    timeReceived* {.fieldNumber: 5.}: Opt[string]

  MessageType* = enum
    putValue = 0
    getValue = 1
    addProvider = 2
    getProviders = 3
    findNode = 4
    ping = 5 # Deprecated
    register = 16 # REGISTER for Service Discovery
    getAds = 17 # GET_ADS for Service Discovery

  ConnectionStatus* = enum
    notConnected = 0
    connected = 1
    canConnect = 2 # Unused
    cannotConnect = 3 # Unused

  Peer* {.proto2.} = object
    id* {.fieldNumber: 1.}: Opt[seq[byte]]
    addrs* {.fieldNumber: 2, ext.}: seq[MultiAddress]
    connection* {.fieldNumber: 3, ext.}: Opt[ConnectionStatus]

  # Registration status for Service Discovery
  RegistrationStatus* = enum
    Confirmed = 0
    Wait = 1
    Rejected = 2

  AddProviderStatus* = enum
    ## Response status carried in field 11 of an ADD_PROVIDER reply (nim extension).
    ## Only populated when the responding peer has ``providerRejection = true``.
    ## Peers with ``providerRejection = false`` never write this field; receivers
    ## always decode it when present and act on it only if their own
    ## ``providerRejection`` is true.
    accepted = 0
    rejected = 1

  UnixTimestamp* = int64 ## Seconds since the Unix epoch (1970-01-01 UTC).

  # Ticket message for Service Discovery
  Ticket* {.proto2.} = object
    advertisement* {.fieldNumber: 1.}: Opt[seq[byte]]
      # field 1 - Copy of the original advertisement
    tInit* {.fieldNumber: 2, pint.}: Opt[UnixTimestamp]
      # field 2 - Ticket creation timestamp (Unix time in seconds)
    tMod* {.fieldNumber: 3, pint.}: Opt[UnixTimestamp]
      # field 3 - Last modification timestamp (Unix time in seconds)
    tWaitFor* {.fieldNumber: 4, ext.}: Opt[Duration]
      # field 4 - Remaining wait time in seconds
    signature* {.fieldNumber: 5.}: Opt[seq[byte]] # field 5 - Ed25519 signature
    serviceIds* {.fieldNumber: 6.}: seq[seq[byte]] # field 6 - Service ids of the batch

  # Register message for Service Discovery
  RegisterMessage* {.proto2.} = object
    advertisement* {.fieldNumber: 1.}: Opt[seq[byte]] # field 1 - Encoded advertisement
    status* {.fieldNumber: 2, ext.}: Opt[RegistrationStatus]
      # field 2 - Registration status (response only)
    ticket* {.fieldNumber: 3.}: Opt[Ticket] # field 3 - Optional ticket
    serviceIds* {.fieldNumber: 4.}: seq[seq[byte]]
      # field 4 - Service ids registered beside `Message.key`
    accepted* {.fieldNumber: 5.}: seq[seq[byte]]
      # field 5 - Service ids admitted (response only)

  # GetAds message for Service Discovery
  GetAdsMessage* {.proto2.} = object
    advertisements* {.fieldNumber: 1.}: seq[seq[byte]]
      # field 1 - List of encoded advertisements

  Message* {.proto2.} = object
    msgType* {.fieldNumber: 1, ext.}: Opt[MessageType]
    key* {.fieldNumber: 2, ext.}: Opt[Key]
    record* {.fieldNumber: 3.}: Opt[Record]
    closerPeers* {.fieldNumber: 8.}: seq[Peer]
    providerPeers* {.fieldNumber: 9.}: seq[Peer]
    providerStatus* {.fieldNumber: 11, ext.}: Opt[AddProviderStatus]
    register* {.fieldNumber: 21.}: Opt[RegisterMessage]
    getAds* {.fieldNumber: 22.}: Opt[GetAdsMessage]

func shortLog*(record: Record): auto =
  (
    key: record.key.get(Key.fromBytes(@[])).shortLog,
    value: record.value.get(Value.fromBytes(@[])).shortLog,
    timeReceived: record.timeReceived.get("").shortLog,
  )

chronicles.formatIt(Record):
  shortLog(it)

func shortLog*(peer: Peer): auto =
  (
    id: peer.id.get(@[]).shortLog,
    addresses: peer.addrs.shortLog,
    connection: peer.connection,
  )

chronicles.formatIt(Peer):
  shortLog(it)

func shortLog*(msg: Message): auto =
  (
    messageType: msg.msgType,
    key: msg.key.get(Key.fromBytes(@[])).shortLog,
    record: msg.record.get(Record()).shortLog,
    closerPeers: msg.closerPeers.shortLog,
    providerPeers: msg.providerPeers.shortLog,
    hasRegistration: msg.register.isSome,
    advertisementCount:
      if msg.getAds.isSome:
        msg.getAds.get().advertisements.len
      else:
        0,
  )

chronicles.formatIt(Message):
  shortLog(it)

func hide(c: Opt[ConnectionStatus], hideConnectionStatus: bool): Opt[ConnectionStatus] =
  if hideConnectionStatus:
    return Opt.none(ConnectionStatus)
  c

proc hash*(peer: Peer): Hash =
  hash(peer.id)

proc `==`*(a, b: Peer): bool =
  a.id == b.id

Protobuf.serializerFor([Record])

# Peer and Message have custom encode because of additional hideConnectionStatus parameter
Protobuf.decodeFor([Peer])
Protobuf.decodeFor([Message], withMetrics = true, domain = "kademlia")

proc encode*(
    msg: Peer, hideConnectionStatus: bool = true
): seq[byte] {.raises: [], gcsafe.} =
  var m = msg
  m.connection = m.connection.hide(hideConnectionStatus)
  Protobuf.encode(m)

proc encode*(
    msg: Message, hideConnectionStatus: bool = true
): seq[byte] {.raises: [], gcsafe.} =
  var m = msg
  if hideConnectionStatus:
    for p in m.closerPeers.mitems:
      p.connection = p.connection.hide(hideConnectionStatus)
    for p in m.providerPeers.mitems:
      p.connection = p.connection.hide(hideConnectionStatus)

  let buffer = Protobuf.encode(m)
  trackEncodeBytes(buffer.len, Message, "kademlia")
  buffer

proc toBytes*(ticket: Ticket): seq[byte] {.raises: [], gcsafe.} =
  ## Returns the canonical byte representation of a Ticket used for signing.
  ## Covers: advertisement || tInit || tMod || tWaitFor [|| count || (len || id)*]
  let ad = ticket.advertisement.get(@[])
  var buf = newSeqOfCap[byte](ad.len + 8 + 8 + 4)
  buf.add(ad)
  buf.add(@(toBytesBE(ticket.tInit.get(0).uint64)))
  buf.add(@(toBytesBE(ticket.tMod.get(0).uint64)))
  buf.add(@(toBytesBE(ticket.tWaitFor.get(ZeroDuration).seconds.uint32)))
  if ticket.serviceIds.len > 0:
    buf.add(@(toBytesBE(ticket.serviceIds.len.uint32)))
    for id in ticket.serviceIds:
      buf.add(@(toBytesBE(id.len.uint32)))
      buf.add(id)
  buf

proc sign*(
    ticket: var Ticket, privateKey: PrivateKey
): Result[void, CryptoError] {.raises: [], gcsafe.} =
  ## Sign the ticket with the given private key.
  let sig = ?privateKey.sign(ticket.toBytes())
  ticket.signature = Opt.some(sig.getBytes())
  ok()

proc verify*(ticket: Ticket, publicKey: PublicKey): bool {.raises: [], gcsafe.} =
  ## Verify the ticket signature against the given public key.
  if ticket.signature.isNone:
    return false
  var sig: Signature
  if not sig.init(ticket.signature.get()):
    return false
  sig.verify(ticket.toBytes(), publicKey)
