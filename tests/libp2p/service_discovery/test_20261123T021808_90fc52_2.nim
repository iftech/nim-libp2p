# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021808-90fc52/2.
#
# Spec, "System Parameters":
#   K_register | 3 | Max number of active (i.e. unexpired) registrations +
#   ongoing registration attempts per bucket.
# Spec, "Distributing ads across registrars":
#   If the `status` is `Confirmed`, the registration is maintained in the
#   registrar's `ad_cache` for `E` seconds. After `E` seconds the advertiser
#   MUST remove the registration from the ongoing registrations for that bucket.
#   Ongoing registrations include those registrars at which the advertiser has
#   an active registration or for which there is an ongoing registration attempt.

import std/sequtils
import chronos, results, sets
import
  ../../../libp2p/[
    multiaddress,
    peerid,
    peerstore,
    protocols/kademlia,
    protocols/service_discovery,
    protocols/service_discovery/advertiser,
    stream/connection,
    switch,
  ]
import ../../tools/[fault_stream, unittest]
import ./utils

const KRegister = 1

type ConfirmingSwitch = ref object of Switch
  ## Every dial reaches a registrar that answers REGISTER with `Confirmed`.
  reply: seq[byte]
  dialed: seq[PeerId]
  streams: seq[FaultStream]

proc new(T: typedesc[ConfirmingSwitch], base: Switch, reply: seq[byte]): T =
  T(
    peerInfo: base.peerInfo,
    peerStore: base.peerStore,
    connManager: base.connManager,
    transports: base.transports,
    muxedUpgrade: base.muxedUpgrade,
    ms: base.ms,
    dialer: base.dialer,
    nameResolver: base.nameResolver,
    addressManager: base.addressManager,
    services: base.services,
    rng: base.rng,
    reply: reply,
  )

method dial*(
    self: ConfirmingSwitch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  self.dialed.add(peerId)
  let stream = FaultStream.new(reply = self.reply)
  self.streams.add(stream)
  stream

proc confirmedReply(): seq[byte] =
  let encoded = Message(
    msgType: Opt.some(MessageType.register),
    register: Opt.some(
      RegisterMessage(
        advertisement: Opt.none(seq[byte]),
        status: Opt.some(RegistrationStatus.Confirmed),
        ticket: Opt.none(Ticket),
      )
    ),
  ).encode()
  doAssert encoded.len < 128, "single byte length prefix"
  @[encoded.len.byte] & encoded

suite "Proof 20261123T021808-90fc52/2 - confirmed registration lifetime":
  asyncTest "a bucket holding K_register unexpired registrations gets no further REGISTER":
    # E stays at its default of 900 s, far longer than this test
    let disco = setupServiceDiscoveryNode(
      discoConfig = ServiceDiscoveryConfig.new(kRegister = KRegister)
    )
    let confirming = ConfirmingSwitch.new(disco.switch, confirmedReply())
    disco.switch = confirming
    defer:
      await disco.stopRegistrations()
      for s in confirming.streams:
        await s.close()

    let registrar = PeerId.random()
    require disco.rtable.insert(registrar)
    disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]

    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    require disco.addProvidedService(service).isOk()
    require disco.advertiser.running.len == 1
    let confirmed = toSeq(disco.advertiser.running)[0]

    # the registrar answers Confirmed: the reply is read and the stream closed
    for _ in 0 ..< 200:
      if confirming.streams.len == 1 and confirming.streams[0].closed():
        break
      await sleepAsync(10.milliseconds)
    require confirming.dialed == @[registrar]
    require confirming.streams[0].closed()
    # the registration is active (unexpired) and tracked as ongoing
    require not confirmed.fut.finished()

    # The registrar leaves the advertise table and another peer of the same
    # bucket joins it, as a full-bucket replacement or an eviction does. The
    # advertisement stays in the registrar's ad_cache until E all the same.
    let table = disco.rtManager.getTable(serviceId).get()
    var other = PeerId.random()
    while table.bucketIndex(other.toKey()) != confirmed.bucketIdx:
      other = PeerId.random()
    disco.switch.peerStore[AddressBook][other] = @[makeMultiAddress("127.0.0.2")]
    require table.removePeer(registrar, "test eviction")
    require table.insert(other)

    await disco.maintainRegistrations()
    await sleepAsync(50.milliseconds)

    # Max K_register unexpired registrations + ongoing attempts per bucket:
    # both peers are in the same bucket and E has not elapsed for the first.
    check confirming.dialed.deduplicate().len <= KRegister
