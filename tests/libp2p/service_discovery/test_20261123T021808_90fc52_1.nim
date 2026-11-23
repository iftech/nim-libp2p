# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021808-90fc52/1 (canonical F-e89a894e).
#
# Spec, "Distributing ads across registrars":
#   If the `status` is `Rejected`, the advertiser MUST remove the registrar from
#   the ongoing registrations for that bucket and SHOULD NOT attempt further
#   registrations with this registrar for this advertisement.

import std/sequtils
import chronos, results, sets, tables
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

type RejectingSwitch = ref object of Switch
  ## Every dial reaches a registrar that answers REGISTER with `Rejected`.
  reply: seq[byte]
  dialed: seq[PeerId]
  streams: seq[FaultStream]

proc new(T: typedesc[RejectingSwitch], base: Switch, reply: seq[byte]): T =
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
    self: RejectingSwitch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  self.dialed.add(peerId)
  let stream = FaultStream.new(reply = self.reply)
  self.streams.add(stream)
  stream

proc rejectedReply(): seq[byte] =
  let encoded = Message(
    msgType: Opt.some(MessageType.register),
    register: Opt.some(
      RegisterMessage(
        advertisement: Opt.none(seq[byte]),
        status: Opt.some(RegistrationStatus.Rejected),
        ticket: Opt.none(Ticket),
      )
    ),
  ).encode()
  doAssert encoded.len < 128, "single byte length prefix"
  @[encoded.len.byte] & encoded

proc settle(disco: ServiceDiscovery) {.async.} =
  for task in toSeq(disco.advertiser.running):
    await task.fut.join().wait(5.seconds)

suite "Proof 20261123T021808-90fc52/1 - rejected registrar":
  asyncTest "a registrar that replied Rejected gets no further REGISTER for the same advertisement":
    let disco = setupServiceDiscoveryNode()
    let rejecting = RejectingSwitch.new(disco.switch, rejectedReply())
    disco.switch = rejecting
    defer:
      await disco.stopRegistrations()
      for s in rejecting.streams:
        await s.close()

    let registrar = PeerId.random()
    check disco.rtable.insert(registrar)
    disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]

    let service = makeServiceInfo()
    let serviceId = service.id.hashServiceId()
    check disco.addProvidedService(service).isOk()
    let advertBefore = disco.advertiser.providedAdverts[serviceId].bytes

    # the first attempt runs to its Rejected reply and the task ends
    await disco.settle()
    require rejecting.dialed == @[registrar]
    # MUST remove the registrar from the ongoing registrations: holds
    require toSeq(disco.advertiser.running).allIt(it.fut.finished())

    # two more maintenance rounds, the same advertisement, the same bucket
    await disco.maintainRegistrations()
    await disco.settle()
    await disco.maintainRegistrations()
    await disco.settle()

    # still the same advertisement
    require disco.advertiser.providedAdverts[serviceId].bytes == advertBefore
    # SHOULD NOT attempt further registrations with this registrar
    check rejecting.dialed.countIt(it == registrar) == 1
