# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261123T021808-90fc52/3.
#
# Spec, "Distributing ads across registrars":
#   If the `status` is `Wait`, the advertiser MUST schedule a next registration
#   attempt to the same registrar based on the `ticket.t_wait_for` value
#   included in the response. The Response contains a `ticket`, which MUST be
#   included in the next registration attempt to this registrar.
# Spec, "Base Message Structure" (Ticket):
#   uint32 t_wait_for = 4;   // Remaining wait time in seconds
#
# `t_wait_for` is a plain scalar. An encoder with implicit field presence
# leaves a zero scalar off the wire, so a Wait ticket with `t_wait_for = 0`
# arrives with field 4 absent and reads as 0.

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

type WaitingSwitch = ref object of Switch
  ## Every dial reaches a registrar that answers REGISTER with `Wait`.
  reply: seq[byte]
  dialed: seq[PeerId]
  streams: seq[FaultStream]

proc new(T: typedesc[WaitingSwitch], base: Switch, reply: seq[byte]): T =
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
    self: WaitingSwitch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  self.dialed.add(peerId)
  let stream = FaultStream.new(reply = self.reply)
  self.streams.add(stream)
  stream

proc waitReply(tWaitFor: Opt[Duration]): seq[byte] =
  let encoded = Message(
    msgType: Opt.some(MessageType.register),
    register: Opt.some(
      RegisterMessage(
        advertisement: Opt.none(seq[byte]),
        status: Opt.some(RegistrationStatus.Wait),
        ticket: Opt.some(
          Ticket(
            advertisement: Opt.some(@[1'u8, 2, 3]),
            tInit: Opt.some(1_700_000_000.UnixTimestamp),
            tMod: Opt.some(1_700_000_000.UnixTimestamp),
            tWaitFor: tWaitFor,
            signature: Opt.some(@[9'u8, 9, 9, 9]),
          )
        ),
      )
    ),
  ).encode()
  doAssert encoded.len < 128, "single byte length prefix"
  @[encoded.len.byte] & encoded

proc dialsAfterWait(tWaitFor: Opt[Duration]): Future[(int, bool)] {.async.} =
  ## Number of REGISTER exchanges with the one registrar within three seconds
  ## of the first Wait reply, and whether its task is still running.
  let disco = setupServiceDiscoveryNode()
  let waiting = WaitingSwitch.new(disco.switch, waitReply(tWaitFor))
  disco.switch = waiting
  defer:
    await disco.stopRegistrations()
    for s in waiting.streams:
      await s.close()

  let registrar = PeerId.random()
  doAssert disco.rtable.insert(registrar)
  disco.switch.peerStore[AddressBook][registrar] = @[makeMultiAddress("127.0.0.1")]

  doAssert disco.addProvidedService(makeServiceInfo()).isOk()
  doAssert disco.advertiser.running.len == 1
  let task = toSeq(disco.advertiser.running)[0]

  # MinTicketWait is 1 s: a retry for t_wait_for = 0 is due well inside 3 s
  for _ in 0 ..< 300:
    if waiting.dialed.len >= 2:
      break
    await sleepAsync(10.milliseconds)

  doAssert waiting.dialed.allIt(it == registrar)
  (waiting.dialed.len, not task.fut.finished())

suite "Proof 20261123T021808-90fc52/3 - Wait ticket without t_wait_for on the wire":
  asyncTest "control: a Wait ticket with an explicit t_wait_for = 0 is retried":
    let (dials, running) = await dialsAfterWait(Opt.some(ZeroDuration))
    check:
      dials >= 2
      running

  asyncTest "a Wait ticket whose zero t_wait_for is left off the wire is retried":
    let (dials, running) = await dialsAfterWait(Opt.none(Duration))
    # MUST schedule a next registration attempt to the same registrar
    check:
      dials >= 2
      running
