# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

from std/times import getTime, toUnix
import chronos, results
import
  ../../../../libp2p/[
    extended_peer_record,
    multiaddress,
    protocols/kademlia/put,
    protocols/service_discovery/advertiser,
    protocols/service_discovery/connection,
    protocols/service_discovery/types,
    stream/connection,
    switch,
  ]
import ../../../../libp2p/protocols/kademlia/protobuf as kad_protobuf
import ../../../tools/[lifecycle, stall_server, unittest]
import ../utils

type
  PendingWriteStream = ref object of Stream
    writeStarted: Future[void].Raising([CancelledError])
    writePending: Future[void].Raising([CancelledError, LPStreamError])
    reads: int

  RpcSwitch = ref object of Switch
    stream: Stream

method dial(
    self: RpcSwitch,
    peerId: PeerId,
    addrs: seq[MultiAddress],
    protos: seq[string],
    forceDial = false,
): Future[Stream] {.async: (raises: [DialFailedError, CancelledError]).} =
  return self.stream

method write(
    stream: PendingWriteStream, msg: sink seq[byte]
) {.async: (raises: [CancelledError, LPStreamError]).} =
  stream.writeStarted.complete()
  await stream.writePending

method readOnce(
    stream: PendingWriteStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  stream.reads.inc()
  raise newLPStreamEOFError()

proc sendRawMessage(
    clientSwitch: Switch, registrarNode: ServiceDiscovery, msgBytes: seq[byte]
): Future[seq[byte]] {.async.} =
  let conn = await clientSwitch.dial(
    registrarNode.switch.peerInfo.peerId, registrarNode.switch.peerInfo.addrs,
    ExtendedServiceDiscoveryCodec,
  )
  defer:
    await conn.close()

  await conn.writeLp(msgBytes)

  return await conn.readLp(ServiceDiscoveryMaxMsgSize)

proc sendMessage(
    clientNode, registrarNode: ServiceDiscovery, msg: kad_protobuf.Message
): Future[kad_protobuf.Message] {.async.} =
  let responseBytes =
    await clientNode.switch.sendRawMessage(registrarNode, msg.encode())
  let response = kad_protobuf.Message.decode(responseBytes)
  check response
  return response.get()

suite "Service Discovery Component - Error Handling":
  teardown:
    checkTrackers()

  asyncTest "cancelling an RPC interrupts dialing":
    let stall = startStallServer()
    let clientNode = setupServiceDiscoveryNode()
    await clientNode.switch.start()
    defer:
      await stall.stop()
      await clientNode.switch.stop()

    let peerId = randomPeerId()
    clientNode.switch.peerStore[AddressBook][peerId] = @[stall.address]
    let pending = clientNode.send(
      peerId,
      kad_protobuf.Message(
        msgType: kad_protobuf.MessageType.getAds, key: makeServiceId()
      ),
    )
    await stall.waitAccepted()
    await pending.cancelAndWait()
    check pending.cancelled()

  asyncTest "cancelling an RPC interrupts writing and resets the stream":
    let clientNode = setupServiceDiscoveryNode()
    let stream = PendingWriteStream(
      writeStarted: Future[void].Raising([CancelledError]).init("RPC write started"),
      writePending:
        Future[void].Raising([CancelledError, LPStreamError]).init("RPC write pending"),
    )
    stream.initStream()
    defer:
      await stream.close()

    clientNode.switch =
      RpcSwitch(peerStore: clientNode.switch.peerStore, stream: stream)
    let peerId = randomPeerId()
    clientNode.switch.peerStore[AddressBook][peerId] = @[makeMultiAddress("127.0.0.1")]
    let pending = clientNode.send(
      peerId,
      kad_protobuf.Message(
        msgType: kad_protobuf.MessageType.getAds, key: makeServiceId()
      ),
    )
    await stream.writeStarted
    await pending.cancelAndWait()
    check:
      pending.cancelled()
      stream.writePending.cancelled()
      stream.wasResetLocally()
      stream.reads == 0

  asyncTest "cancelling an RPC propagates cancellation":
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    let received =
      Future[void].Raising([CancelledError]).init("service discovery request received")
    registrarNode.handler = proc(
        stream: Stream, proto: string
    ) {.async: (raises: [CancelledError]).} =
      try:
        discard await stream.readLp(ServiceDiscoveryMaxMsgSize)
        received.complete()
        discard await stream.readLp(ServiceDiscoveryMaxMsgSize)
      except LPStreamError:
        discard
      finally:
        await noCancel stream.close()

    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)
    let pending = clientNode.send(
      registrarNode.switch.peerInfo.peerId,
      kad_protobuf.Message(
        msgType: kad_protobuf.MessageType.getAds, key: makeServiceId()
      ),
    )
    await received
    await pending.cancelAndWait()
    check pending.cancelled()

  asyncTest "message with unknown MessageType is rejected without a reply":
    let registrarNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode])

    let clientSwitch = createSwitch()
    await clientSwitch.start()
    defer:
      await clientSwitch.stop()

    # msgType = 99 is outside the MessageType enum, so decodeEnum will reject it.
    let invalidMsg = @[8'u8, 99]

    expect AsyncTimeoutError:
      discard
        await clientSwitch.sendRawMessage(registrarNode, invalidMsg).wait(2.seconds)

  asyncTest "REGISTER without register body returns Rejected":
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    let serviceId = makeServiceId()
    let msg = kad_protobuf.Message(
      msgType: kad_protobuf.MessageType.register,
      key: serviceId,
      register: Opt.none(kad_protobuf.RegisterMessage),
    )

    let response = await clientNode.sendMessage(registrarNode, msg)
    check:
      response.register.get().status.get() == kad_protobuf.RegistrationStatus.Rejected
      registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "REGISTER with empty advertisement returns Rejected":
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    let serviceId = makeServiceId()
    let msg = kad_protobuf.Message(
      msgType: kad_protobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kad_protobuf.RegisterMessage(
          advertisement: @[],
          status: Opt.none(kad_protobuf.RegistrationStatus),
          ticket: Opt.none(kad_protobuf.Ticket),
        )
      ),
    )

    let response = await clientNode.sendMessage(registrarNode, msg)
    check:
      response.register.get().status.get() == kad_protobuf.RegistrationStatus.Rejected
      registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "REGISTER with malformed advertisement bytes returns Rejected":
    let registrarNode = setupServiceDiscoveryNode()
    let advertiserNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, advertiserNode])
    await connect(registrarNode, advertiserNode)

    let serviceId = makeServiceId()
    let adBytes = @[1'u8, 2, 3, 4]

    let regResp = await advertiserNode.sendRegister(
      registrarNode.switch.peerInfo.peerId, serviceId, adBytes
    )
    require regResp.isOk()
    check:
      regResp.get().status == kad_protobuf.RegistrationStatus.Rejected
      registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "REGISTER with advertisement for another service returns Rejected":
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    let serviceId = "service".hashServiceId()
    let adBytes = makeAdvertisement(
        "other-service", clientNode.switch.peerInfo.privateKey
      )
      .encode()
      .get()
    let msg = kad_protobuf.Message(
      msgType: kad_protobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kad_protobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kad_protobuf.RegistrationStatus),
          ticket: Opt.none(kad_protobuf.Ticket),
        )
      ),
    )

    let response = await clientNode.sendMessage(registrarNode, msg)
    check:
      response.register.get().status.get() == kad_protobuf.RegistrationStatus.Rejected
      registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "oversized message is rejected without a reply":
    let registrarNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode])

    let clientSwitch = createSwitch()
    await clientSwitch.start()
    defer:
      await clientSwitch.stop()

    let oversizedMsg = newSeq[byte](ServiceDiscoveryMaxMsgSize + 1)

    expect LPStreamError:
      discard await clientSwitch.sendRawMessage(registrarNode, oversizedMsg)

  asyncTest "REGISTER with non-32-byte key returns Rejected":
    # Spec calls for rejection on bad key length.
    # The handler rejects the key on its length, before seating the sender.
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    let adBytes =
      makeAdvertisement("service", clientNode.switch.peerInfo.privateKey).encode().get()

    for keyLen in [0, 31, 33, 64]:
      let key = newSeq[byte](keyLen)

      let msg = kad_protobuf.Message(
        msgType: kad_protobuf.MessageType.register,
        key: Key.fromBytes(key),
        register: Opt.some(
          kad_protobuf.RegisterMessage(
            advertisement: adBytes,
            status: Opt.none(kad_protobuf.RegistrationStatus),
            ticket: Opt.none(kad_protobuf.Ticket),
          )
        ),
      )

      let response = await clientNode.sendMessage(registrarNode, msg)
      check:
        response.register.get().status.get() == kad_protobuf.RegistrationStatus.Rejected
        registrarNode.countAdsInCache(Key.fromBytes(key)) == 0

  asyncTest "REGISTER with ticket that has mismatched advertisement returns Rejected":
    # A ticket whose embedded advertisement does not match the registration's
    # advertisement must be rejected (prevents tInit poisoning via unsigned tickets).
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    let serviceId = "service".hashServiceId()
    let adBytes =
      makeAdvertisement("service", clientNode.switch.peerInfo.privateKey).encode().get()
    let otherAdBytes =
      makeAdvertisement("other", clientNode.switch.peerInfo.privateKey).encode().get()

    var badTicket = kad_protobuf.Ticket(
      advertisement: otherAdBytes,
      tInit: getTime().toUnix() - 10,
      tMod: getTime().toUnix() - 5,
      tWaitFor: 1.secs,
      signature: Opt.none(seq[byte]),
    )
    check badTicket.sign(registrarNode.switch.peerInfo.privateKey)

    let msg = kad_protobuf.Message(
      msgType: kad_protobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kad_protobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kad_protobuf.RegistrationStatus),
          ticket: Opt.some(badTicket),
        )
      ),
    )

    let response = await clientNode.sendMessage(registrarNode, msg)
    check:
      response.register.get().status.get() == kad_protobuf.RegistrationStatus.Rejected
      registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "REGISTER with ticket that has invalid signature returns Rejected":
    # A ticket that fails signature verification (wrong key or tampered) must
    # produce Rejected; its time values must never be trusted or copied.
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    let serviceId = "service".hashServiceId()
    let adBytes =
      makeAdvertisement("service", clientNode.switch.peerInfo.privateKey).encode().get()

    # Sign with a different node's key
    let otherNode = setupServiceDiscoveryNode()
    var badTicket = kad_protobuf.Ticket(
      advertisement: adBytes,
      tInit: getTime().toUnix() - 1000,
      tMod: getTime().toUnix() - 500,
      tWaitFor: 10.secs,
      signature: Opt.none(seq[byte]),
    )
    check badTicket.sign(otherNode.switch.peerInfo.privateKey)

    let msg = kad_protobuf.Message(
      msgType: kad_protobuf.MessageType.register,
      key: serviceId,
      register: Opt.some(
        kad_protobuf.RegisterMessage(
          advertisement: adBytes,
          status: Opt.none(kad_protobuf.RegistrationStatus),
          ticket: Opt.some(badTicket),
        )
      ),
    )

    let response = await clientNode.sendMessage(registrarNode, msg)
    check:
      response.register.get().status.get() == kad_protobuf.RegistrationStatus.Rejected
      registrarNode.countAdsInCache(serviceId) == 0

  asyncTest "GET_ADS with non-32-byte key returns empty response":
    # Spec calls for rejection on bad key length.
    # The handler returns an empty response before the cache lookup.
    let registrarNode = setupServiceDiscoveryNode()
    let clientNode = setupServiceDiscoveryNode()
    startAndDeferStop(@[registrarNode, clientNode])
    await connect(registrarNode, clientNode)

    for keyLen in [0, 31, 33, 64]:
      let key = newSeq[byte](keyLen)

      let msg = kad_protobuf.Message(
        msgType: kad_protobuf.MessageType.getAds, key: Key.fromBytes(key)
      )

      let response = await clientNode.sendMessage(registrarNode, msg)
      check:
        response.msgType == kad_protobuf.MessageType.getAds
        response.getAds.isSome()
        response.getAds.get().advertisements.len == 0

  asyncTest "PUT_VALUE signed by another peer is rejected with a default validator config":
    let kadConfig = KadDHTConfig.new(timeout = 1.seconds, disableBootstrapping = true)
    let storeNode =
      setupServiceDiscoveryNode(xprPublishing = false, kadConfig = kadConfig)
    let clientNode =
      setupServiceDiscoveryNode(xprPublishing = false, kadConfig = kadConfig)
    startAndDeferStop(@[storeNode, clientNode])
    await connect(storeNode, clientNode)

    let storePeerId = storeNode.switch.peerInfo.peerId
    let value = Value.fromBytes(makeAdvertisement().encode())
    discard await clientNode.dispatchPutVal(storePeerId, storePeerId.toKey(), value)

    check storeNode.dataTable.get(storePeerId.toKey()).isNone()
