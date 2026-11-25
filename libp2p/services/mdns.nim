# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/[strutils, tables, net, sequtils]
import chronos, chronicles
import ../[switch, peerinfo, peerstore, multicodec, address_manager, results, wire]
import ../peeraddrpolicy
import ../logging
import ../nameresolving/dnsmessage
import ../crypto/rng
import ./mdns/[network, ratelimit]

export network.MdnsPort

const
  MdnsServiceName* = "_p2p._udp"
  MdnsDefaultQueryInterval* = 60.seconds
  MdnsMinQueryInterval* = 60.seconds
  MdnsMaxQueryInterval* = (int64(high(uint32)) div 2).seconds
  MdnsResponseInterval* = 1.seconds
  MdnsDefaultMaxPendingCallbacks* = 10
  RecordTtl = 120'u32

type
  MdnsPeer* = object
    peerId*: PeerId
    addrs*: seq[MultiAddress]

  MdnsPeerFound* = proc(
    switch: Switch, peer: MdnsPeer
  ): Future[void].Raising([CancelledError]) {.gcsafe, raises: [].}

  MdnsService* = ref object of Service
    onPeerFound: MdnsPeerFound
    callbacks: seq[Future[void].Raising([CancelledError])]
    maxPendingCallbacks: int
    callbackLimitWarnings: LogRateLimit
    stopping: bool
    serviceName: DnsName
    instance: string
    interval: Duration
    network: MdnsNetwork
    loop: Future[void].Raising([CancelledError])
    owner: Switch
    advertisement: DnsMessage
    advertisementBytes: seq[byte]
    multicastLimits: InterfaceLimits

logScope:
  topics = "libp2p mdns"

func sameName(a, b: DnsName): bool =
  if a.len != b.len:
    return false
  for i in 0 ..< a.len:
    if cmpIgnoreCase(a[i], b[i]) != 0:
      return false
  true

proc new*(
    T: typedesc[MdnsService],
    onPeerFound: MdnsPeerFound = nil,
    serviceName = MdnsServiceName,
    queryInterval = MdnsDefaultQueryInterval,
    networkInterfaceProvider: NetworkInterfaceProvider = getAddresses,
    maxPendingCallbacks: int = MdnsDefaultMaxPendingCallbacks,
): T =
  ## A custom service name isolates applications on the same LAN.
  ## 
  ## Discovered addresses are added to the switch's peerstore with low
  ## confidence before `onPeerFound` runs. The callback controls whether to
  ## dial; a nil callback stores discoveries without connecting. It may be
  ## called repeatedly for the same peer. 
  ##
  ## An async callback can dial using the supplied switch. Its future is owned
  ## by the service and cancelled when it stops; handle dial errors in it.
  ## At most `maxPendingCallbacks` callbacks can be pending; further discoveries
  ## are stored in the peerstore but their callbacks are skipped.
  ## Detached work started by the callback remains the application's responsibility.
  ## Do not await stopping the switch or this service from that callback.
  ## 
  ## The query interval must be within MdnsMinQueryInterval and
  ## MdnsMaxQueryInterval, inclusive.
  doAssert queryInterval >= MdnsMinQueryInterval and
    queryInterval <= MdnsMaxQueryInterval, "mDNS query interval is out of range"
  doAssert maxPendingCallbacks >= 0, "mDNS callback limit cannot be negative"
  let name =
    try:
      let name = serviceName.toDnsName() & @["local"]
      discard
        encodeMessage(DnsMessage(questions: @[DnsQuestion(name: name, kind: PTR)]))
      name
    except ValueError as exc:
      raiseAssert "Invalid mDNS service name: " & exc.msg

  let limits = newInterfaceLimits()
  proc interfacesChanged(indices: seq[uint32]) {.gcsafe, raises: [].} =
    limits.prune(indices)

  return T(
    onPeerFound: onPeerFound,
    serviceName: name,
    interval: queryInterval,
    maxPendingCallbacks: maxPendingCallbacks,
    network:
      MdnsNetwork.new(networkInterfaceProvider, onInterfacesChanged = interfacesChanged),
    multicastLimits: limits,
  )

proc suitable(address: MultiAddress): bool =
  let text = $address
  if not (text.startsWith("/ip4/") or text.startsWith("/ip6/")) or
      not isDialableMA(address):
    return false
  const excluded = [
    multiCodec("p2p-circuit"),
    multiCodec("ws"),
    multiCodec("wss"),
    multiCodec("p2p-webrtc-direct"),
    multiCodec("webtransport"),
  ]
  for protocol in excluded:
    if address.contains(protocol).get(false):
      return false
  let transportAddress = initTAddress(address).valueOr:
    return false
  let host =
    if transportAddress.isV4Mapped():
      transportAddress.toIPv4()
    else:
      transportAddress

  return
    host.port != Port(0) and not host.isLoopback() and not host.isMulticast() and
    not host.isUnspecified()

proc announcement*(
    service: MdnsService, peer: PeerInfo, instance: string, ttl: uint32
): DnsMessage =
  ## Construct a DNS-SD advertisement. Exposed for packet-level interoperability tests.
  let
    instanceName = @[instance] & service.serviceName
    hostName = @[instance, "local"]
  var message = DnsMessage(response: true)
  var strings: seq[string]
  var ips: seq[string]
  var textBytes = 0
  var srvPort: uint16
  for address in service.network.expandAddresses(peer.listenAddrs):
    if not suitable(address):
      continue
    let text = "dnsaddr=" & $address & "/p2p/" & $peer.peerId
    # Leave room for the DNS-SD names and records in a normal LAN datagram.
    if text.len > 255 or text in strings or textBytes + text.len > 900:
      continue
    let transportAddress = initTAddress(address).valueOr:
      continue
    if strings.len == 0:
      srvPort = uint16(transportAddress.port)
    strings.add(text)
    textBytes += text.len + 1
    address.getIp().ifValue(ip):
      if $ip notin ips:
        ips.add($ip)
        message.additionals.add(
          DnsRecord(
            name: hostName,
            kind: (if ip.family == IpAddressFamily.IPv4: A else: AAAA),
            ttl: ttl,
            cacheFlush: true,
            address: $ip,
          )
        )
  if strings.len == 0:
    return message
  message.answers =
    @[DnsRecord(name: service.serviceName, kind: PTR, target: instanceName, ttl: ttl)]
  message.additionals.add(
    DnsRecord(
      name: instanceName,
      kind: SRV,
      target: hostName,
      port: srvPort,
      ttl: ttl,
      cacheFlush: true,
    )
  )
  message.additionals.add(
    DnsRecord(
      name: instanceName, kind: TXT, strings: strings, ttl: ttl, cacheFlush: true
    )
  )
  return message

proc announcement*(service: MdnsService, peer: PeerInfo, instance: string): DnsMessage =
  # Round fractional seconds up so records remain valid for two full intervals.
  let nanos = service.interval.nanoseconds
  let seconds = nanos div 1_000_000_000 + int64(nanos mod 1_000_000_000 != 0)
  service.announcement(peer, instance, max(RecordTtl, uint32(seconds * 2)))

proc peers*(service: MdnsService, message: DnsMessage, self: PeerId): seq[MdnsPeer] =
  ## Decode this service's live TXT records and group IP transport addresses by
  ## peer ID. mDNS is unauthenticated.
  if not message.response:
    return @[]
  var grouped: Table[PeerId, seq[MultiAddress]]
  proc collect(records: openArray[DnsRecord]) =
    for record in records:
      if record.kind != TXT or record.ttl == 0 or
          record.name.len != service.serviceName.len + 1 or
          not sameName(record.name[1 .. ^1], service.serviceName):
        continue
      for text in record.strings:
        if not text.startsWith("dnsaddr="):
          continue
        let address = MultiAddress.init(text[8 .. ^1]).valueOr:
          continue
        let (id, base) = parseFullAddress(address).valueOr:
          continue
        if id == self:
          continue
        if base.contains(multiCodec("p2p")).get(false) or not suitable(base):
          continue
        let addresses = addr grouped.mgetOrPut(id, @[])
        if base notin addresses[]:
          addresses[].add(base)

  collect(message.answers)
  collect(message.additionals)
  var found: seq[MdnsPeer]
  for id, addresses in grouped.pairs:
    found.add(MdnsPeer(peerId: id, addrs: addresses))
  return found

proc multicast(
    service: MdnsService, message: DnsMessage
) {.async: (raises: [CancelledError]).} =
  try:
    discard await service.network.multicast(encodeMessage(message))
  except ValueError:
    debug "mDNS announcement encoding failed", err = getCurrentExceptionMsg()

proc advertise(service: MdnsService) {.async: (raises: [CancelledError]).} =
  service.advertisement = service.announcement(service.owner.peerInfo, service.instance)
  try:
    service.advertisementBytes = encodeMessage(service.advertisement)
  except ValueError:
    debug "mDNS announcement encoding failed", err = getCurrentExceptionMsg()
    service.advertisement = default(DnsMessage)
    service.advertisementBytes.setLen(0)
  if service.advertisement.answers.len > 0:
    discard await service.network.multicast(service.advertisementBytes)

proc maintain(service: MdnsService) {.async: (raises: [CancelledError]).} =
  var firstIteration = true
  while true:
    await service.advertise()
    await service.multicast(
      DnsMessage(
        questions: @[DnsQuestion(name: service.serviceName, kind: PTR)],
        answers: service.advertisement.answers,
      )
    )
    # Transports can still be binding during the first iteration. Retry locally
    # without sending additional queries until an advertisement is available.
    var remaining = service.interval
    while firstIteration and service.advertisement.answers.len == 0 and
        remaining > 0.seconds:
      let delay = min(1.seconds, remaining)
      await sleepAsync(delay)
      remaining = remaining - delay
      await service.advertise()
    firstIteration = false
    if remaining > 0.seconds:
      await sleepAsync(remaining)

proc storeDiscovery(peerStore: PeerStore, peer: MdnsPeer) =
  let addrs =
    peerStore.addressPolicy.dialableAddrs(peer.addrs, peerStore.allowUndialableAddrs)
  peerStore[AddressBook].extend(peer.peerId, addrs, AddressConfidence.Low)

proc notifyPeerFound(service: MdnsService, switch: Switch, peer: MdnsPeer) =
  if service.onPeerFound.isNil:
    return

  service.callbacks.keepItIf(not it.finished())
  if service.callbacks.len < service.maxPendingCallbacks:
    service.callbacks.add(service.onPeerFound(switch, peer))
  elif service.callbackLimitWarnings.allowLog():
    warn "mDNS discovery callback skipped: pending callback limit reached",
      peerId = peer.peerId, limit = service.maxPendingCallbacks

proc handleResponse(service: MdnsService, switch: Switch, message: DnsMessage) =
  for peer in service.peers(message, switch.peerInfo.peerId):
    switch.peerStore.storeDiscovery(peer)
    service.notifyPeerFound(switch, peer)

proc isOwnQuery(service: MdnsService, message: DnsMessage): bool =
  # Our periodic query carries our own PTR as a known answer. This also
  # distinguishes it from queries sent by other services on this host.
  for record in message.answers:
    if record.kind == PTR and sameName(record.name, service.serviceName) and
        sameName(record.target, @[service.instance] & service.serviceName):
      return true
  false

proc findQuestion(service: MdnsService, message: DnsMessage): int =
  for i, question in message.questions:
    if sameName(question.name, service.serviceName) or
        sameName(question.name, @[service.instance] & service.serviceName) or
        sameName(question.name, @[service.instance, "local"]):
      return i
  -1

proc replyUnicast(
    service: MdnsService, message: DnsMessage, context: MdnsReplyContext
) {.async: (raises: []).} =
  var response = service.advertisement
  for record in response.answers.mitems:
    record.cacheFlush = false
  for record in response.additionals.mitems:
    record.cacheFlush = false
  if context.isLegacyQuery:
    response.id = message.id
    response.questions = message.questions
  let packet =
    try:
      encodeMessage(response)
    except ValueError:
      debug "mDNS datagram ignored", err = getCurrentExceptionMsg()
      return
  # Chronos requires a non-cancellable datagram callback.
  discard await noCancel service.network.reply(packet, context, true)

proc handleQuery(
    service: MdnsService, message: DnsMessage, context: MdnsReplyContext
) {.async: (raises: []).} =
  if not context.isLegacyQuery and service.isOwnQuery(message):
    return

  let matched = service.findQuestion(message)
  if matched < 0 or service.advertisement.answers.len == 0:
    return

  if message.questions[matched].unicastResponse or context.isLegacyQuery:
    await service.replyUnicast(message, context)
    return

  let ipv6 = context.isIpv6
  let index = context.interfaceIndex
  let limits = service.multicastLimits.get(index)
  if not limits[].acquire(ipv6, Moment.now()):
    return

  var sent = false
  try:
    # Chronos requires a non-cancellable datagram callback.
    sent =
      await noCancel service.network.reply(service.advertisementBytes, context, false)
  finally:
    limits[].finish(ipv6, sent, Moment.now(), MdnsResponseInterval)

proc received(
    service: MdnsService, switch: Switch, datagram: seq[byte], context: MdnsReplyContext
) {.async: (raises: []).} =
  if service.stopping or switch.isStopping or not service.network.isLocalSource(context):
    return

  let message =
    try:
      parseMessage(datagram)
    except ValueError:
      debug "mDNS datagram ignored", err = getCurrentExceptionMsg()
      return

  if message.response:
    service.handleResponse(switch, message)
  else:
    await service.handleQuery(message, context)

proc makeInstanceName(rng: Rng): string =
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
  var name = newString(rng.rand(32, 63))
  for c in name.mitems:
    c = alphabet[rng.rand(0, alphabet.high)]
  name

proc tryStart*(
    service: MdnsService, switch: Switch
): Future[LPResult[void]] {.async: (raises: [CancelledError]).} =
  service.stopping = false
  if service.network.isOpen:
    return ok()
  service.owner = switch
  # Random instance labels avoid publishing the peer ID as a DNS host name.
  service.instance = makeInstanceName(switch.rng)
  proc onPacket(
      packet: seq[byte], context: MdnsReplyContext
  ): Future[void].Raising([]) =
    service.received(switch, packet, context)

  let opened = await service.network.open(onPacket)
  if opened.isErr:
    service.owner = nil
    return opened
  service.loop = service.maintain()
  info "mDNS discovery started", instance = service.instance
  return ok()

method start*(
    service: MdnsService, switch: Switch
) {.async: (raises: [CancelledError, LPError]).} =
  let started = await service.tryStart(switch)
  if started.isErr:
    warn "mDNS discovery unavailable", err = started.error

method stop*(
    service: MdnsService, switch: Switch
) {.async: (raises: [CancelledError]).} =
  service.stopping = true
  if not service.network.isOpen:
    return
  await noCancel service.callbacks.cancelAndWait()
  service.callbacks.setLen(0)
  if not service.loop.isNil:
    await noCancel service.loop.cancelAndWait()
    service.loop = nil
  let goodbye = service.announcement(switch.peerInfo, service.instance, 0)
  if goodbye.answers.len > 0:
    await noCancel service.multicast(goodbye)
  await noCancel service.network.close()
  service.owner = nil
  service.advertisement = default(DnsMessage)
  service.advertisementBytes.setLen(0)
  service.multicastLimits.clear()
  info "mDNS discovery stopped"
