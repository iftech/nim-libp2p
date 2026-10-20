# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import net, chronos, sequtils
import stew/base36
import
  ../../../libp2p/[
    autotls/utils,
    autotls/acme/api,
    autotls/acme/client,
    cid,
    crypto/crypto,
    multicodec,
    peerid,
  ]
import ../../tools/[unittest, resolver, crypto]
import ./rfc_vectors

suite "AutoTLS DNS records":
  const
    BaseDomain = api.Domain("k51qzi5uqu5dhkzk3z.libp2p.direct")
    AcmeChallengeName = "_acme-challenge.k51qzi5uqu5dhkzk3z.libp2p.direct"
    Ip4Name = "100-10-10-3.k51qzi5uqu5dhkzk3z.libp2p.direct"
    KeyAuth = KeyAuthorization("expected-key-authorization")
    OtherKeyAuth = KeyAuthorization("another-key-authorization")

  let ipAddress = parseIpAddress("100.10.10.3")

  var resolver {.threadvar.}: StubNameResolver

  asyncTeardown:
    checkTrackers()

  asyncSetup:
    resolver =
      StubNameResolver.new(txtRecords = @[KeyAuth], ipAddresses = @["100.10.10.3"])

  asyncTest "matching TXT and a published A record report the records as set":
    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 0, retryTime = 0.seconds
    )
    check dnsSet == true

  asyncTest "a TXT record holding another key authorization is not accepted":
    resolver.txtScript = @[@[OtherKeyAuth]]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 0, retryTime = 0.seconds
    )
    check dnsSet == false

  asyncTest "a matching TXT record without an A record is not accepted":
    resolver.ipAddresses = @[]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 0, retryTime = 0.seconds
    )
    check dnsSet == false

  asyncTest "an absent TXT record is not accepted":
    resolver.txtScript = @[@[]]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 0, retryTime = 0.seconds
    )
    check dnsSet == false

  asyncTest "the challenge name and the dashed-IP name are the names queried":
    discard await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 0, retryTime = 0.seconds
    )

    check:
      resolver.txtQueries == @[AcmeChallengeName]
      resolver.ipQueries == @[Ip4Name]

  asyncTest "stops at the first attempt that sees both records":
    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 10, retryTime = 0.seconds
    )

    check:
      dnsSet == true
      resolver.txtQueries.len == 1
      resolver.ipQueries.len == 1

  asyncTest "a TXT record that only appears on a later attempt is accepted":
    resolver.txtScript = @[@[], @[KeyAuth]]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 10, retryTime = 0.seconds
    )

    check:
      dnsSet == true
      resolver.txtQueries.len == 2

  asyncTest "an A record resolved on an earlier attempt is not carried over":
    resolver.txtScript = @[@[], @[KeyAuth]]
    resolver.ipScript =
      @[StubNameResolverIpOutcome.Resolve, StubNameResolverIpOutcome.RaiseAddressError]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 10, retryTime = 0.seconds
    )
    check dnsSet == false

  asyncTest "retries until both records are seen on the same attempt":
    # Only the third attempt sees the two together.
    resolver.txtScript = @[@[KeyAuth], @[], @[KeyAuth]]
    resolver.ipScript = @[
      StubNameResolverIpOutcome.RaiseAddressError, StubNameResolverIpOutcome.Resolve,
      StubNameResolverIpOutcome.Resolve,
    ]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 10, retryTime = 0.seconds
    )

    check:
      dnsSet == true
      resolver.txtQueries.len == 3
      resolver.ipQueries.len == 3

  asyncTest "waits retryTime before each retry":
    resolver.txtScript = @[@[]]

    let start = Moment.now()
    let dnsSet = await checkDNSRecords(
      resolver,
      ipAddress,
      BaseDomain,
      KeyAuth,
      retries = 4,
      retryTime = 200.milliseconds,
    )
    let elapsed = Moment.now() - start

    # retries = 4 is 5 total attempts with a delay before each retry, so 4 x 200ms.
    check:
      dnsSet == false
      elapsed >= 700.milliseconds

  asyncTest "an A record that never resolves is not accepted":
    resolver.ipScript = @[StubNameResolverIpOutcome.RaiseAddressError]

    let dnsSet = await checkDNSRecords(
      resolver, ipAddress, BaseDomain, KeyAuth, retries = 3, retryTime = 0.seconds
    )
    check dnsSet == false

  asyncTest "cancellation while resolving the A record propagates":
    resolver.ipScript = @[StubNameResolverIpOutcome.RaiseCancelled]

    expect(CancelledError):
      discard await checkDNSRecords(
        resolver, ipAddress, BaseDomain, KeyAuth, retries = 3, retryTime = 0.seconds
      )

  asyncTest "an IPv6 address is queried with its colons dashed":
    discard await checkDNSRecords(
      resolver,
      parseIpAddress("2001:db8::1"),
      BaseDomain,
      KeyAuth,
      retries = 0,
      retryTime = 0.seconds,
    )

    check resolver.ipQueries == @["2001-db8--1.k51qzi5uqu5dhkzk3z.libp2p.direct"]

  asyncTest "a leading or trailing colon becomes a 0 in the queried name":
    # a seq variable, not an array literal: await over an array literal segfaults on Nim devel refc
    let ips = @["::1", "2001:db8::", "::"]
    for ip in ips:
      discard await checkDNSRecords(
        resolver,
        parseIpAddress(ip),
        BaseDomain,
        KeyAuth,
        retries = 0,
        retryTime = 0.seconds,
      )

    check resolver.ipQueries ==
      @["0--1." & BaseDomain, "2001-db8--0." & BaseDomain, "0--0." & BaseDomain]

suite "AutoTLS peer ID label":
  # RSA and ECDSA public keys exceed maxInlineKeyLength, so their PeerIds carry a
  # sha2-256 multihash rather than an inlined identity multihash.
  let peerIds = @[
    PeerId.init(PrivateKey.random(PKScheme.Ed25519, rng()).get()).get(),
    PeerId.init(PrivateKey.random(PKScheme.Secp256k1, rng()).get()).get(),
    PeerId.init(PrivateKey.random(PKScheme.ECDSA, rng()).get()).get(),
    PeerId.init(PrivateKey.init(rfc7517Key())).get(),
  ]

  test "the label is the peer ID as a CIDv1 libp2p-key CID":
    for peerId in peerIds:
      let cid = Cid.init(Base36.decode(encodePeerId(peerId).get())).get()

      check:
        cid.version == CIDv1
        cid.contentType.get == multiCodec("libp2p-key")
        cid.mhash.get.data.buffer == peerId.data

  test "every key type gives a legal DNS label":
    for peerId in peerIds:
      let label = encodePeerId(peerId).get()

      check:
        # RFC 1035 caps a DNS label at 63 octets.
        label.len <= 63
        label.allIt(it in {'0' .. '9', 'a' .. 'z'})

  test "a peer ID that is not a multihash gives an error":
    check encodePeerId(PeerId(data: @[byte 0xff])).isErr()

suite "AutoTLS PEM":
  test "the body wraps at 64 columns between the banners":
    check pemEncode(toSeq(0 .. 48).mapIt(byte(it)), "PRIVATE KEY") ==
      "-----BEGIN PRIVATE KEY-----\n" &
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n" & "MA==\n" &
      "-----END PRIVATE KEY-----\n"

  test "a body that fills the last column adds no blank line":
    check pemEncode(toSeq(0 .. 47).mapIt(byte(it)), "PRIVATE KEY") ==
      "-----BEGIN PRIVATE KEY-----\n" &
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n" &
      "-----END PRIVATE KEY-----\n"

  test "an empty key gives an empty body":
    check pemEncode(newSeq[byte](), "PRIVATE KEY") ==
      "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"
