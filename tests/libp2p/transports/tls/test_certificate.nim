# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import times, results
import
  ../../../../libp2p/
    [transports/tls/certificate, transports/tls/certificate_ffi, crypto/crypto, peerid]
import ../../../tools/[unittest, crypto]

suite "Certificate roundtrip tests":
  test "generate then parse with DER ecoding":
    let schemes = @[Ed25519, Secp256k1, ECDSA]
    for scheme in schemes:
      let keypair = KeyPair.random(scheme, rng()).tryGet()
      let peerId = PeerId.init(keypair.pubkey).tryGet()

      let certX509 = generateX509(keypair, encodingFormat = EncodingFormat.DER)
      let cert = parse(certX509.certificate)
      check:
        peerId == cert.peerId()
        cert.publicKey().scheme == scheme
        cert.verify(cert.peerId())

  test "verified identity key matches peer id":
    let keypair = KeyPair.random(Ed25519, rng()).tryGet()
    let peerId = PeerId.init(keypair.pubkey).tryGet()
    let otherPeerId = PeerId.random(rng()).tryGet()

    let certX509 = generateX509(keypair, encodingFormat = EncodingFormat.DER)
    let cert = parse(certX509.certificate)
    let identityKey = cert.verifiedIdentityKey()

    check:
      identityKey.isSome
      cert.verify(peerId)
      not cert.verify(otherPeerId)

    if identityKey.isSome:
      let actualPeerId = PeerId.init(identityKey.get()).tryGet()
      check:
        actualPeerId == peerId
        actualPeerId != otherPeerId

  test "generate with invalid validity time":
    let keypair = KeyPair.random(Ed25519, rng()).tryGet()

    # past
    var validFrom = (now() - 3.days).toTime()
    var validTo = (now() - 1.days).toTime()
    var certX509 = generateX509(keypair, validFrom, validTo)
    var cert = parse(certX509.certificate)
    check not cert.verify(cert.peerId())

    # future
    validFrom = (now() + 1.days).toTime()
    validTo = (now() + 3.days).toTime()
    certX509 = generateX509(keypair, validFrom, validTo)
    cert = parse(certX509.certificate)
    check not cert.verify(cert.peerId())

    # twisted from-to
    validFrom = (now() + 3.days).toTime()
    validTo = (now() - 3.days).toTime()
    certX509 = generateX509(keypair, validFrom, validTo)
    cert = parse(certX509.certificate)
    check not cert.verify(cert.peerId())

## Test vectors from https://github.com/libp2p/specs/blob/master/tls/tls.md#test-vectors.
suite "Test vectors":
  test "ECDSA Peer ID":
    let certBytesHex =
      "308201f63082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f2044730450220064ea8124774caf8f50e57f436aa62350ce652418c019df5d98a3ac666c9386a022100aa59d704a931b5f72fb9222cb6cc51f954d04a4e2e5450f8805fe8918f71eaae300a06082a8648ce3d04030203470030440220799395b0b6c1e940a7e4484705f610ab51ed376f19ff9d7c16757cfbf61b8d4302206205c03fbb0f95205c779be86581d3e31c01871ad5d1f3435bcf375cb0e5088a"
    let cert = parse(fromHex(certBytesHex))

    check $cert.peerId() == "QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE"
    check cert.publicKey().scheme == PKScheme.ECDSA
    check cert.verify(cert.peerId())

  test "RSA Peer ID":
    let certBytesHex =
      "308203863082032ba0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea382024f3082024b30820247060a2b0601040183a25a010104820237308202330482012b080012a60230820122300d06092a864886f70d01010105000382010f003082010a0282010100c6423f0fa8757d15b9e9332126339f32395b3f5d16e639b9d030e0507e60e68c973607dad6a2994a5b5f80456de271f21faee9051807e846ade5b396c661eef046e1f8f2279182df845f8962040cf08f6cfadcfde9c4592a0d11b92edab459e9099535db595834c8db762136a164f159bb01a5545a24e0f453df420e6633a9cbc123454b68c11966bc9851993608875e804cfe65604ac60f357b226ba57de0c191039935f7c0c85f1d3de7c2aeb7e6a1520f7201542b949784feb85d53d99f034a55218e6c4fae870cddf7dbb43583cd9eb1bc9e5111c0e7cf62aafef1188711ba205b87c8c95a4ccf154881a49e8b155c795fc1c7621b3b95b01ce4af48a6a7020301000104820100ab0ed7f294e3ec740cb5842ec3d0fc5a0458e00b60bb6c9ee0da8626d0cc1a50cbeb4cc1d61e9a487b327627600b7474e29f5d6c2f66c24966b3524c87e9edc42a3461fb183ce92127b160cf1be599f04a68a22cb463c266181b87e265d418ebff1bcf255bd5e5c1db783ff5909db37c183af5532563c847f104b540855727af53c0412d181f0893e150d5a28e0e9562ff301ff1278264a724152abf0e79537d52cddc205a0f5205490f18218b28ec8051b887033572ace045c24bfe3c0c72d18171148fac43f8b3a494a4ba90d27e554f64c17dc8513597078409e813791d79ee225bf6a2d8dc0893304f74b949230dad4ee4e1cfa62fa1c9ff0439bcda79c3300a06082a8648ce3d0403020349003046022100b3f1961bb314db110f9aae02e1ca0db9cbfda089635a6b99f257661db41a913d022100c04cad46601322e10cf092360a5a290148dfca40fdf7050c977863c57b407144"
    let cert = parse(fromHex(certBytesHex))

    check $cert.peerId() == "QmXsmtNnfvVdbDaPK415Zw3sjcS49aNfE33PtrQPtoyUfa"
    check cert.publicKey().scheme == PKScheme.RSA
    check cert.verify(cert.peerId())

  test "Ed25519 Peer ID":
    let certBytesHex =
      "308201ae30820156a0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea37c307a3078060a2b0601040183a25a0101046a3068042408011220a77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b90440d90d2769db992d5e6195dbb08e706b6651e024fda6cfb8846694a435519941cac215a8207792e42849cccc6cd8136c6e4bde92a58c5e08cfd4206eb5fe0bf909300a06082a8648ce3d0403020346003043021f50f6b6c52711a881778718238f650c9fb48943ae6ee6d28427dc6071ae55e702203625f116a7a454db9c56986c82a25682f7248ea1cb764d322ea983ed36a31b77"
    let cert = parse(fromHex(certBytesHex))

    check $cert.peerId() == "12D3KooWM6CgA9iBFZmcYAHA6A2qvbAxqfkmrYiRQuz3XEsk4Ksv"
    check cert.publicKey().scheme == PKScheme.Ed25519
    check cert.verify(cert.peerId())

  test "Secp256k1 Peer ID":
    let certBytesHex =
      "308201ba3082015fa0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea38184308181307f060a2b0601040183a25a01010471306f0425080212210206dc6968726765b820f050263ececf7f71e4955892776c0970542efd689d2382044630440220145e15a991961f0d08cd15425bb95ec93f6ffa03c5a385eedc34ecf464c7a8ab022026b3109b8a3f40ef833169777eb2aa337cfb6282f188de0666d1bcec2a4690dd300a06082a8648ce3d0403020349003046022100e1a217eeef9ec9204b3f774a08b70849646b6a1e6b8b27f93dc00ed58545d9fe022100b00dafa549d0f03547878338c7b15e7502888f6d45db387e5ae6b5d46899cef0"
    let cert = parse(fromHex(certBytesHex))

    check $cert.peerId() == "16Uiu2HAkutTMoTzDw1tCvSRtu6YoixJwS46S1ZFxW8hSx9fWHiPs"
    check cert.publicKey().scheme == PKScheme.Secp256k1
    check cert.verify(cert.peerId())

  test "Invalid certificate signature":
    let certBytesHex =
      "308201f73082019da0030201020204499602d2300a06082a8648ce3d040302302031123010060355040a13096c69627032702e696f310a300806035504051301313020170d3735303130313133303030305a180f34303936303130313133303030305a302031123010060355040a13096c69627032702e696f310a300806035504051301313059301306072a8648ce3d020106082a8648ce3d030107034200040c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd601331c8870234dec878504c174144fa4b14b66a651691606d8173e55bd37e381569ea381c23081bf3081bc060a2b0601040183a25a01010481ad3081aa045f0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f204473045022100bb6e03577b7cc7a3cd1558df0da2b117dfdcc0399bc2504ebe7de6f65cade72802206de96e2a5be9b6202adba24ee0362e490641ac45c240db71fe955f2c5cf8df6e300a06082a8648ce3d0403020348003045022100e847f267f43717358f850355bdcabbefb2cfbf8a3c043b203a14788a092fe8db022027c1d04a2d41fd6b57a7e8b3989e470325de4406e52e084e34a3fd56eef0d0df"
    let cert = parse(fromHex(certBytesHex)) # should parse correctly

    # should have key
    check $cert.peerId() == "QmfXbAwNjJLXfesgztEHe8HwgVDCMMpZ9Eax1HYq6hn9uE"
    check cert.publicKey().scheme == PKScheme.ECDSA

    # should not verify
    check not cert.verify(cert.peerId())

  test "Expired certificate":
    let certBytesHex =
      "30820214308201BBA003020102021412A974B8DE545B54729BF8393EFFFB00AEF69FB5300A06082A8648CE3D04030230423140303E06035504030C37434E3D313244334B6F6F574A7A564657566869746861656A395172374E6A4A4642626A44447942475351737146317361734342635841483022180F32303234313232343038303030345A180F32303235303232343038303030345A30423140303E06035504030C37434E3D313244334B6F6F574A7A564657566869746861656A395172374E6A4A4642626A44447942475351737146317361734342635841483059301306072A8648CE3D020106082A8648CE3D03010703420004C1DB5D2F5D4697386B723993D5499DB50E80E3F970135381B25FDBCA0660797F79FCE818EDDEFF6D27F56C6505F3F3F439E5D78F355293A5215718FA91DA0263A3818A3081873078060A2B0601040183A25A0101046A30680424080112208850FF8CF0E751088411ECF49A34DDBB50EEE0584F1B8CA6F9BBC93752FD6D4A04401ACF48FCFC7CA932C316E21DC986B366531D158E1499194D8601AE9FEF65D6E41198D4FC14B5AEA6BC67B06D28AFA13B759477048FF887CC26C0F197FB227B0F300B0603551D0F0101FF0401A0300A06082A8648CE3D040302034700304402206B1C01813E0A3CF0777D564A8090386B324660E703F6120E7C387DF23F94323B0220206E6BCC1213EF2A15E01B16F30DF45653B84AE6CEA87271A9301E055DB65FCB"
    let cert = parse(fromHex(certBytesHex))

    # should have valid key
    check $cert.peerId() == "12D3KooWJzVFWVhithaej9Qr7NjJFBbjDDyBGSQsqF1sasCBcXAH"
    check cert.publicKey().scheme == PKScheme.Ed25519

    # should not verify
    check not cert.verify(cert.peerId())

suite "utilities test":
  test "parseCertTime":
    var dt = parseCertTime("Mar 19 11:54:31 2025 GMT")
    check 1742385271 == dt.toUnix()

    dt = parseCertTime("Jan  1 00:00:00 1975 GMT")
    check 157766400 == dt.toUnix()

    dt = parseCertTime("Jan  1 13:05:06 2025 GMT")
    check 1735736706 == dt.toUnix()

    expect TimeParseError:
      discard parseCertTime("")

  test "validTo":
    let keypair = KeyPair.random(Ed25519, rng()).tryGet()
    let expiration = fromUnix(1735736706)
    let cert = generateX509(keypair, validTo = expiration, encodingFormat = PEM)

    check validTo(cert.certificate, PEM).get() == expiration

  test "KeyPair to cert_key_t":
    let key = KeyPair.random(PKScheme.RSA, rng()).get()

    let rawSeckey: seq[byte] = key.seckey.getRawBytes.valueOr:
      raiseAssert "Failed to get seckey raw bytes (DER)"

    # make seckey into certKey
    let certKey = cert_new_key_t(rawSeckey).valueOr:
      raiseAssert("Failed to create key")
    defer:
      cert_free_key(certKey)

    # make certKey back into seq[byte]
    let rawSeckeyBack = cert_serialize_privk(certKey, CERT_FORMAT_DER).valueOr:
      raiseAssert("Failed to serialize privk")

    # after and before should be the same
    check rawSeckey == rawSeckeyBack

  test "CSR generation":
    let certKey = cert_generate_key().expect("could not generate key")
    defer:
      cert_free_key(certKey)

    check:
      cert_signing_req("my.domain.string", certKey).isOk()

      cert_signing_req(
        "my.big.domain.string.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaa",
          # 253 characters, no labels longer than 63, okay
        certKey,
      )
        .isOk()

      cert_signing_req(
        "my.domain.", # domain ending in ".", okay
        certKey,
      )
        .isOk()

      cert_signing_req(
        "my.big.domain.string.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        # 254 characters, too long
        certKey,
      )
        .error() == CERT_ERROR_CN_TOO_LONG

      cert_signing_req(
        "my.big.domain.string.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          # 64 character label, too long
        certKey,
      )
        .error() == CERT_ERROR_CN_LABEL_TOO_LONG

      cert_signing_req(
        "my..empty.label.domain", # domain with empty label
        certKey,
      )
        .error() == CERT_ERROR_CN_EMPTY_LABEL # CERT_ERROR_CN_EMPTY_LABEL

      cert_signing_req(
        "", # domain with empty cn
        certKey,
      )
        .error() == CERT_ERROR_CN_EMPTY

  test "parse rejects empty certificate":
    expect CertificateParsingError:
      discard parse(newSeq[byte]())

  test "certificate extension values must be non-empty":
    let certKey = cert_generate_key().expect("could not generate key")
    defer:
      cert_free_key(certKey)

    check:
      cert_generate(
        certKey,
        @[],
        @[byte(1)],
        "test",
        "20250101130506Z".cstring,
        "20250101140506Z".cstring,
        CERT_FORMAT_DER,
      ).error == CERT_ERROR_EXTENSION_DATA
      cert_generate(
        certKey,
        @[byte(1)],
        @[],
        "test",
        "20250101130506Z".cstring,
        "20250101140506Z".cstring,
        CERT_FORMAT_DER,
      ).error == CERT_ERROR_EXTENSION_DATA
