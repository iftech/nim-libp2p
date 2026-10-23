# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import nimcrypto/utils
import ../../../libp2p/crypto/[crypto, ed25519/ed25519]
import ../../tools/[unittest, crypto]

## Test vectors are from RFC 8032 (https://tools.ietf.org/html/rfc8032)

const TestsCount = 20

const SecretKeys = [
  """9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
     d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a""",
  """4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
     3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c""",
  """c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
     fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025""",
  """f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5
     278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e""",
  """833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
     ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf""",
]
const PublicKeys = [
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
  "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
  "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
]

const Messages = [
  "", "72", "af82",
  """08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98
     fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8
     79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d
     658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc
     1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe
     ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e
     06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef
     efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7
     aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1
     85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2
     d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24
     554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270
     88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc
     2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07
     07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba
     b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a
     ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e
     c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7
     51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c
     42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8
     ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df
     f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08
     d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649
     de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4
     88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3
     2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e
     6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f
     b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5
     0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1
     369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d
     b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c
     0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0""",
  """ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
     2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f""",
]

const Signatures = [
  """e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
     5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b""",
  """92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
     085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00""",
  """6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
     18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a""",
  """0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350
     aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03""",
  """dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589
     09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704""",
]

const FailScalars = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  "EDD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010",
]

const GoodScalars = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ECD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010",
]

suite "Ed25519 test suite":
  test "Scalar check edge cases test":
    for item in FailScalars:
      check checkScalar(fromHex(stripSpaces(item))) == 0
    for item in GoodScalars:
      check checkScalar(fromHex(stripSpaces(item))) == 1

  test "Private key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EdPrivateKey
      var skey2 = newSeq[byte](256)
      var key = EdPrivateKey.random(rng())
      var skey1 = key.getBytes()
      check:
        key.toBytes(skey2) > 0
      check:
        rkey1.init(skey1) == true
        rkey2.init(skey2) == true
      var rkey3 = EdPrivateKey.init(skey1).expect("key/sig")
      var rkey4 = EdPrivateKey.init(skey2).expect("key/sig")
      check:
        rkey1 == key
        rkey2 == key
        rkey3 == key
        rkey4 == key
      rkey1.clear()
      rkey2.clear()
      check:
        isFullZero(rkey1.data) == true
        isFullZero(rkey2.data) == true

  test "Public key serialize/deserialize test":
    for i in 0 ..< TestsCount:
      var rkey1, rkey2: EdPublicKey
      var skey2 = newSeq[byte](256)
      var pair = EdKeyPair.random(rng())
      var skey1 = pair.pubkey.getBytes()
      check:
        pair.pubkey.toBytes(skey2) > 0
        rkey1.init(skey1) == true
        rkey2.init(skey2) == true
      var rkey3 = EdPublicKey.init(skey1).expect("key/sig")
      var rkey4 = EdPublicKey.init(skey2).expect("key/sig")
      check:
        rkey1 == pair.pubkey
        rkey2 == pair.pubkey
        rkey3 == pair.pubkey
        rkey4 == pair.pubkey
      rkey1.clear()
      rkey2.clear()
      check:
        isFullZero(rkey1.data) == true
        isFullZero(rkey2.data) == true

  test "Malformed public keys are rejected":
    var identity, orderTwo, nonCanonicalIdentity: array[EdPublicKeySize, byte]
    identity[0] = 1
    orderTwo[0] = 0xEC
    nonCanonicalIdentity[0] = 0xEE
    for i in 1 ..< EdPublicKeySize - 1:
      orderTwo[i] = 0xFF
      nonCanonicalIdentity[i] = 0xFF
    orderTwo[^1] = 0x7F
    nonCanonicalIdentity[^1] = 0x7F

    var key: EdPublicKey
    check:
      not key.init(identity)
      not key.init(orderTwo)
      not key.init(nonCanonicalIdentity)

  test "RFC8032 test vectors":
    for i in 0 ..< 5:
      var key = EdPrivateKey.init(stripSpaces(SecretKeys[i])).expect("key/sig")
      var exppub = EdPublicKey.init(stripSpaces(PublicKeys[i])).expect("key/sig")
      var pubkey = key.getPublicKey()
      check pubkey == exppub
      var msg = fromHex(stripSpaces(Messages[i]))
      var sig = key.sign(msg)
      var expsig =
        EdSignature.init(fromHex(stripSpaces(Signatures[i]))).expect("key/sig")
      check sig == expsig
      check sig.verify(msg, pubkey) == true
      sig.data[32] = not (sig.data[32])
      check sig.verify(msg, pubkey) == false

  test "Generate/Sign/Serialize/Deserialize/Verify test":
    var message = "message to sign"
    for i in 0 ..< TestsCount:
      var kp = EdKeyPair.random(rng())
      var sig = kp.seckey.sign(message)
      var sersk = kp.seckey.getBytes()
      var serpk = kp.pubkey.getBytes()
      var sersig = sig.getBytes()
      discard EdPrivateKey.init(sersk)
      var pubkey = EdPublicKey.init(serpk).expect("key/sig")
      var csig = EdSignature.init(sersig).expect("key/sig")
      check csig.verify(message, pubkey) == true
      let error = csig.data.high
      csig.data[error] = not (csig.data[error])
      check csig.verify(message, pubkey) == false

  test "fromSeed is deterministic":
    let seed = fromHex(stripSpaces(SecretKeys[0])[0 ..< 64])
    let key1 = EdPrivateKey.fromSeed(seed)
    let key2 = EdPrivateKey.fromSeed(seed)
    let expected = EdPrivateKey.init(stripSpaces(SecretKeys[0])).expect("key/sig")
    check key1 == key2
    check key1 == expected

  test "fromSeed with zero seed produces valid key":
    var seed: array[32, byte]
    let key = EdPrivateKey.fromSeed(seed)
    let expected = EdPrivateKey
      .init(
        "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
      )
      .expect("key/sig")
    check key == expected

  test "fromSeed produces same key as random() with same seed":
    # Generate a random key, extract its seed, recreate with fromSeed
    let randomKey = EdPrivateKey.random(rng())
    var seed: array[32, byte]
    copyMem(addr seed[0], addr randomKey.data[0], 32)
    let recreated = EdPrivateKey.fromSeed(seed)
    check randomKey == recreated
