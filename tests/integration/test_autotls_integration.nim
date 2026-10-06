# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

when defined(linux) and defined(amd64):
  import chronos
  import ../../libp2p/[autotls/acme/api, autotls/acme/client, crypto/rsa]
  import ../tools/[unittest, crypto]

  template assertChallenge(challenge: ACMEChallengeDns01Response): auto =
    check:
      challenge.finalize.len > 0
      challenge.order.len > 0
      challenge.dns01.url.len > 0
      challenge.dns01.`type` == ACMEChallengeType.DNS01
      challenge.dns01.status == ACMEChallengeStatus.PENDING
      challenge.dns01.token.len > 0

  suite "AutoTLS Integration":
    asyncTeardown:
      checkTrackers()

    asyncTest "request challenge without ACMEClient (ACMEApi only)":
      let key = RsaPrivateKey.random(rng()).get()
      let acmeApi = ACMEApi.new(LetsEncryptStagingDirectoryURL)
      defer:
        await acmeApi.close()

      let registerResponse = (await acmeApi.requestRegister(key)).get()
      check registerResponse.kid != ""
      if registerResponse.kid == "":
        raiseAssert "unable to register acme account"

      let challenge = (
        await acmeApi.requestChallenge(
          @["some.dummy.domain.com"], key, registerResponse.kid
        )
      ).get()

      assertChallenge(challenge)

    asyncTest "request challenge with ACMEClient":
      let acme =
        ACMEClient.new(rng = rng(), api = ACMEApi.new(LetsEncryptStagingDirectoryURL))
      defer:
        await acme.close()

      let challenge = (await acme.getChallenge(@["some.dummy.domain.com"])).get()

      assertChallenge(challenge)
