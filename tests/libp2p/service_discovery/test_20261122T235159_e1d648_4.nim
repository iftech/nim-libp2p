# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261122T235159-e1d648/4.
# Spec, "REGISTER Request Validation": "Registrars MUST validate: ... 2. `key` =
# 32 bytes (valid SHA-256) ... Respond with `register.status = REJECTED` if
# validation fails."

import results
import ../../../libp2p/signed_envelope
import ../../../libp2p/protocols/kademlia/protobuf as kadprotobuf
import ../../tools/unittest
import ./utils

suite "Proof 20261122T235159-e1d648/4 - REGISTER without a key":
  test "REGISTER with no key is answered with status REJECTED":
    let disco = setupServiceDiscoveryNode()
    let ad = makeAdvertisement("proof-4-service")
    let inMsg = kadprotobuf.Message(
      msgType: kadprotobuf.MessageType.register,
      register: Opt.some(
        kadprotobuf.RegisterMessage(
          advertisement: ad.encode().get(),
          status: Opt.none(kadprotobuf.RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(ad.data.peerId, inMsg)

    # What the stream handler writes back, as the advertiser decodes it.
    let onWire = kadprotobuf.Message.decode(reply.encode()).get()
    checkpoint "reply on the wire: " & $reply.encode().len & " bytes"

    check:
      onWire.msgType == Opt.some(kadprotobuf.MessageType.register)
      onWire.register.isSome()
    check onWire.register.get(kadprotobuf.RegisterMessage()).status ==
      Opt.some(kadprotobuf.RegistrationStatus.Rejected)
