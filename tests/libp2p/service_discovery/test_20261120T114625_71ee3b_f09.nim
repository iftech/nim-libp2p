# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH
{.used.}

# Proof for finding 20261120T114625-71ee3b/9.
# Spec, REGISTER Request Validation: "Registrars MUST validate: ... 2. key = 32
# bytes (valid SHA-256) ... Respond with register.status = REJECTED if
# validation fails."
# Spec, REGISTER Response: "type | REQUIRED | REGISTER (6)", "register.status |
# REQUIRED | CONFIRMED, WAIT, or REJECTED".

import results
import ../../../libp2p/[extended_peer_record, peerid]
import ../../../libp2p/protocols/kademlia/types as kadtypes
import ../../tools/unittest
import ./utils

suite "Proof 20261120T114625-71ee3b/9 - REGISTER without a key":
  test "a REGISTER request with no key is answered with status Rejected":
    let disco = setupServiceDiscoveryNode()
    let ad = makeAdvertisement("proof-missing-key")

    let inMsg = Message(
      msgType: MessageType.register,
      key: Opt.none(Key),
      register: Opt.some(
        RegisterMessage(
          advertisement: ad.encode().get(),
          status: Opt.none(RegistrationStatus),
          ticket: Opt.none(Ticket),
        )
      ),
    )

    let reply = disco.registration(ad.data.peerId, inMsg)

    let isRegisterReply = reply.msgType == Opt.some(MessageType.register)
    let isRejected =
      reply.register.isSome() and
      reply.register.get().status == Opt.some(RegistrationStatus.Rejected)

    check isRegisterReply
    check isRejected
