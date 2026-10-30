# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [], gcsafe.}

import ../../../../libp2p/protocols/waggle

export waggle

type
  BitMetadata* = ref object of WaggleMetadata
    have*: byte

  BitShard* = ref object of WaggleShard
    id*: seq[byte]
    have*: byte

method clone*(m: BitMetadata): WaggleMetadata =
  BitMetadata(have: m.have)

method bytes*(m: BitMetadata): seq[byte] =
  @[m.have]

proc validate(data: seq[byte]): Result[void, string] =
  if data.len != 1 or data[0] > 7:
    return err("invalid bit metadata")
  ok()

method update*(m: BitMetadata, data: seq[byte]): Result[bool, string] =
  ?data.validate()
  let next = m.have or data[0]
  let changed = m.have != next
  m.have = next
  ok(changed)

method objectId*(s: BitShard): seq[byte] =
  s.id

method metadata*(s: BitShard): WaggleMetadata =
  BitMetadata(have: s.have)

method actionFromMetadata*(
    s: BitShard, peer: PeerId, connectionId: ConnectionId, metadata: Opt[seq[byte]]
): Result[WaggleAction, string] =
  var remote: byte
  if metadata.isSome:
    let data = metadata.get()
    ?data.validate()
    remote = data[0]
  let missing = s.have and not remote
  var action = WaggleAction(need: (remote and not s.have) != 0)
  if missing != 0:
    action.send = Opt.some(
      PieceSend(pieces: @[missing], peerMetadata: BitMetadata(have: remote or missing))
    )
  ok(action)
