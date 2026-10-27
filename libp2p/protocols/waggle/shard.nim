# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [], gcsafe.}

import results
import ../../peerid

export results

type
  WaggleMetadata* = ref object of RootObj
  WaggleShard* = ref object of RootObj

  PieceSend* = object
    pieces*: seq[byte]
    peerMetadata*: WaggleMetadata

  WaggleAction* = object
    need*: bool
    send*: Opt[PieceSend]

method clone*(metadata: WaggleMetadata): WaggleMetadata {.base.} =
  ## Return an independent snapshot, including mutable state.
  raiseAssert "WaggleMetadata.clone must be implemented"

method bytes*(metadata: WaggleMetadata): seq[byte] {.base.} =
  raiseAssert "WaggleMetadata.bytes must be implemented"

method update*(
    metadata: WaggleMetadata, data: seq[byte]
): Result[bool, string] {.base.} =
  ## Merge remote state, returning whether it changed. Reject invalid metadata.
  raiseAssert "WaggleMetadata.update must be implemented"

method objectId*(shard: WaggleShard): seq[byte] {.base.} =
  raiseAssert "WaggleShard.objectId must be implemented"

method metadata*(shard: WaggleShard): WaggleMetadata {.base.} =
  ## Return an independent snapshot describing this object's available/wanted pieces.
  raiseAssert "WaggleShard.metadata must be implemented"

method actionFromMetadata*(
    shard: WaggleShard, peer: PeerId, connectionId: uint64, metadata: Opt[seq[byte]]
): Result[WaggleAction, string] {.base.} =
  ## Select missing pieces and the peer view after sending them. `need` asks the
  ## application to integrate an incoming message. Do not mutate the shard here.
  raiseAssert "WaggleShard.actionFromMetadata must be implemented"
