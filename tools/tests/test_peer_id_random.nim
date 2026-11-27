# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import compiler/[parser, idents, options]
import ../peer_id_random_linter

proc count(source: string): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  peerIdRandom.run(source, ast, PeerIdRandomSettings()).len

for source in [
  "discard PeerId.random(rng)", "discard PeerId.random(rng())",
  "discard PeerId.random(10, rng())", "proc nested() = discard PeerId.random(rng())",
]:
  doAssert count(source) == 1, source
for source in [
  "discard PeerId.random()", "discard PeerId.random(10)", "discard Other.random(rng())",
  "discard PeerId.random(customRng)",
]:
  doAssert count(source) == 0, source
