# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos, os, strutils
import ../../../../tests/interop/topic_streams
import ../../../../libp2p/[multiaddress, peerid]

when isMainModule:
  let address = readFile(paramStr(1)).strip().split("/p2p/")
  let success = waitFor topicStreamsInteropTest(
    MultiAddress.init(address[0]).get(), PeerId.init(address[1]).get()
  )
  if not success:
    quit("Topic streams interop failed", 1)
  echo "Topic streams interop passed over QUIC v1: two signed round trips per topic, two streams per direction"
