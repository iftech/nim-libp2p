# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results
import chronos, chronicles
import
  ../../../../libp2p/[switch, muxers/muxer, dialer, multiaddress, multicodec, peerid],
  ../../protocol,
  ./types,
  ./server

type AutonatV2Mock* = ref object of LPProtocol
  config*: AutonatV2Config
  response*: seq[byte]

proc new*(
    T: typedesc[AutonatV2Mock], config: AutonatV2Config = AutonatV2Config.new()
): T =
  let autonatV2 = T(config: config)
  proc handleStream(
      stream: Stream, proto: ProtoCodec
  ) {.async: (raises: [CancelledError]).} =
    defer:
      await stream.close()

    try:
      let msg = AutonatV2Msg.decode(await stream.readLp(AutonatV2MsgLpSize)).valueOr:
        return
    except LPStreamError:
      return

    try:
      await stream.writeLp(autonatV2.response)
    except LPStreamRemoteClosedError:
      discard
    except LPStreamError:
      discard

  autonatV2.handler = handleStream
  autonatV2.codec = AutonatV2DialRequestCodec
  autonatV2
