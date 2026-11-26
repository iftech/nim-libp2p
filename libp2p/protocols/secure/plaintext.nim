# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos
import secure, ../../stream/connection

const PlainTextCodec* = "/plaintext/1.0.0"

type PlainText* = ref object of Secure

proc new*(T: typedesc[PlainText]): T =
  let p = T()
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    ## plain text doesn't do anything
    discard

  p.codec = PlainTextCodec
  p.handler = handle
  p
