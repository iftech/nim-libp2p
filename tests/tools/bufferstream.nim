# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronos
import ../../libp2p/stream/[chronosstream, bufferstream, lpstream]

type
  WriteHandler* = proc(data: sink seq[byte]): Future[void] {.
    async: (raises: [CancelledError, LPStreamError])
  .}

  TestBufferStream* = ref object of BufferStream
    writeHandler*: WriteHandler

  ReadSignallingStream* = ref object of BufferStream
    reads*: AsyncQueue[int]

method write*(
    s: TestBufferStream, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError], raw: true).} =
  s.writeHandler(move(msg))

method getWrapped*(s: TestBufferStream): Connection =
  nil

proc new*(T: typedesc[TestBufferStream], writeHandler: WriteHandler): T =
  let testBufferStream = T(writeHandler: writeHandler)
  testBufferStream.initStream()
  testBufferStream

method readOnce*(
    s: ReadSignallingStream, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  let reading = procCall BufferStream(s).readOnce(pbytes, nbytes)
  await s.reads.addLast(nbytes)
  return await reading
