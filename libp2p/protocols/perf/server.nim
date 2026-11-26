# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## `Perf <https://github.com/libp2p/specs/blob/master/perf/perf.md>`_ protocol specification

{.push raises: [].}

import chronos, chronicles
import stew/endians2
import ./core, ../protocol, ../../stream/connection

export chronicles, connection

logScope:
  topics = "libp2p perf"

type Perf* = ref object of LPProtocol

proc new*(T: typedesc[Perf]): T =
  var p = T()

  proc handle(stream: Stream, proto: ProtoCodec) {.async: (raises: [CancelledError]).} =
    try:
      trace "Received benchmark performance check", stream

      var sizeBuffer: array[8, byte]
      await stream.readExactly(addr sizeBuffer[0], 8)
      var responseSize = uint64.fromBytesBE(sizeBuffer)

      var readBuffer: array[PerfSize, byte]
      while not stream.atEof:
        try:
          let readBytes = await stream.readOnce(addr readBuffer[0], PerfSize)
          if readBytes == 0:
            break
        except LPStreamEOFError:
          break

      var writeBuffer: array[PerfSize, byte]
      while responseSize > 0:
        let toWrite = min(responseSize, PerfSize)
        await stream.write(writeBuffer[0 ..< toWrite])
        responseSize -= toWrite
    except CancelledError as exc:
      trace "cancelled perf handler"
      raise exc
    except CatchableError as exc:
      trace "exception in perf handler", err = exc.msg, stream
    finally:
      await stream.close()

  p.handler = handle
  p.codec = PerfCodec
  return p
