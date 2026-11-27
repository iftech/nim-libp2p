# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import chronos, chronicles
import ../protocodec
import ../stream/connection, ../errors

logScope:
  topics = "libp2p muxer"

const DefaultChanTimeout* = 5.minutes

type
  MuxerError* = object of LPError
  TooManyChannels* = object of MuxerError

  StreamHandler* = proc(stream: MuxedStream): Future[void] {.async: (raises: []).}
  MuxerHandler* = proc(muxer: Muxer): Future[void] {.async: (raises: []).}

  Muxer* = ref object of RootObj
    streamHandler*: StreamHandler
    handler*: Future[void].Raising([])
    connection*: RawConn

  # user provider proc that returns a constructed Muxer
  MuxerConstructor* = proc(conn: RawConn): Muxer {.gcsafe, closure, raises: [].}

  # this wraps a creator proc that knows how to make muxers
  MuxerProvider* = object
    newMuxer*: MuxerConstructor
    codec*: ProtoCodec

func shortLog*(m: Muxer): auto =
  if m == nil:
    "nil"
  else:
    shortLog(m.connection)

chronicles.formatIt(Muxer):
  shortLog(it)

# muxer interface
method newStream*(
    m: Muxer, name: string = "", lazy: bool = false
): Future[MuxedStream] {.
    base, async: (raises: [CancelledError, LPStreamError, MuxerError], raw: true)
.} =
  raiseAssert("[Muxer.newStream] abstract method not implemented!")

when defined(libp2p_agents_metrics):
  method setShortAgent*(m: Muxer, shortAgent: string) {.base, gcsafe.} =
    m.connection.setShortAgent(shortAgent)

method close*(m: Muxer) {.base, async: (raises: []).} =
  if m.connection != nil:
    await m.connection.close()

method handle*(m: Muxer): Future[void] {.base, async: (raises: []).} =
  discard

proc new*(
    T: typedesc[MuxerProvider], creator: MuxerConstructor, codec: ProtoCodec
): T {.gcsafe.} =
  let muxerProvider = T(newMuxer: creator, codec: codec)
  muxerProvider

method getStreams*(m: Muxer): seq[MuxedStream] {.base, gcsafe.} =
  raiseAssert("[Muxer.getStreams] abstract method not implemented!")
