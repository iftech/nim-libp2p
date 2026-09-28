# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import std/macros, results, protobuf_serialization

when defined(libp2p_protobuf_metrics):
  import ./protobuf_metrics

func makeLabel(domain, msgType: string): string =
  if domain == "":
    return msgType
  return domain & "." & msgType

template trackEncodeBytes*(count: int, msgType: typedesc, domain: string) =
  when defined(libp2p_protobuf_metrics):
    let label = makeLabel(domain, $msgType)
    libp2p_protobuf_bytes_sent.inc(count.int64, labelValues = [label])
    libp2p_protobuf_messages_sent.inc(labelValues = [label])

template trackDecodeBytes*(count: int, msgType: typedesc, domain: string) =
  when defined(libp2p_protobuf_metrics):
    let label = makeLabel(domain, $msgType)
    libp2p_protobuf_bytes_received.inc(count.int64, labelValues = [label])
    libp2p_protobuf_messages_received.inc(labelValues = [label])

macro decodeFor*(
    _: type Protobuf, Types: untyped, withMetrics: bool = false, domain: string = ""
): untyped =
  ## This generates decode protobuf procs for `Types`
  let doMetrics = newLit(withMetrics.eqIdent("true"))
  var stmts = newStmtList()
  for T in Types:
    let decodeName = ident("decode" & $T)
    let metricLabel = newLit(makeLabel(domain.strVal, $T))
    stmts.add quote do:
      proc `decodeName`(buf2: seq[byte]): `T` {.raises: [SerializationError].} =
        when defined(libp2p_protobuf_metrics) and `doMetrics`:
          libp2p_protobuf_bytes_received.inc(
            buf2.len.int64, labelValues = [`metricLabel`]
          )
          libp2p_protobuf_messages_received.inc(labelValues = [`metricLabel`])

        decode(Protobuf, buf2, `T`)

      proc decode*(_: type `T`, buf: seq[byte]): Result[`T`, string] =
        try:
          ok(`decodeName`(buf))
        except SerializationError as e:
          err("failed to decode " & $(`T`) & " from protobuf bytes. " & e.msg)

  stmts

macro serializerFor*(
    _: type Protobuf, Types: untyped, withMetrics: bool = false, domain: string = ""
): untyped =
  ## Generates public protobuf `encode` and `T.decode` helpers.
  ## Define local `validateDecoded` for checks protobuf cannot express.
  let doMetrics = newLit(withMetrics.eqIdent("true"))
  var stmts = newStmtList()
  for T in Types:
    let decodeName = ident("decode" & $T)
    let metricLabel = newLit(makeLabel(domain.strVal, $T))
    stmts.add quote do:
      proc encode*(c: `T`): seq[byte] =
        let buf = encode(Protobuf, c)
        when defined(libp2p_protobuf_metrics) and `doMetrics`:
          libp2p_protobuf_bytes_sent.inc(buf.len.int64, labelValues = [`metricLabel`])
          libp2p_protobuf_messages_sent.inc(labelValues = [`metricLabel`])
        buf

      proc `decodeName`(buf2: seq[byte]): `T` {.raises: [SerializationError].} =
        when defined(libp2p_protobuf_metrics) and `doMetrics`:
          libp2p_protobuf_bytes_received.inc(
            buf2.len.int64, labelValues = [`metricLabel`]
          )
          libp2p_protobuf_messages_received.inc(labelValues = [`metricLabel`])

        decode(Protobuf, buf2, `T`)

      proc decode*(_: type `T`, buf: seq[byte]): Result[`T`, string] =
        let decoded =
          try:
            `decodeName`(buf)
          except SerializationError as e:
            return err("failed to decode " & $(`T`) & " from protobuf bytes. " & e.msg)

        when compiles(`T`.validateDecoded(decoded)):
          # Let types reject proto3 defaults or other invalid decoded values.
          let validation = `T`.validateDecoded(decoded)
          if validation.isErr:
            return err(
              "failed to decode " & $(`T`) & " from protobuf bytes. " & validation.error
            )

        ok(decoded)

  stmts
