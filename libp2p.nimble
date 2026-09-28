mode = ScriptMode.Verbose

packageName = "libp2p"
version = "2.4.0"
author = "Status Research & Development GmbH"
description = "LibP2P implementation"
license = "MIT"
skipDirs = @["cbind", "examples", "interop", "simulation", "tests", "tools"]

requires "nim >= 2.2.4",
  "nimcrypto >= 0.6.0", "bearssl >= 0.2.7",
  "https://github.com/vacp2p/nim-boringssl >= 0.0.11", "chronicles >= 0.12.3",
  "chronos >= 4.2.2", "metrics >= 0.2.2", "secp256k1", "stew >= 0.4.2", "results",
  "serialization >= 0.5.0", "json_serialization >= 0.4.4", "lsquic >= 0.10.0",
  "protobuf_serialization >= 0.6.0",
  "https://github.com/status-im/nim-websock >= 0.4.1",
  "https://github.com/logos-storage/nim-libplum >= 0.6.2"

import os

let nimc = getEnv("NIMC", "nim")

task gen_multicodec,
  "Download the multicodec CSV and regenerate libp2p/multicodec_table.nim":
  exec nimc & " c -r tools/gen_multicodec.nim"
