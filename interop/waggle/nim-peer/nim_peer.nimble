version = "0.1.0"
author = "Status Research & Development GmbH"
description = "Waggle peer for Nim/Rust interoperability testing"
license = "MIT"
srcDir = "src"
bin = @["peer"]

requires "nim >= 2.2.6"
# libp2p is resolved via nimble.paths from the project root
