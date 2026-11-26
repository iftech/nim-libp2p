version = "0.1.0"
author = "Status Research & Development GmbH"
description = "mDNS peer for interop testing"
license = "MIT"
srcDir = "src"
bin = @["peer"]

# Dependencies

requires "nim >= 2.2.6"
# libp2p is resolved via nimble.paths from the project root
