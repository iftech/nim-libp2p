# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/strutils
import compiler/[parser, idents, options]
import ../license_linter

proc count(source: string, settings = HeaderSettings()): int =
  let ast = parseString(source, newIdentCache(), newPartialConfigRef())
  licenseHeader.run(source, ast, settings).len

let header = HeaderSettings().license
doAssert count(header & "\ndiscard\n") == 0
doAssert count(header.replace("\n", "  \r\n")) == 0
for source in ["", "discard", "\n" & header, "# wrong\n" & header]:
  doAssert count(source) == 1, source
doAssert count("# custom\ndiscard", HeaderSettings(license: "# custom\n")) == 0
let source = "# SPDX-License-Identifier: Apache-2.0 OR MIT\n# wrong\n"
let ast = parseString(source, newIdentCache(), newPartialConfigRef())
let findings = licenseHeader.run(source, ast, HeaderSettings())
doAssert findings.len == 1 and findings[0].line == 2
