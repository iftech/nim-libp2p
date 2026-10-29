# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import lint
import linters/chronicles

runLint:
  sources = ["."]
  ignoredPatterns = ["./nimbledeps/**/*", "./nimcache/**/*"]

  step "Check chronicles messages":
    linter = chronicles
    check messageEndsWithPeriod:
      severity = error
    check messageOneSentence:
      severity = error

  step "Check chronicles fields":
    linter = chronicles
    check fieldNameLength:
      severity = error
      settings:
        minLength = 3
        exceptions = ["id", "ip"]
    check errForException:
      severity = error
      settings:
        field = "err"
        aliases = ["description", "error", "message", "msg"]
    check noPayloadWhenElevated:
      severity = error
      settings:
        levels = ["warn", "error"]
        fields = [
          "msg", "message", "buffer", "record", "reply", "response", "rpcMsg", "data",
          "encoded", "certificate", "ticket", "key",
        ]
