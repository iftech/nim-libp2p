# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import lint
import tools/chronicles_linter

runLint:
  sources = ["."]
  ignoredPatterns = ["**/nimbledeps/**", "**/nimcache*/**", "./build/**/*"]

  step "Check chronicles messages":
    linter = chronicles
    check messageEndsWithPunctuation:
      severity = error
    check messageMaxSentences:
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
