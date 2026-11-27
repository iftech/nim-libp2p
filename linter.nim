# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import lint
import tools/chronicles_linter
import tools/log_payload_linter
import tools/todo_linter

runLint:
  sources = ["."]
  ignoredPatterns = ["**/nimbledeps/**", "**/nimcache*/**", "./build/**/*"]

  step "Check chronicles messages":
    check messageEndsWithPunctuation:
      severity = error
    check messageMaxSentences:
      severity = error

  step "Check chronicles fields":
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

  step "Check TODO issue references":
    check todoWithIssue:
      severity = hint

  step "Semantic checks":
    ignoredPatterns = ["./**/*"]
    semCheck boundedLogPayloads:
      severity = error
      settings:
        ignoredTypes =
          @["Duration", "MultiAddress", "IpAddress", "GroupId", "RateLimit"]
