# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import lint
import
  tools/[
    chronicles_linter, chronos_linter, code_style_linter, libp2p_linter,
    unittest2_linter,
  ]

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
    # Reported as a hint: without type information this check cannot tell a
    # value that has a compact formatter from one that does not, so it reports
    # values that `audit_logs.py` exempts. See the note in
    # `tools/chronicles_linter.nim`.
    check unboundedFields:
      severity = hint

  step "Check code style":
    ignoredPatterns = ["./tools/**/*"]
    check implicitResult:
      severity = hint

  step "Check chronos usage":
    check completedCancel:
      severity = hint

  # A short literal timeout in a test is how a test asserts that something
  # does not happen; the rule is about production code.
  step "Check chronos timeouts":
    ignoredPatterns = ["./tests/**/*"]
    check forbiddenCall:
      severity = hint
      settings:
        # `Event.wait()` takes no timeout; only `wait(fut, duration)` picks one.
        minArgs = 1
        # A duration from a config field or a parameter is the caller's budget.
        # Only a literal one is a number picked at the call site.
        literalOnly = true

  step "Check unittest2 usage":
    check checkFalse:
      severity = error

  # The helper's own implementation is the one place the raw call is right.
  step "Check nim-libp2p usage":
    ignoredPatterns = ["./libp2p/peerid.nim"]
    check peerIdRandom:
      severity = hint

  step "Check checkUntilTimeout":
    check checkUntilTimeout:
      severity = hint
