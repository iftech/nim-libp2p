# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Shared helpers for the NoiseHFS interop dialer and listener: the fixed
## stdout contract (`emit`), the one-line-only greeting framing
## (`firstLine`), and validation of the post-handshake greeting both sides
## exchange (`requireGreeting`).

import std/strutils

const GreetingPrefix* = "hello from "

proc emit*(line: string) =
  ## Write one contract line to stdout and flush immediately: stdout is
  ## fully buffered when redirected to a file, and the runner polls the log
  ## while this process is still alive.
  echo line
  stdout.flushFile()

proc firstLine*(s: string): string {.raises: [ValueError].} =
  ## Only the first line of `s`, stripped. A peer could batch extra bytes
  ## into the same message as its greeting; RECV must always be exactly one
  ## clean line on stdout, not whatever else rode along in the frame.
  ## A message with no newline is not a complete greeting line: raise
  ## instead of accepting it (the JS, Python and Rust harnesses likewise
  ## never accept a greeting without its newline).
  let nlPos = s.find('\n')
  if nlPos < 0:
    raise newException(ValueError, "truncated greeting")
  s[0 ..< nlPos].strip()

proc requireGreeting*(line: string) =
  ## Abort with the fixed ERROR contract unless `line` is `GreetingPrefix`
  ## followed by a non-empty name.
  if not line.startsWith(GreetingPrefix) or line.len == GreetingPrefix.len:
    stderr.writeLine("ERROR unexpected greeting: " & line)
    quit(1)
