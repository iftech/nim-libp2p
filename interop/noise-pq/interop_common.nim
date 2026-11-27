# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Shared helpers for the NoiseHFS interop dialer and listener: the fixed
## stdout contract (`emit`), command-line parsing (`portFromArgs`), the
## one-line-only greeting framing (`firstLine`), and validation of the
## post-handshake greeting both sides exchange (`requireGreeting`).

import std/[os, strutils]

const
  GreetingPrefix* = "hello from "
  DefaultPort* = 9998
  MaxPortDigits = 5

proc emit*(line: string) {.raises: [IOError].} =
  ## Write one contract line to stdout and flush immediately: stdout is
  ## fully buffered when redirected to a file, and the runner polls the log
  ## while this process is still alive.
  stdout.writeLine(line)
  stdout.flushFile()

proc portFromArgs*(usage: string): int {.raises: [].} =
  ## The TCP port given as the only command-line argument, or `DefaultPort`
  ## without one. Anything else - extra arguments, non-digits, or a value
  ## outside 1..65535 - exits with `usage`. Port 0 is refused because the
  ## kernel would then pick the port, and the runner has to know it up front.
  if paramCount() == 0:
    return DefaultPort
  if paramCount() > 1:
    quit(usage, 1)

  let arg = paramStr(1)
  if arg.len == 0 or arg.len > MaxPortDigits or not arg.allCharsInSet(Digits):
    quit(usage, 1)

  let port =
    try:
      parseInt(arg)
    except ValueError:
      quit(usage, 1)
  if port < 1 or port > int(uint16.high):
    quit(usage, 1)
  port

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

proc requireGreeting*(line: string) {.raises: [IOError].} =
  ## Abort with the fixed ERROR contract unless `line` is `GreetingPrefix`
  ## followed by a non-empty name.
  if not line.startsWith(GreetingPrefix) or line.len == GreetingPrefix.len:
    stderr.writeLine("ERROR unexpected greeting: " & line)
    quit(1)
