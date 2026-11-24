# How we would like reports written

## Layout and length
- Short, with these sections in this order: Summary, Impact, Affected code, Reproduction, Suggested fix.

## What every report should state
- The protocol or component, and whether it is reachable before the security handshake completes.
- The attacker's position (any remote peer, a connected peer, a peer on the local network, a malicious
  server the node talks to) and what it has to send.
- The affected files and functions, the commit you tested, and the Nim memory manager used (refc/orc).
- A reproducer as a Nim test that can be dropped into `tests/libp2p/`.

## Style
- Plain text; one root cause per report; start the title with the component's name, e.g. "yamux: ...".
