# Common hurdles

This page will document all common hurdles you may experience while developing or using nim-libp2p.

## compile error: undeclared identifier

Sometimes compiling nim-libp2p or your project that depends on nim-libp2p may produce the following compile error:

```
nim c -r --threads:on libp2p_chat_example.nim
Hint: used config file '/home/user/.choosenim/toolchains/nim-2.2.0/config/nim.cfg' [Conf]
Hint: used config file '/home/user/.choosenim/toolchains/nim-2.2.0/config/config.nims' [Conf]
.......................................................................................................................................................................
/home/user/.nimble/pkgs2/libp2p-1.14.3-3c089f3ccd23aa5a04e5db288cb8eef524938487/libp2p/utility.nim(77, 30) Error: undeclared identifier: 'Opt'
```

Error message `Error: undeclared identifier:` can complain about identifier of any other library - it will be different from time to time. Root cause is the same for all errors of this kind.

To fix this please, follow these steps:

1. remove `/home/user/.nimble` - to remove everything (nim & nimble)
2. install nim again - fresh install
3. `nimble install nimble` - get latest `nimble` first
4. then run `make setup` when developing this repository, or `nimble install libp2p` when using libp2p from another project

## Connection admission limits

The default connection cap is 50 shared slots, with no outbound reserve.
`withMaxConnections(n)` and `ConnectionLimits.maxTotal(n)` also leave every slot
available to either direction unless a reserve is supplied.

To prevent established inbound connections from consuming outbound dial capacity,
opt in with an absolute number of reserved slots:

```nim
ConnectionLimits.maxTotal(150, outboundReserve = 30)
# Equivalent builder setting:
# builder.withMaxConnections(150, outboundReserve = 30)
```

This allows 150 total connections, with at most 120 inbound. Outbound connections
can use all 150 slots when available. The reserve must be nonnegative and smaller
than the total cap. Without a reserve, authenticated inbound connections can
still fill the shared cap and block ordinary outbound dials.

Pending inbound upgrades have separate protections regardless of the reserve:
there are at most 32, further limited to half the inbound capacity (minimum one),
and at most eight per IPv4 address or IPv6 /56. Connections without an IP use only
the global pending budget. The budget covers Identify and connection callbacks.
Transport upgrades expire after 10 seconds. These protections change handshake
admission behavior even when the outbound reserve is zero.

---

(open a pull request if you want something to be included here)

---

[← Back to README](../README.md)
