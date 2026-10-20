# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

{.push raises: [].}

import std/net, tables, chronos, stew/[byteutils, endians2]
import
  ../../libp2p/[
    stream/connection,
    transports/tcptransport,
    transports/tortransport,
    upgrademngrs/upgrade,
    multiaddress,
    errors,
  ]
import ../tools/multiaddress

type TorServerStub* = ref object of RootObj
  tcpTransport: TcpTransport
  addrTable: Table[string, string]

proc new*(T: typedesc[TorServerStub]): T =
  T(
    tcpTransport: TcpTransport.new(flags = {ReuseAddr}, upgrade = Upgrade()),
    addrTable: initTable[string, string](),
  )

proc registerAddr*(self: TorServerStub, key: string, val: string) =
  self.addrTable[key] = val

proc bridge(
    srcStream: Stream, dstStream: Stream
) {.async: (raises: [CancelledError]).} =
  ## Relay bytes between the client and destination, propagating half-closes
  ## so that closeWrite from one side is forwarded to the other.
  const bufferSize = 4096
  var
    bufSrcToDst: array[bufferSize, byte]
    bufDstToSrc: array[bufferSize, byte]
    futSrc = srcStream.readOnce(addr bufSrcToDst[0], bufSrcToDst.len)
    futDst = dstStream.readOnce(addr bufDstToSrc[0], bufDstToSrc.len)
    srcEof = false
    dstEof = false
    bufRead: int

  defer:
    await noCancel allFutures(futSrc.cancelAndWait(), futDst.cancelAndWait())

  try:
    while (not srcEof or not dstEof) and not srcStream.closed() and
        not dstStream.closed():
      try:
        if srcEof:
          discard await futDst
        elif dstEof:
          discard await futSrc
        else:
          discard await race(futSrc, futDst)
      except ValueError as e:
        raiseAssert("Futures list is not empty: " & e.msg)

      if not srcEof and futSrc.finished():
        bufRead = await futSrc
        if bufRead > 0:
          await dstStream.write(@bufSrcToDst[0 ..< bufRead])
          zeroMem(addr bufSrcToDst[0], bufSrcToDst.len)
          futSrc = srcStream.readOnce(addr bufSrcToDst[0], bufSrcToDst.len)
        else:
          # src half-closed its write side - propagate EOF to dst and keep
          # relaying data from dst to src
          srcEof = true
          await dstStream.closeWrite()

      if not dstEof and futDst.finished():
        bufRead = await futDst
        if bufRead > 0:
          await srcStream.write(bufDstToSrc[0 ..< bufRead])
          zeroMem(addr bufDstToSrc[0], bufDstToSrc.len)
          futDst = dstStream.readOnce(addr bufDstToSrc[0], bufDstToSrc.len)
        else:
          dstEof = true
          await srcStream.closeWrite()
  except CancelledError as exc:
    raise exc
  except LPStreamError:
    discard

proc start*(self: TorServerStub, address: TransportAddress) {.async.} =
  await self.tcpTransport.start(@[ma(address)])

  var msg = newSeq[byte](3)
  while self.tcpTransport.running:
    let connSrc = await self.tcpTransport.accept()
    defer:
      await noCancel connSrc.close()
    await connSrc.readExactly(addr msg[0], 3)

    await connSrc.write(@[05'u8, 00])

    msg = newSeq[byte](4)
    await connSrc.readExactly(addr msg[0], 4)
    let atyp = msg[3]
    let address =
      case atyp
      of Socks5AddressType.IPv4.byte:
        let n = 4 + 2 # +2 bytes for the port
        msg = newSeq[byte](n)
        await connSrc.readExactly(addr msg[0], n)
        var ip: array[4, byte]
        for i, e in msg[0 ..^ 3]:
          ip[i] = e
        $(IpAddress(family: IPv4, address_v4: ip)) & ":" &
          $(Port(fromBytesBE(uint16, msg[^2 ..^ 1])))
      of Socks5AddressType.IPv6.byte:
        let n = 16 + 2 # +2 bytes for the port
        msg = newSeq[byte](n) # +2 bytes for the port
        await connSrc.readExactly(addr msg[0], n)
        var ip: array[16, byte]
        for i, e in msg[0 ..^ 3]:
          ip[i] = e
        $(IpAddress(family: IPv6, address_v6: ip)) & ":" &
          $(Port(fromBytesBE(uint16, msg[^2 ..^ 1])))
      of Socks5AddressType.FQDN.byte:
        await connSrc.readExactly(addr msg[0], 1)
        let n = int(uint8.fromBytes(msg[0 .. 0])) + 2 # +2 bytes for the port
        msg = newSeq[byte](n)
        await connSrc.readExactly(addr msg[0], n)
        string.fromBytes(msg[0 ..^ 3]) & ":" &
          $(Port(fromBytesBE(uint16, msg[^2 ..^ 1])))
      else:
        raise newException(LPError, "Address not supported")

    let tcpIpAddr = self.addrTable[$(address)]

    await connSrc.write(@[05'u8, 00, 00, 01, 00, 00, 00, 00, 00, 00])

    let connDst = await self.tcpTransport.dial("", ma(tcpIpAddr))
    defer:
      await noCancel connDst.close()

    await bridge(connSrc, connDst)

proc stop*(self: TorServerStub) {.async.} =
  await self.tcpTransport.stop()
