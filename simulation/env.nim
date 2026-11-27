# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import strutils, os
import chronos, metrics/chronos_httpserver, chronicles
from nativesockets import getHostname

let
  prometheusPort* = Port(8008) #prometheus metrics
  myPort* = Port(5000) #libp2p port
  chunks* = parseInt(getEnv("FRAGMENTS", "1")) #No. of fragments for each message

proc getPeerDetails*(): Result[(string, int, string), string] =
  let
    hostname = getHostname()
    connectTo = parseInt(getEnv("CONNECTTO", "10"))
    address =
      if getEnv("TRANSPORT", "QUIC") == "QUIC":
        "/ip4/0.0.0.0/udp/" & $myPort & "/quic-v1"
      else:
        "/ip4/0.0.0.0/tcp/" & $myPort
  info "Host info ", address = address
  return ok((hostname, connectTo, address))

#Prometheus metrics
proc startMetricsServer*(
    serverIp: IpAddress, serverPort: Port
): Result[MetricsHttpServerRef, string] =
  info "Starting metrics HTTP server", serverIp = $serverIp, serverPort = $serverPort

  let metricsServerRes = MetricsHttpServerRef.new($serverIp, serverPort)
  if metricsServerRes.isErr():
    return err("metrics HTTP server start failed: " & $metricsServerRes.error)

  let server = metricsServerRes.value
  try:
    waitFor server.start()
  except CatchableError:
    return err("metrics HTTP server start failed: " & getCurrentExceptionMsg())

  info "Metrics HTTP server started", serverIp = $serverIp, serverPort = $serverPort
  ok(metricsServerRes.value)
