# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

when defined(nimdoc):
  ## Welcome to the nim-libp2p reference!
  ##
  ## If you're new to nim-libp2p, you can find a tutorial `here<https://vacp2p.github.io/nim-libp2p/tutorial_1_connect/>`_
  ## that can help you get started.

  # Import stuff for doc
  import
    libp2p/[
      switch,
      stream/lpstream,
      builders,
      transports/tcptransport,
      transports/wstransport,
      protocols/ping,
      protocols/pubsub,
      peerid,
      peerinfo,
      peerstore,
      multiaddress,
    ]
else:
  import
    libp2p/[
      muxers/muxer,
      muxers/mplex/mplex,
      stream/lpstream,
      stream/bufferstream,
      stream/connection,
      transports/transport,
      transports/tcptransport,
      transports/quictransport,
      protocols/secure/noise,
      cid,
      multihash,
      multicodec,
      logging,
      errors,
      switch,
      peerid,
      peerinfo,
      multiaddress,
      builders,
      crypto/crypto,
      protocols/pubsub,
    ]

  export
    switch, peerid, peerinfo, connection, multiaddress, crypto, lpstream, bufferstream,
    muxer, mplex, transport, tcptransport, noise, errors, cid, multihash, multicodec,
    logging, builders, pubsub, quictransport
