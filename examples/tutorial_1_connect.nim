{.used.}
## # Simple ping tutorial
##
## Hi all, welcome to the first nim-libp2p tutorial!
##
## !!! tips ""
##     This tutorial is for everyone who is interested in building peer-to-peer applications. No Nim programming experience is needed.
##
## To give you a quick overview, **Nim** is the programming language we are using and **nim-libp2p** is the Nim implementation of [libp2p](https://libp2p.io/), a modular library that enables the development of peer-to-peer network applications.
##
## Hope you'll find it helpful in your journey of learning. Happy coding! ;)
##
## ## Before you start
## The only prerequisite here is [Nim](https://nim-lang.org/), the programming language with a Python-like syntax and a performance similar to C. Detailed information can be found [here](https://nim-lang.org/docs/tut1.html).
##
## Install Nim via their [official website](https://nim-lang.org/install.html).
## Check Nim's installation via `nim --version` and its package manager Nimble via `nimble --version`.
##
## You can now install the latest version of `nim-libp2p`:
## ```bash
## nimble install libp2p@#master
## ```
##
## ## A simple ping application
## We'll start by creating a simple application, which is starting two libp2p [switch](https://libp2p.io/docs/switch/), and pinging each other using the [Ping](https://libp2p.io/docs/protocols/#ping) protocol.
##
## !!! tips ""
##     You can find the source of this tutorial (and other tutorials) in the [libp2p/examples](https://github.com/status-im/nim-libp2p/tree/master/examples) folder!
##
## Let's create a `part1.nim`, and import our dependencies:
import chronos

import libp2p
import libp2p/protocols/ping

## [chronos](https://github.com/status-im/nim-chronos) the asynchronous framework used by `nim-libp2p`
##
## Next, we'll create a helper procedure to create our switches. A switch needs a bit of configuration, and it will be easier to do this configuration only once:
proc createSwitch(ma: MultiAddress, rng: Rng): Switch =
  var switch = SwitchBuilder
    .new()
    .withRng(rng)
    # Give the application RNG
    .withAddress(ma)
    # Our local address(es)
    .withTcpTransport()
    # Use TCP as transport
    .withMplex()
    # Use Mplex as muxer
    .withNoise()
    # Use Noise as secure manager
    .build()

  return switch

## This will create a switch using [Mplex](https://libp2p.io/docs/multiplexing-overview/) as a multiplexer, Noise to secure the communication, and TCP as an underlying transport.
##
## You can of course tweak this, to use a different or multiple transport, or tweak the configuration of Mplex and Noise, but this is some sane defaults that we'll use going forward.
##
##
## Let's now start to create our main procedure:
proc main() {.async.} =
  let
    rng = newRng()
    localAddress = MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet()
    pingProtocol = Ping.new(rng = rng)
  ## We created some variables that we'll need for the rest of the application: the global `rng` instance, our `localAddress`, and an instance of the `Ping` protocol.
  ## The address is in the [MultiAddress](https://github.com/multiformats/multiaddr) format. The port `0` means "take any port available".
  ##
  ## `tryGet` is procedure which is part of [nim-result](https://github.com/arnetheduck/nim-result/), that will throw an exception if the supplied MultiAddress is invalid.
  ##
  ## We can now create our two switches:
  let
    switch1 = createSwitch(localAddress, rng)
    switch2 = createSwitch(localAddress, rng)

  switch1.mount(pingProtocol)

  await switch1.start()
  await switch2.start()
  ## We've **mounted** the `pingProtocol` on our first switch. This means that the first switch will actually listen for any ping requests coming in, and handle them accordingly.
  ##
  ## Now that we've started the nodes, they are listening for incoming peers.
  ## We can find out which port was attributed, and the resulting local addresses, by using `switch1.peerInfo.addrs`.
  ##
  ## We'll **dial** the first switch from the second one, by specifying its **Peer ID**, its **MultiAddress** and the **`Ping` protocol codec**:
  let stream =
    await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, PingCodec)
  ## We now have a `Ping` stream setup between the second and the first switch, we can use it to actually ping the node:
  # ping the other node and echo the ping duration
  echo "ping: ", await pingProtocol.ping(stream)

  # We must close the stream ourselves when we're done with it
  await stream.close()
  ## And that's it! Just a little bit of cleanup: shutting down the switches, waiting for them to stop, and we'll call our `main` procedure:
  await allFutures(switch1.stop(), switch2.stop())
    # close connections and shutdown all transports

waitFor(main())

## You can now run this program using `nim c -r part1.nim`, and you should see the dialing sequence, ending with a ping output.
##
## In the [next tutorial](tutorial_2_customproto.md), we'll look at how to create our own custom protocol.
