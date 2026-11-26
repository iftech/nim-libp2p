{.used.}
## # Custom protocol in libp2p
##
## In the [previous tutorial](tutorial_1_connect.md), we've looked at how to create a simple ping program using the `nim-libp2p`.
##
## We'll now look at how to create a custom protocol inside the libp2p
##
## Let's create a `part2.nim`, and import our dependencies:
import chronos
import stew/byteutils

import libp2p
## This is similar to the first tutorial, except we don't need to import the `Ping` protocol.
##
## Next, we'll declare our custom protocol
const TestCodec = "/test/proto/1.0.0"

type TestProto = ref object of LPProtocol

## We've set a [protocol ID](https://libp2p.io/docs/protocols/#protocol-ids), and created a custom `LPProtocol`. In a more complex protocol, we could use this structure to store interesting variables.
##
## A protocol generally has two parts: a handling/server part, and a dialing/client part.
## These two parts can be identical, but in our trivial protocol, the server will wait for a message from the client, and the client will send a message, so we have to handle the two cases separately.
##
## Let's start with the server part:

proc new(T: typedesc[TestProto]): T =
  # every incoming stream will be handled in this closure
  proc handle(stream: Stream, proto: string) {.async: (raises: [CancelledError]).} =
    # Read up to 1024 bytes from this stream, and transform them into
    # a string
    try:
      echo "Got from remote - ", string.fromBytes(await stream.readLp(1024))
    except LPStreamError as exc:
      echo "exception in handler", exc.msg
    finally:
      await stream.close()

  return T.new(codecs = @[TestCodec], handler = handle)

## This is a constructor for our `TestProto`, that will specify our `codecs` and a `handler`, which will be called for each incoming peer asking for this protocol.
## In our handle, we simply read a message from the stream and `echo` it.
##
## We can now create our client part:
proc hello(p: TestProto, stream: Stream) {.async.} =
  await stream.writeLp("Hello p2p!")

proc createSwitch(rng: Rng): Switch {.raises: [LPError].} =
  return SwitchBuilder
    .new()
    .withRng(rng)
    .withAddress(MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet())
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

## Again, pretty straightforward, we just send a message on the stream.
##
## We can now create our main procedure:
proc main() {.async.} =
  let
    rng = newRng()
    switch1 = createSwitch(rng)
    switch2 = createSwitch(rng)
    testProto = TestProto.new()

  switch1.mount(testProto)

  await switch1.start()
  await switch2.start()

  let stream =
    await switch2.dial(switch1.peerInfo.peerId, switch1.peerInfo.addrs, TestCodec)

  await testProto.hello(stream)

  # We must close the stream ourselves when we're done with it
  await stream.close()

  await allFutures(switch1.stop(), switch2.stop())
    # close connections and shutdown all transports

## This is very similar to the first tutorial's `main`.
##
## We can now wrap our program by calling our main proc:
waitFor(main())

## And that's it!
## In the [next tutorial](tutorial_3_protobuf.md), we'll create a more complex protocol using Protobuf.
