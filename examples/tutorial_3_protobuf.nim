{.used.}
## # Protobuf usage
##
## In the [previous tutorial](tutorial_2_customproto.md), we created a simple "ping" protocol.
## Most real protocol want their messages to be structured and extensible, which is why
## most real protocols use [protobuf](https://developers.google.com/protocol-buffers) to
## define their message structures.
##
## Here, we'll create a slightly more complex protocol, which parses & generate protobuf
## messages. Let's start by importing our dependencies, as usual:
import chronos
import results # for Opt[T]
import protobuf_serialization, protobuf_serialization/pkg/results

import libp2p

## ## Protobuf encoding & decoding
## This will be the structure of our messages:
## ```protobuf
## syntax = "proto2";
## 
## message MetricList {
##   message Metric {
##     string name = 1;
##     float value = 2;
##   }
##
##   repeated Metric metrics = 1;
## }
## ```
## We'll create our protobuf types, encoders & decoders, according to this format.
## To create the encoders & decoders, we are going to use 
## [nim-protobuf-serialization](https://github.com/status-im/nim-protobuf-serialization) library.
type
  Metric {.proto2.} = object
    name {.fieldNumber: 1.}: Opt[string]
    value {.fieldNumber: 2.}: Opt[float]

  MetricList {.proto2.} = object
    metrics {.fieldNumber: 1.}: seq[Metric]

{.push raises: [].}

func validate(m: Metric): Result[void, string] =
  # although `name` and `value` are optional, they should always be set.
  if m.name.isNone:
    return err("invalid Metric: Metric.name must be set")
  if m.value.isNone:
    return err("invalid Metric: Metric.value must be set")
  ok()

proc encode*(m: Metric): seq[byte] =
  Protobuf.encode(m)

proc decode*(_: type Metric, buf: seq[byte]): Result[Metric, string] =
  try:
    let m = Protobuf.decode(buf, Metric)
    # any metrics that is received (decoded) should be valid
    ?m.validate()
    ok(m)
  except SerializationError as e:
    err("failed to decode Metric from protobuf bytes. " & e.msg)

proc encode*(c: MetricList): seq[byte] =
  Protobuf.encode(c)

proc decode*(_: type MetricList, buf: seq[byte]): Result[MetricList, string] =
  try:
    ok(Protobuf.decode(buf, MetricList))
  except SerializationError as e:
    err("failed to decode MetricList from protobuf bytes. " & e.msg)

## ## Results instead of exceptions
## As you can see, this part of the program also uses Results instead of exceptions for error handling.
## We start by `{.push raises: [].}`, which will prevent every non-async function from raising
## exceptions.
##
## Then, we use [nim-result](https://github.com/arnetheduck/nim-result) to convey
## errors to function callers. A `Result[T, E]` will either hold a valid result of type
## T, or an error of type E.
##
## You can check if the call succeeded by using `res.isOk`, and then get the
## value using `res.value` or the error by using `res.error`.
##
## Another useful tool is `?`, which will unpack a Result if it succeeded,
## or if it failed, exit the current procedure returning the error.
##
## nim-result is packed with other functionalities that you'll find in the
## nim-result repository.
##
## Results and exception are generally interchangeable, but have different semantics
## that you may or may not prefer.
##
## ## Creating the protocol
## We'll next create a protocol, like in the last tutorial, to request these metrics from our host
type
  MetricCallback =
    proc(): Future[MetricList] {.async: (raises: [CancelledError]), gcsafe.}
  MetricProto = ref object of LPProtocol
    metricGetter: MetricCallback

proc new(_: typedesc[MetricProto], cb: MetricCallback): MetricProto =
  var res: MetricProto
  proc handle(stream: Stream, proto: ProtoCodec) {.async: (raises: [CancelledError]).} =
    try:
      let
        metrics = await res.metricGetter()
        asProtobuf = metrics.encode()
      await stream.writeLp(asProtobuf)
    except LPStreamError as exc:
      echo "exception in handler", exc.msg
    finally:
      await stream.close()

  res = MetricProto.new(@[ProtoCodec("/metric-getter/1.0.0")], handle)
  res.metricGetter = cb
  return res

proc fetch(p: MetricProto, stream: Stream): Future[MetricList] {.async.} =
  let protobuf = await stream.readLp(2048)
  # tryGet will raise an exception if the Result contains an error.
  # It's useful to bridge between exception-world and result-world
  return MetricList.decode(protobuf).tryGet()

proc createSwitch(rng: Rng): Switch {.raises: [LPError].} =
  return SwitchBuilder
    .new()
    .withRng(rng)
    .withAddress(MultiAddress.init("/ip4/0.0.0.0/tcp/0").tryGet())
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

## We can now create our main procedure:
proc main() {.async.} =
  let rng = newRng()
  proc randomMetricGenerator(): Future[MetricList] {.async: (raises: [CancelledError]).} =
    let metricCount = rng.generate(uint32) mod 16
    var metricList: MetricList
    for i in 0 ..< metricCount + 1:
      metricList.metrics.add(
        Metric(
          name: Opt.some("metric_" & $i),
          value: Opt.some(float(rng.generate(uint16)) / 1000.0),
        )
      )
    metricList

  let
    metricProto1 = MetricProto.new(randomMetricGenerator)
    metricProto2 = MetricProto.new(randomMetricGenerator)
    switch1 = createSwitch(rng)
    switch2 = createSwitch(rng)

  switch1.mount(metricProto1)

  await switch1.start()
  await switch2.start()

  let
    stream = await switch2.dial(
      switch1.peerInfo.peerId, switch1.peerInfo.addrs, metricProto2.codecs
    )
    metrics = await metricProto2.fetch(stream)
  await stream.close()

  for metric in metrics.metrics:
    echo metric.name.get(), " = ", metric.value.get()

  await allFutures(switch1.stop(), switch2.stop())
    # close connections and shutdown all transports

waitFor(main())

## If you run this program, you should see random metrics being sent from the switch1 to the switch2.
