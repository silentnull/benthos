你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
![Benthos](icon.png "Benthos")

[![godoc for Jeffail/benthos][godoc-badge]][godoc-url]
[![goreportcard for Jeffail/benthos][goreport-badge]][goreport-url]
[![Build Status][drone-badge]][drone-url]

Benthos is a high performance and resilient message streaming service, able to
connect various sources and sinks and perform arbitrary
[actions, transformations and filters][processors] on payloads. It is easy to
deploy and monitor, and ready to drop into your pipeline either as a static
binary or a docker image. It can also be used as a [framework][godoc-url] for
building your own resilient stream processors in Go.

A Benthos stream consists of four layers: [inputs][inputs], optional
[buffer][buffers], [processor][processors] workers and [outputs][outputs].
Inputs and outputs can be combined in a range of broker patterns. It is possible
to run multiple isolated streams within a single Benthos instance using
[`--streams` mode][streams-mode], and perform CRUD operations on the running
streams via [REST endpoints][streams-api].

### Delivery Guarantees

Benthos is crash resilient by default. When connecting to at-least-once sources
and sinks without a buffer it guarantees at-least-once delivery without needing
to persist messages during transit.

When running a Benthos stream with a [buffer][buffers] there are various options
for choosing a level of resiliency that meets your needs.

### Serverless

There are [specialised distributions][serverless] of Benthos for serverless
deployment.

## Supported Sources & Sinks

- [AWS (DynamoDB, Kinesis, S3, SQS)][aws]
- [Elasticsearch][elasticsearch] (output only)
- File
- [GCP (pub/sub)][gcp]
- [HDFS][hdfs]
- HTTP(S)
- [Kafka][kafka]
- [Memcached][memcached] (output only)
- [MQTT][mqtt]
- [Nanomsg][nanomsg]
- [NATS][nats]
- [NATS Streaming][natsstreaming]
- [NSQ][nsq]
- [RabbitMQ (AMQP 0.91)][rabbitmq]
- [Redis (streams, list, pubsub)][redis]
- Stdin/Stdout
- Websocket
- [ZMQ4][zmq]

## Documentation

Documentation for Benthos components, concepts and recommendations can be found
on the [documentation site][general-docs], or within the repo at the
[docs directory][docs-dir].

For guidance on how to configure more advanced stream processing concepts such
as stream joins, enrichment workflows, etc, check out the
[cookbooks section.][cookbooks]

For guidance on building your own custom plugins check out
[this example repo.][plugin-repo]

## Run

``` shell
benthos -c ./config.yaml
```

Or, with docker:

``` shell
# Send HTTP /POST data to Kafka:
docker run --rm \
	-e "INPUT_TYPE=http_server" \
	-e "OUTPUT_TYPE=kafka" \
	-e "OUTPUT_KAFKA_ADDRESSES=kafka-server:9092" \
	-e "OUTPUT_KAFKA_TOPIC=benthos_topic" \
	-p 4195:4195 \
	jeffail/benthos

# Using your own config file:
docker run --rm -v /path/to/your/config.yaml:/benthos.yaml jeffail/benthos
```

## Monitoring

### Health Checks

Benthos serves two HTTP endpoints for health checks:
- `/ping` can be used as a liveness probe as it always returns a 200.
- `/ready` can be used as a readiness probe as it serves a 200 only when both
  the input and output are connected, otherwise a 503 is returned.

### Metrics

Benthos [exposes lots of metrics][metrics] either to Statsd, Prometheus or for
debugging purposes an HTTP endpoint that returns a JSON formatted object. The
target can be specified [via config][metrics-config].

### Tracing

Benthos also [emits opentracing events][tracers] to a tracer of your choice
(currently only [Jaeger][jaeger] is supported) which can be used to visualise
the processors within a pipeline.

## Configuration

The configuration file for a Benthos stream is made up of four main sections;
input, buffer, pipeline, output. If we were to pipe stdin directly to Kafka it
would look like this:

``` yaml
input:
  type: stdin
buffer:
  type: none
pipeline:
  threads: 1
  processors: []
output:
  type: kafka
  kafka:
    addresses:
    - localhost:9092
    topic: benthos_stream
```

There are also sections for setting logging, metrics and HTTP server options.

Benthos provides lots of tools for making configuration discovery, debugging and
organisation easy. You can [read about them here][config-doc].

You can also find runnable example configs demonstrating each input, output,
buffer and processor option [here](config).

### Environment Variables

It is possible to select fields inside a configuration file to be set via
[environment variables][config-interp]. The docker image, for example, is built
with [a config file][env-config] where _all_ common fields can be set this way.

## Install

Grab a binary for your OS from [here.][releases]

Or pull the docker image:

``` shell
docker pull jeffail/benthos
```

Build with Go (1.11 or later):

``` shell
git clone git@github.com:Jeffail/benthos
cd benthos
make
```

### Plugins

It's pretty easy to write your own custom plugins for Benthos, take a look at
[this repo][plugin-repo] for examples and build instructions.


### Docker Builds

There's a multi-stage `Dockerfile` for creating a Benthos docker image which
results in a minimal image from scratch. You can build it with:

``` shell
make docker
```

Then use the image:

``` shell
docker run --rm \
	-v /path/to/your/benthos.yaml:/config.yaml \
	-v /tmp/data:/data \
	-p 4195:4195 \
	benthos -c /config.yaml
```

There are a [few examples here][compose-examples] that show you some ways of
setting up Benthos containers using `docker-compose`.

### ZMQ4 Support

Benthos supports ZMQ4 for both data input and output. To add this you need to
install libzmq4 and use the compile time flag when building Benthos:

``` shell
make TAGS=ZMQ4
```

Or to build a docker image using CGO, which includes ZMQ:

``` shell
make docker-cgo
```

## Contributing

Contributions are welcome, please [read the guidelines](CONTRIBUTING.md).

[inputs]: https://docs.benthos.dev/inputs/
[buffers]: https://docs.benthos.dev/buffers/
[processors]: https://docs.benthos.dev/processors/
[outputs]: https://docs.benthos.dev/outputs/

[metrics]: https://docs.benthos.dev/metrics/
[tracers]: https://docs.benthos.dev/tracers/
[metrics-config]: config/metrics
[config-interp]: https://docs.benthos.dev/config_interpolation/
[compose-examples]: resources/docker/compose_examples
[streams-api]: https://docs.benthos.dev/api/streams/
[streams-mode]: https://docs.benthos.dev/streams/
[general-docs]: https://docs.benthos.dev
[examples-docs]: https://docs.benthos.dev/examples/
[env-config]: config/env/README.md
[config-doc]: https://docs.benthos.dev/configuration/
[serverless]: https://docs.benthos.dev/serverless/
[cookbooks]: https://docs.benthos.dev/cookbooks/
[docs-dir]: docs/README.md

[releases]: https://github.com/Jeffail/benthos/releases
[plugin-repo]: https://github.com/benthosdev/benthos-plugin-example

[godoc-badge]: https://godoc.org/github.com/Jeffail/benthos/lib/stream?status.svg
[godoc-url]: https://godoc.org/github.com/Jeffail/benthos/lib/stream
[goreport-badge]: https://goreportcard.com/badge/github.com/Jeffail/benthos
[goreport-url]: https://goreportcard.com/report/Jeffail/benthos
[drone-badge]: https://cloud.drone.io/api/badges/Jeffail/benthos/status.svg
[drone-url]: https://cloud.drone.io/Jeffail/benthos

[aws]: https://aws.amazon.com/
[zmq]: http://zeromq.org/
[nanomsg]: http://nanomsg.org/
[rabbitmq]: https://www.rabbitmq.com/
[mqtt]: http://mqtt.org/
[nsq]: http://nsq.io/
[nats]: http://nats.io/
[natsstreaming]: https://nats.io/documentation/streaming/nats-streaming-intro/
[redis]: https://redis.io/
[kafka]: https://kafka.apache.org/
[elasticsearch]: https://www.elastic.co/
[hdfs]: https://hadoop.apache.org/
[gcp]: https://cloud.google.com/
[memcached]: https://memcached.org/
[jaeger]: https://www.jaegertracing.io/
