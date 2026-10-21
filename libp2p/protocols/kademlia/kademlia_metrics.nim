# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import metrics

export metrics

# Message metrics
declarePublicCounter kad_messages_sent, "kad messages sent", ["type"]
declarePublicCounter kad_messages_received, "kad messages received", ["type"]
declarePublicCounter kad_message_bytes_sent, "kad message bytes sent", ["type"]
declarePublicCounter kad_message_bytes_received, "kad message bytes received", ["type"]
declarePublicHistogram kad_message_duration_ms,
  "kad message round trip duration in milliseconds",
  ["type"],
  buckets = [10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0]
declarePublicCounter kad_responses_with_closer_peers,
  "responses with closer peers", ["type"]

# Outbound stream reuse metrics
declarePublicCounter kad_streams_opened, "outbound RPC streams opened"
declarePublicCounter kad_stream_reuses, "outbound RPCs sent on an already open stream"
declarePublicCounter kad_stream_reuse_failures,
  "reused outbound streams that failed and were retried on a fresh stream"
declarePublicCounter kad_streams_dropped,
  "open outbound streams given up because the stream closed under us"

# Lookup metrics
declarePublicCounter kad_lookup_followups,
  "iterative lookups that entered the k-closest follow-up phase"

# Provider record metrics
declarePublicCounter kad_provider_rejections_sent,
  "ADD_PROVIDER messages rejected due to a per-key or per-peer limit"
declarePublicCounter kad_provider_spillover_rounds,
  "ADD_PROVIDER spillover rounds (batch of candidates fully rejected)"
declarePublicCounter kad_provider_republish_regions,
  "keyspace regions republished, one DHT walk each"
declarePublicCounter kad_provider_republish_keys, "provided keys republished"
declarePublicGauge kad_network_size_estimate,
  "estimated network size from lookup closest-peer distances"

# Routing table metrics
declarePublicGauge kad_routing_table_peers, "total peers in routing table"
declarePublicGauge kad_routing_table_buckets, "number of buckets"
declarePublicGauge kad_routing_table_bucket_size, "peers per bucket", ["bucket"]
declarePublicCounter kad_routing_table_insertions, "peer insertions"
declarePublicCounter kad_routing_table_replacements, "peer replacements"
declarePublicCounter kad_routing_table_evictions, "peer evictions", ["reason"]
declarePublicCounter kad_routing_table_liveness_probes,
  "routing-table liveness probes", ["result"]
declarePublicCounter kad_admission_probes_backed_off,
  "admission probes skipped because the peer's last probe failed"
declarePublicCounter kad_admission_probes_dropped,
  "admission probes skipped because no probe slot was free"
declarePublicCounter kad_lookup_undialable_peers,
  "lookup shortlist peers dropped for having no address in the peer store"
declarePublicCounter kad_routing_table_reseeds,
  "re-seed attempts triggered by a peer count below the minimum"
