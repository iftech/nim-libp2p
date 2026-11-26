# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import metrics

template readMetricValue(read: untyped): float64 =
  block:
    {.push warning[Deprecated]: off.}
    let value =
      try:
        read
      except KeyError:
        0.0
    {.pop.}
    value

template metricValue*(collector: untyped, labelValues: untyped = []): float64 =
  readMetricValue(collector.value(labelValues))

template metricValueByName*(
    collector: untyped, metricName: string, labelValues: untyped = []
): float64 =
  readMetricValue(collector.valueByName(metricName, labelValues))
