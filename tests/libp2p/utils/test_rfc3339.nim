# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, times
import ../../../libp2p/utils/rfc3339
import ../../tools/unittest

suite "RFC 3339 date-time parser":
  test "parses whole seconds as UTC":
    let parsed = parseRfc3339DateTime("2026-08-21T12:00:00Z").get()

    check parsed == dateTime(2026, mAug, 21, 12, zone = utc())
    check parsed.timezone == utc()

  test "normalizes positive and negative offsets to UTC":
    check parseRfc3339DateTime("2026-08-21T14:30:00+02:30").get() ==
      dateTime(2026, mAug, 21, 12, zone = utc())
    check parseRfc3339DateTime("2026-08-21T07:00:00-05:00").get() ==
      dateTime(2026, mAug, 21, 12, zone = utc())
    check parseRfc3339DateTime("2026-01-01T00:30:00+01:00").get() ==
      dateTime(2025, mDec, 31, 23, 30, zone = utc())

  test "accepts fractions of arbitrary precision":
    let base = dateTime(2026, mAug, 21, 11, 36, 41, zone = utc())

    check parseRfc3339DateTime("2026-08-21T11:36:41.1Z").get() - base ==
      initDuration(milliseconds = 100)
    check parseRfc3339DateTime("2026-08-21T11:36:41.621940726Z").get() - base ==
      initDuration(nanoseconds = 621_940_726)
    check parseRfc3339DateTime("2026-08-21T11:36:41.6219407265Z").get() - base ==
      initDuration(nanoseconds = 621_940_726)

  test "accepts RFC 3339 lowercase separators and leap seconds":
    check parseRfc3339DateTime("2026-08-21t12:00:00z").get() ==
      dateTime(2026, mAug, 21, 12, zone = utc())
    check parseRfc3339DateTime("2016-12-31T23:59:60Z").get() ==
      dateTime(2017, mJan, 1, zone = utc())

  test "accepts valid calendar boundaries":
    let testCase = ["2024-02-29T00:00:00Z", "2026-12-31T23:59:59-00:00"]
    for value in testCase:
      check parseRfc3339DateTime(value).isOk()

  test "rejects missing or malformed date-time fields":
    let testCase = [
      "", "2026-08-21", "2026/08/21T12:00:00Z", "2026-08-21 12:00:00Z",
      "202x-08-21T12:00:00Z", "2026-0x-21T12:00:00Z", "2026-08-2xT12:00:00Z",
      "2026-08-21T1x:00:00Z", "2026-08-21T12:0x:00Z", "2026-08-21T12:00:0xZ",
    ]
    for value in testCase:
      check parseRfc3339DateTime(value).isErr()

  test "rejects out-of-range calendar and clock fields":
    let testCase = [
      "2026-00-21T12:00:00Z", "2026-13-21T12:00:00Z", "2026-08-00T12:00:00Z",
      "2026-02-29T12:00:00Z", "2026-04-31T12:00:00Z", "2026-08-21T24:00:00Z",
      "2026-08-21T12:60:00Z", "2026-08-21T12:00:61Z",
    ]
    for value in testCase:
      check parseRfc3339DateTime(value).isErr()

  test "rejects malformed fractions and trailing data":
    let testCase = [
      "2026-08-21T12:00:00.Z", "2026-08-21T12:00:00.aZ", "2026-08-21T12:00:00.1",
      "2026-08-21T12:00:00.1Zextra",
    ]
    for value in testCase:
      check parseRfc3339DateTime(value).isErr()

  test "rejects missing, malformed, and out-of-range offsets":
    let testCase = [
      "2026-08-21T12:00:00", "2026-08-21T12:00:00+12", "2026-08-21T12:00:00+1200",
      "2026-08-21T12:00:00+12:0x", "2026-08-21T12:00:00+24:00",
      "2026-08-21T12:00:00+12:60", "2026-08-21T12:00:00X", "2026-08-21T12:00:00ZZ",
    ]
    for value in testCase:
      check parseRfc3339DateTime(value).isErr()

  test "returns the rejected input in its error":
    let value = "not-a-date"

    check parseRfc3339DateTime(value).error == "Invalid RFC 3339 date-time: " & value
