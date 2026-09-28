# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import results, times

func digit(value: string, index: int): int =
  ord(value[index]) - ord('0')

func decimal(value: string, first, last: int): int =
  for index in first .. last:
    result = result * 10 + value.digit(index)

proc parseRfc3339DateTime*(value: string): Result[DateTime, string] =
  ## Parses an RFC 3339 timestamp and normalizes it to UTC. Fractions more precise
  ## than Nim's nanosecond-resolution DateTime are truncated.
  template invalid(): untyped =
    return err("Invalid RFC 3339 date-time: " & value)

  if value.len < 20:
    invalid()

  for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]:
    if value[index] notin {'0' .. '9'}:
      invalid()
  if value[4] != '-' or value[7] != '-' or value[10] notin {'T', 't'} or value[13] != ':' or
      value[16] != ':':
    invalid()

  let
    year = value.decimal(0, 3)
    month = value.decimal(5, 6)
    monthday = value.decimal(8, 9)
    hour = value.decimal(11, 12)
    minute = value.decimal(14, 15)
    second = value.decimal(17, 18)

  if month notin 1 .. 12 or monthday < 1 or hour > 23 or minute > 59 or second > 60:
    invalid()
  let parsedMonth = Month(month)
  if monthday > getDaysInMonth(parsedMonth, year):
    invalid()

  var
    index = 19
    nanosecond = 0
  if value[index] == '.':
    inc index
    let fractionStart = index
    while index < value.len and value[index] in {'0' .. '9'}:
      if index - fractionStart < 9:
        nanosecond = nanosecond * 10 + value.digit(index)
      inc index
    let fractionDigits = index - fractionStart
    if fractionDigits == 0:
      invalid()
    for _ in fractionDigits ..< 9:
      nanosecond *= 10

  var offsetMinutes = 0
  if index < value.len and value[index] in {'Z', 'z'}:
    if index + 1 != value.len:
      invalid()
  elif index + 6 == value.len and value[index] in {'+', '-'} and
      value[index + 1] in {'0' .. '9'} and value[index + 2] in {'0' .. '9'} and
      value[index + 3] == ':' and value[index + 4] in {'0' .. '9'} and
      value[index + 5] in {'0' .. '9'}:
    let
      offsetHours = value.decimal(index + 1, index + 2)
      offsetMinutePart = value.decimal(index + 4, index + 5)
    if offsetHours > 23 or offsetMinutePart > 59:
      invalid()
    offsetMinutes = offsetHours * 60 + offsetMinutePart
    if value[index] == '-':
      offsetMinutes = -offsetMinutes
  else:
    invalid()

  let utcDateTime =
    dateTime(
      year, parsedMonth, monthday, hour, minute, min(second, 59), nanosecond, utc()
    ) - initDuration(minutes = offsetMinutes)

  if second == 60:
    if utcDateTime.hour != 23 or utcDateTime.minute != 59 or
        utcDateTime.monthday != getDaysInMonth(utcDateTime.month, utcDateTime.year):
      invalid()
    return ok(utcDateTime + initDuration(seconds = 1))

  ok(utcDateTime)
