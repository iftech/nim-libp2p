# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import ../../../libp2p/utils/opt
import ../../tools/unittest

type ModuloValue = distinct int

func `==`(left, right: ModuloValue): bool =
  int(left) mod 10 == int(right) mod 10

suite "Opt comparisons":
  test "plain values compare symmetrically and inequality negates equality":
    for option in [Opt.none(int), Opt.some(3), Opt.some(4)]:
      for value in [3, 4]:
        let expected = option.isSome and option.get() == value
        check:
          (option == value) == expected
          (value == option) == expected
          (option != value) == not expected
          (value != option) == not expected

  test "option-to-option comparisons retain presence and value semantics":
    for left in [Opt.none(int), Opt.some(3), Opt.some(4)]:
      for right in [Opt.none(int), Opt.some(3), Opt.some(4)]:
        let expected =
          left.isSome == right.isSome and (left.isNone or left.get() == right.get())
        check:
          (left == right) == expected
          (left != right) == not expected

  test "nested options retain option-to-option equality":
    let empty = Opt.none(Opt[int])
    let present = Opt.some(Opt.none(int))
    check:
      empty == Opt.none(Opt[int])
      present == Opt.some(Opt.none(int))
      empty != present
      present != Opt.some(Opt.some(3))

  test "strings and sequences compare their payloads":
    check:
      Opt.some("value") == "value"
      "value" != Opt.none(string)
      Opt.some(@[1, 2]) == @[1, 2]
      @[1, 2] != Opt.some(@[2, 1])

  test "a present nil reference differs from an empty option":
    let value: ref int = nil
    check:
      Opt.some(value) == value
      value == Opt.some(value)
      Opt.none(ref int) != value
      value != Opt.none(ref int)

  test "payload equality uses the type's comparison":
    check:
      Opt.some(ModuloValue(13)) == ModuloValue(3)
      ModuloValue(3) == Opt.some(ModuloValue(13))
      Opt.some(ModuloValue(13)) != ModuloValue(4)

  test "each operand is evaluated once":
    var optionCalls, valueCalls: int
    proc option(): Opt[int] =
      inc optionCalls
      Opt.none(int)

    proc value(): int =
      inc valueCalls
      3

    check:
      option() != value()
      optionCalls == 1
      valueCalls == 1
      value() != option()
      optionCalls == 2
      valueCalls == 2
      not (option() == value())
      optionCalls == 3
      valueCalls == 3
      not (value() == option())
      optionCalls == 4
      valueCalls == 4
