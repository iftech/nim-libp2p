# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import sequtils, sets, chronos
import ../../../libp2p/[protocols/rendezvous, protocols/rendezvous/protobuf, peerid]
import ../../tools/[unittest, crypto]

proc registration(ns: string, expiration: Moment): RegisteredData =
  RegisteredData(
    expiration: expiration, peerId: PeerId.random(), data: Register(ns: ns)
  )

proc filled(namespaces: openArray[string], expiration: Moment): RegistrationStore =
  var store = RegistrationStore()
  for ns in namespaces:
    let expected = store.nextId()
    check store.add(registration(ns, expiration)) == expected
  store

proc ids(store: RegistrationStore): seq[RegistrationId] =
  store.toSeq().mapIt(it.id)

suite "RendezVous registration store":
  test "An empty store starts at id 0":
    var store = RegistrationStore()

    check:
      store.len == 0
      store.firstId() == 0
      store.nextId() == 0
      0.RegistrationId notin store
      store.dropExpired(Moment.now()).len == 0

  test "add returns the next id":
    var store = RegistrationStore()
    let later = Moment.now() + 1.hours

    check:
      store.add(registration("a", later)) == 0
      store.add(registration("b", later)) == 1
      store.ids() == @[0.RegistrationId, 1]
      store.nextId() == 2

  test "dropExpired keeps the live registrations intact":
    let
      now = Moment.now()
      later = now + 1.hours
    var store = filled(["a", "b", "c", "d"], later)
    store[0].expiration = now - 1.seconds
    store[2].expiration = now - 1.seconds

    check:
      store.dropExpired(now) == [0.RegistrationId, 2].toHashSet()
      store.ids() == @[1.RegistrationId, 3]
      store[1].data.ns == "b"
      store[3].data.ns == "d"
      0.RegistrationId notin store
      2.RegistrationId notin store
      store.firstId() == 1
      store.nextId() == 4

  test "Dropping every registration keeps the ids growing":
    let now = Moment.now()
    var store = filled(["a", "b"], now - 1.seconds)

    check:
      store.dropExpired(now).len == 2
      store.len == 0
      store.firstId() == 2
      store.add(registration("c", now + 1.hours)) == 2

  test "entriesFrom starts at the first id not below the given one":
    let now = Moment.now()
    var store = filled(["a", "b", "c", "d", "e"], now + 1.hours)
    store[2].expiration = now - 1.seconds
    check store.dropExpired(now) == [2.RegistrationId].toHashSet()

    check:
      toSeq(store.entriesFrom(0)).mapIt(it.id) == @[0.RegistrationId, 1, 3, 4]
      toSeq(store.entriesFrom(2)).mapIt(it.id) == @[3.RegistrationId, 4]
      toSeq(store.entriesFrom(4)).mapIt(it.id) == @[4.RegistrationId]
      toSeq(store.entriesFrom(5)).len == 0

  test "remove deletes one id and ignores an unknown id":
    var store = filled(["a", "b", "c"], Moment.now() + 1.hours)

    store.remove(1)
    store.remove(7)

    check:
      store.ids() == @[0.RegistrationId, 2]
      1.RegistrationId notin store
      store.nextId() == 3
