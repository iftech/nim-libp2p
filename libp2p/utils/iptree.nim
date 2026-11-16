# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import std/net
import stew/bitops2

type
  IpTreeNode* = ref object
    counter*: int
    left*, right*: IpTreeNode

  IpTree* = ref object
    root*: IpTreeNode ## IPv4 tree root: a 32-level binary tree.
    root6*: IpTreeNode ## IPv6 tree root: a 128-level binary tree.

proc new*(T: typedesc[IpTree]): T =
  T(root: IpTreeNode(counter: 0), root6: IpTreeNode(counter: 0))

proc ipBytes(ip: IpAddress): seq[uint8] {.raises: [].} =
  case ip.family
  of IpAddressFamily.IPv4:
    @(ip.address_v4)
  of IpAddressFamily.IPv6:
    @(ip.address_v6)

proc treeRoot(ipTree: IpTree, ip: IpAddress): IpTreeNode =
  case ip.family
  of IpAddressFamily.IPv4: ipTree.root
  of IpAddressFamily.IPv6: ipTree.root6

proc step(v: IpTreeNode, goRight: bool, create: bool): IpTreeNode =
  ## Returns the child of `v` in the direction given by `goRight`. With
  ## `create`, a missing child is allocated and linked in, so the result is
  ## never nil; otherwise a missing child yields nil.
  var nxt = if goRight: v.right else: v.left
  if nxt.isNil and create:
    nxt = IpTreeNode(counter: 0)
    if goRight:
      v.right = nxt
    else:
      v.left = nxt
  nxt

proc insertIp*(ipTree: IpTree, ip: IpAddress) {.raises: [].} =
  ## Inserts an IP address into the IP tree, following its binary
  ## representation and incrementing counters at each visited node.
  ## IPv4 addresses walk the 32-level tree,
  ## IPv6 addresses walk the 128-level tree.
  var v = ipTree.treeRoot(ip)
  v.counter += 1

  let bytes = ip.ipBytes()

  for b in bytes:
    for bit in countdown(7, 0):
      let goRight = (b and (1'u8 shl bit)) != 0
      v = step(v, goRight, create = true)
      v.counter += 1

proc insertIps*(ipTree: IpTree, ips: seq[IpAddress]) {.raises: [].} =
  for ip in ips:
    ipTree.insertIp(ip)

proc removeIp*(ipTree: IpTree, ip: IpAddress) {.raises: [].} =
  ## Removes an IP address from the IP tree by decrementing counters along
  ## its binary-representation path, from the root through the leaf.
  ## Counters never go below zero. Any trailing run of nodes left at counter
  ## 0 with no children is unlinked, so a fully-removed address doesn't leave
  ## dead nodes behind.
  let root = ipTree.treeRoot(ip)
  if root.counter == 0:
    return

  let bytes = ip.ipBytes()

  # path[0] is the root; path[i] for i > 0 is the node reached after the
  # i-th bit. Sized for the deepest case (IPv6: root + 128 levels).
  var path: array[129, IpTreeNode]
  path[0] = root
  var pathLen = 1

  var v = root
  for b in bytes:
    for bit in countdown(7, 0):
      let goRight = (b and (1'u8 shl bit)) != 0
      v = step(v, goRight, create = false)
      if v.isNil or v.counter == 0:
        return

      path[pathLen] = v
      inc pathLen

  # Every node visited above has counter > 0 (checked as it was added to
  # path), so this can't underflow.
  for j in 0 ..< pathLen:
    dec path[j].counter

  # Prune the trailing run of now-empty leaves: walk from the leaf back
  # toward the root, unlinking any node left with counter == 0 and no
  # children, stopping at the first node that still has either.
  for i in countdown(pathLen - 1, 1):
    let n = path[i]
    if n.counter > 0 or not n.left.isNil or not n.right.isNil:
      break
    let parent = path[i - 1]
    if parent.left == n:
      parent.left = nil
    else:
      parent.right = nil

proc removeIps*(ipTree: IpTree, ips: seq[IpAddress]) {.raises: [].} =
  for ip in ips:
    ipTree.removeIp(ip)

proc ipsLen*(ipTree: IpTree): int {.raises: [].} =
  ## Total IP multi-set size (IPv4 + IPv6 root counters).
  ipTree.root.counter + ipTree.root6.counter

func prefixLen(a, b: openArray[uint8]): int =
  for i in 0 ..< a.len:
    let x = a[i] xor b[i]
    if x != 0:
      return i * 8 + leadingZeros(x)
  a.len * 8

func commonPrefixLen(a, b: IpAddress): int =
  if a.family != b.family:
    return 0
  case a.family
  of IpAddressFamily.IPv4:
    prefixLen(a.address_v4, b.address_v4)
  of IpAddressFamily.IPv6:
    prefixLen(a.address_v6, b.address_v6)

proc ipScore*(
    ipTree: IpTree, ip: IpAddress, exclude: openArray[IpAddress] = []
): float64 {.raises: [].} =
  ## Sybil score of `ip`, as if each IP in `exclude` (all in the tree) were removed.
  var divergesAt: array[129, int]
  var excluded = 0
  for e in exclude:
    if e.family == ip.family:
      inc excluded
      inc divergesAt[commonPrefixLen(ip, e)]

  let root = ipTree.treeRoot(ip)
  if root.counter - excluded <= 0:
    return 0.0

  var v = root
  var score = 0
  var depth = 0
  let total = float64(root.counter - excluded)
  let bytes = ip.ipBytes()
  let nBits = bytes.len * 8

  var threshold = total * 0.5
  for b in bytes:
    for bit in countdown(7, 0):
      let goRight = (b and (1'u8 shl bit)) != 0
      v = step(v, goRight, create = false)

      if v.isNil:
        return (float64(score) / float64(nBits))

      excluded -= divergesAt[depth]
      inc depth
      let effective = max(v.counter - excluded, 0)
      if float64(effective) > threshold:
        score += 1

      threshold *= 0.5

  (float64(score) / float64(nBits))

proc ipsMaxScore*(
    ipTree: IpTree, ips: seq[IpAddress], exclude: openArray[IpAddress] = []
): float64 {.raises: [].} =
  ## Max IP similarity score across the given addresses.
  if ips.len < 1:
    return 1.0

  var maxScore = 0.0
  for ip in ips:
    let score = ipTree.ipScore(ip, exclude)
    if score > maxScore:
      maxScore = score

  return maxScore
