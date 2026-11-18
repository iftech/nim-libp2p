# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Platform-specific socket options used by the mDNS multicast transport.

when defined(windows):
  import ./socketoptions/windows
  export windows
else:
  import ./socketoptions/posix
  export posix
