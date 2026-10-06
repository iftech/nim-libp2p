# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

type
  GroupId* = seq[byte]
    ## Identifies a logical *full message* that partial message belongs to.
    ##
    ## The identifier must be derivable without access to the complete message
    ## (for example, it must not be a hash of the full message). All parts or
    ## views of the same logical message MUST use the same GroupId.

  PartsData* = seq[byte]
    ## Encoded message data containing zero or more parts of a logical *full message*.
    ##
    ## The data may represent a complete message, a partial message, or be empty.
    ## The encoding and structure of the parts are application-defined.

  PartsMetadata* = seq[byte]
    ## Opaque, encoded metadata describing the parts of a logical *full message*.
    ##
    ## This metadata MAY describe:
    ## - Parts that are currently available
    ## - Parts that are requested or missing
    ## - Or both, implicitly or explicitly
    ##
    ## The interpretation and encoding of this metadata are entirely
    ## application-defined.

proc `$`*(g: GroupId): string =
  return cast[string](g)
