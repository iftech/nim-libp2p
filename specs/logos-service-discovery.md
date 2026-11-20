# LOGOS-SERVICE-DISCOVERY

| Field | Value |
| --- | --- |
| Name | Logos Service Discovery Protocol |
| Slug | 107 |
| Status | raw |
| Category | Standards Track |
| Editor | Arunima Chaudhuri [arunima@status.im](mailto:arunima@status.im) |
| Contributors | Ugur Sen [ugur@status.im](mailto:ugur@status.im), Hanno Cornelius [hanno@status.im](mailto:hanno@status.im) |

<!-- timeline:start -->

## Timeline

- **2026-05-11** — [`1ac7689`](https://github.com/logos-co/logos-lips/blob/1ac7689ee3fe1665d5d5d1bf9c180ed951cc660d/docs/anoncomms/raw/logos-service-discovery.md) — chore: split ift ts specs (#334)
- **2026-04-15** — [`5a3e844`](https://github.com/logos-co/logos-lips/blob/5a3e844679a0ac60e6b4e945a64c2f7d8650cba5/docs/ift-ts/raw/logos-service-discovery.md) — Chore/move repo into logos co (#312)
- **2026-03-24** — [`513d8ea`](https://github.com/logos-co/logos-lips/blob/513d8eae6be8b7b30bf427023ac686df2f2918c0/docs/ift-ts/raw/logos-service-discovery.md) — feat: renaming capability to service discovery (#300)
- **2026-02-27** — [`2ec272e`](https://github.com/logos-co/logos-lips/blob/2ec272e57f6110106297d062098110a3549c5db6/docs/ift-ts/raw/logos-capability-discovery.md) — docs: refactor and add algo explanation before pseudocode (#280)
- **2026-01-27** — [`ab9337e`](https://github.com/logos-co/logos-lips/blob/ab9337e58b5947a3b58d205fec7d52fb8d16c2eb/docs/ift-ts/raw/logos-capability-discovery.md) — Add recipe for algorithms (#232)
- **2026-01-19** — [`f24e567`](https://github.com/logos-co/logos-lips/blob/f24e567d0b1e10c178bfa0c133495fe83b969b76/docs/ift-ts/raw/logos-capability-discovery.md) — Chore/updates mdbook (#262)
- **2026-01-16** — [`89f2ea8`](https://github.com/logos-co/logos-lips/blob/89f2ea89fc1d69ab238b63c7e6fb9e4203fd8529/docs/ift-ts/raw/logos-capability-discovery.md) — Chore/mdbook updates (#258)
- **2025-12-22** — [`0f1855e`](https://github.com/logos-co/logos-lips/blob/0f1855edcf68ef982c4ce478b67d660809aa9830/docs/vac/raw/logos-capability-discovery.md) — Chore/fix headers (#239)
- **2025-12-22** — [`b1a5783`](https://github.com/logos-co/logos-lips/blob/b1a578393edf8487ccc97a5f25b25af9bf41efb3/docs/vac/raw/logos-capability-discovery.md) — Chore/mdbook updates (#237)
- **2025-12-18** — [`d03e699`](https://github.com/logos-co/logos-lips/blob/d03e699084774ebecef9c6d4662498907c5e2080/docs/vac/raw/logos-capability-discovery.md) — ci: add mdBook configuration (#233)
- **2025-12-09** — [`aaf158a`](https://github.com/logos-co/logos-lips/blob/aaf158aa59edb2ce0841a345725d16355218c196/vac/raw/logos-capability-discovery.md) — VAC/RAW/LOGOS-DISCOVERY-CAPABILITY RFC  (#212)

<!-- timeline:end -->

> **Note:** This specification is currently a WIP and undergoing a high rate of changes.

## Abstract

This RFC defines the Logos Service Discovery protocol,
a discovery mechanism inspired by [DISC-NG service discovery](https://ieeexplore.ieee.org/document/10629017)
built on top of [Kad-dht](https://github.com/libp2p/specs/tree/7740c076350b6636b868a9e4a411280eea34d335/kad-dht).

The protocol enables nodes to:

- Advertise their participation in specific services
- Efficiently discover other peers participating in those services

In this RFC, the terms "capability" and "service" are used interchangeably.
Within Logos, a node’s “capabilities” map directly to
the “services” it participates in.
Similarly, "peer" and "node" refer to the same entity:
a participant in the Logos Discovery network.

Logos discovery extends Kad-dht toward a multi-service, resilient discovery layer,
enhancing reliability while maintaining compatibility with existing Kad-dht behavior.
For everything else that isn't explicitly stated herein,
it is safe to assume behaviour similar to Kad-dht.

## Motivation

In decentralized networks supporting multiple services,
efficient peer discovery for specific services is critical.
Traditional approaches face several challenges:

- Inefficiency: Random-walk–based discovery is inefficient for unpopular services.
- Load imbalance: A naive approach where nodes advertise their service at DHT peers
whose IDs are closest to the service ID
leads to hotspots and overload at popular services.
- Scalability: Discovery must scale logarithmically across many distinct services.

Logos discovery addresses these through:

- Service-specific routing tables
- Adaptive advertisement placement with admission control
- Improved lookup operations balancing efficiency and resilience

## Format Specification

The key words “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”,
“SHOULD”, “SHOULD NOT”, “RECOMMENDED”, “MAY”, and “OPTIONAL” in this document
are to be interpreted as described in [2119](https://www.ietf.org/rfc/rfc2119.txt).

## Protocol Roles

The Logos service discovery protocol defines three roles that nodes can perform:

### Advertiser

**Advertisers** are nodes that participate in a service
and want to be discovered by other peers.

### Discoverer

**Discoverers** are nodes attempting to find peers that provide a specific service.

### Registrar

**Registrars** are nodes that store and serve advertisements.

Responsibilities:

- Registrars MUST use a waiting time based admission control mechanism
to decide whether to store an advertisement coming from an advertiser or not.
- Registrars SHOULD respond to query requests for advertisements coming from discoverers.

## Definitions

### DHT Routing Table

Every participant in the kad-dht peer discovery layer
maintains the peer routing table `KadDHT(peerID)`.
It is a distributed key-value store with
[peer IDs](https://github.com/libp2p/specs/blob/7740c076350b6636b868a9e4a411280eea34d335/peer-ids/peer-ids.md#peer-ids)
as key against their matching
[signed peer records](https://github.com/libp2p/specs/blob/7740c076350b6636b868a9e4a411280eea34d335/RFC/0003-routing-records.md) values.
It is centered on the node's own `peerID`.

> “Centered on” means the table is organized using that ID as the reference point
for computing distances with other peers and assigning peers to buckets.

### Bucket

Each routing table is organized into buckets.
A bucket is a logical container that stores information about peers
at a particular distance range from a reference ID.

Conceptually:

- Each bucket corresponds to a specific range in the XOR distance metric
- Peers are assigned to buckets based on their XOR distance from the table's center ID
- Buckets enable logarithmic routing by organizing the keyspace into manageable segments

The number of buckets and their organization is described in the [Distance](#distance) section.
Implementation considerations for bucket management
are detailed in [Bucket Management](#bucket-management) section.

### Service

A service is a logical sub-network within the larger peer-to-peer network.
It represents a specific capability a node supports
— for example, a particular protocol or functionality it offers.
A service MUST be identified by a libp2p protocol ID via the
[identify protocol](https://github.com/libp2p/specs/tree/7740c076350b6636b868a9e4a411280eea34d335/identify).
This service protocol ID (e.g., `/waku/store/1.0.0`)
identifies the capability being discovered.

### Service ID

The service ID `service_id_hash` MUST be the SHA-256 hash of the protocol ID.

For example:

| Service Identifier | Service ID |
| --- | --- |
| `/waku/store/1.0.0` | `313a14f48b3617b0ac87daabd61c1f1f1bf6a59126da455909b7b11155e0eb8e` |
| `/libp2p/mix/1.2.0` | `9c55878d86e575916b267195b34125336c83056dffc9a184069bcb126a78115d` |

### Advertisement Cache

An advertisement cache `ad_cache` is a bounded storage structure
maintained by registrars to store accepted advertisements.

### Advertise Table

For every service it participates in, an advertiser node MUST maintain an
advertise table `AdvT(service_id_hash)` centered on `service_id_hash`.
The table MAY be initialized using
peers from the advertiser’s `KadDHT(peerID)` routing table.
It SHOULD be updated opportunistically through interactions with
registrars during the advertisement process.

Each bucket in the advertise table contains a list of registrar peers at a
particular XOR distance range from `service_id_hash`, which are candidates for placing
advertisements.

### Search Table

For every service it attempts to discover, a discoverer node MUST maintain a
search table `DiscT(service_id_hash)` centered on `service_id_hash`.
The table MAY be initialized using
peers from the discoverer’s`KadDHT(peerID)` routing table.
It SHOULD be updated through interactions with
registrars during lookup operations.

Each bucket in the search table contains a list of registrar peers at a
particular XOR distance range from `service_id_hash`, which discoverers can query to
retrieve advertisements for that service.

### Registrar Table

For every service for which it stores and serves advertisements,
a registrar node SHOULD maintain a registrar table `RegT(service_id_hash)`
centered on `service_id_hash`.
The table MAY be initialized using peers from the
registrar’s `KadDHT(peerID)` routing table.
It SHOULD be updated opportunistically
through interactions with advertisers and discoverers.

Each bucket in the registrar table contains a list of peer nodes
at a particular XOR distance range from `service_id_hash`.
Registrars use this table to return
`closerPeers` in `REGISTER` and `GET_ADS` responses,
enabling advertisers and discoverers to
refine their service-specific routing tables.

### Address

A [multiaddress](https://github.com/libp2p/specs/tree/7740c076350b6636b868a9e4a411280eea34d335/addressing)
is a standardized way used in libp2p to represent network addresses.
Implementations SHOULD use multiaddresses for peer connectivity.
However, implementations MAY use alternative address representations if they:

- Remain interoperable
- Convey sufficient information (IP + port) to establish connections

### Signature

Refer to [Peer Ids and Keys](https://github.com/libp2p/specs/blob/7740c076350b6636b868a9e4a411280eea34d335/peer-ids/peer-ids.md)
to know about supported signatures.
In the base Kad DHT specification, signatures are optional,
typically implemented as a PKI signature over the tuple `(key || value || author)`.
In this RFC digital signatures MUST be used to
authenticate advertisements and tickets.

### Expiry Time `E`

`E` is advertisement expiry time in seconds.
The expiry time **`E`** is a system wide parameter,
not an individual advertisement field or parameter of an individual registrar.

## Data Structures

### Advertisement

An **advertisement** indicates that a specific node participates in a service.
In this RFC we refer to advertisement objects as `ads`.
For a single advertisement object we use `ad`.

An advertisement logically represents:

- **Service identification**: Which service the node participates in (via `service_id_hash`)
- **Peer identification**: The node's unique peer ID
- **Network addresses**: How to reach the node (multiaddrs)
- **Authentication**: Cryptographic proof that the node controls the peer ID

> Ads are authenticated but the containing information can still be false.
It is trivial to create valid ads that refer to nodes that don't exist.
Similarly, the advertiser's IP and peer ID should not be confused with the ad's, they may be different.

Implementations are RECOMMENDED to use ExtensiblePeerRecord (XPR) encoding for advertisements.
See the [Advertisement Encoding](#advertisement-encoding) section
in the wire protocol specification for transmission format details.

### Ticket

Tickets are digitally signed objects issued by registrars to advertisers
to track accumulated waiting time for admission into the advertisement cache.

A ticket logically represents:

- **Advertisement reference**: The advertisement this ticket is associated with
- **Time tracking**: When the ticket was created (`t_init`) and last modified (`t_mod`)
- **Waiting time**: How long the advertiser must wait before retrying (`t_wait_for`)
- **Authentication**: Cryptographic proof that the registrar issued this ticket

Tickets enable stateless admission control at registrars.
Advertisers accumulate waiting time across registration attempts
by presenting tickets from previous attempts.

See the [RPC Messages](#rpc-messages) section for the wire format specification of tickets.

## Protocol Specifications

### System Parameters

The system parameters are derived directly from
the [DISC-NG paper](https://ieeexplore.ieee.org/document/10629017).
Implementations SHOULD modify them as needed based on specific requirements.

| Parameter | Default Value | Description |
| --- | --- | --- |
| `K_register` | 3 | Max number of active (i.e. unexpired) registrations + ongoing registration attempts per bucket. |
| `K_lookup` | 5 | For each bucket in the search table, number of random registrar nodes queried by discoverers |
| `F_lookup` | 30 | number of advertisers to find in the lookup process. We stop lookup process when we have found these many advertisers |
| `F_return` | 10 | max number of service-specific peers returned from a single registrar |
| `E` | 900 seconds | Advertisement expiry time (15 minutes) |
| `C` | 1,000 | Advertisement cache capacity |
| `P_occ` | 10 | Occupancy exponent for waiting time calculation |
| `G` | 10⁻⁷ | Safety parameter for waiting time calculation |
| `δ` | 1 second | Registration window time |
| `m`  | 16 | Number of buckets for service-specific tables |

### Distance

The distance `d` between any two keys in Logos Service Discovery
MUST be calculated using the bitwise XOR applied to their 256-bit SHA-256 representations.
This provides a deterministic, uniform, and symmetric way to measure proximity in the keyspace.
The keyspace is the entire numerical range of possible `peerID` and `service_id_hash`
— the 256-bit space in which all SHA-256–derived IDs exist.
XOR MUST be used to measure distances between them in the keyspace.

For every node in the network, the `peerID` is unique.
In this system, both `peerID` and the `service_id_hash` are 256-bit SHA-256 hashes.
Thus both belong to the same keyspace.

`KadDHT(peerID)` table is centered on `peerID`.
`AdvT(service_id_hash)`, `DiscT(service_id_hash)`
and `RegT(service_id_hash)` are service-specific tables
and MUST be centered on `service_id_hash`.
Bootstrapping of service-specific tables
MAY be done from the `KadDHT(peerID)` table.

When inserting a peer into the service-specific tables,
the bucket index into which the peer will be inserted MUST be determined by:

- x = reference ID which is the `service_id_hash`
- y = target peer ID `peerID`
- L = 256 = bit length of IDs
- `m` = 16 = number of buckets in the advertise/search table
- `d = x ⊕ y = service_id_hash ⊕ peerID` = bitwise XOR distance (interpreted as an unsigned integer)

The bucket index `i` where `y` is placed in `x`'s table is calculated as:

- Let `lz = CLZ(d)` = number of leading zeros in the 256-bit representation of `d`
- `i = min( lz , m − 1 )`
- Special case: For `d = 0` (same ID), `i = m - 1`

Lower-index buckets represent peers far away from `service_id_hash` in the keyspace,
while higher-index buckets contain peers closer to `service_id_hash`.
This property allows efficient logarithmic routing:
each hop moves to a peer that shares a longer prefix of bits
with the target `service_id_hash`.

Service-specific tables may initially have low peer density,
especially when `service_id_hash` and `peerID` are distant in the keyspace.
Buckets SHOULD be filled opportunistically through `response.closerPeers`
during interactions (see [Peer Table Updates](#peer-table-updates))
using the same formula.

## RPC Messages

All RPC messages use the libp2p Kad-DHT message format
with extensions for Logos discovery operations.

### Base Message Structure

```protobuf
syntax = "proto2";

message Register {
    // Used in response to indicate the status of the registration
    enum RegistrationStatus {
        CONFIRMED = 0;
        WAIT = 1;
        REJECTED = 2;
    }

    // Ticket protobuf definition
    message Ticket {
        // Copy of the original advertisement
        bytes advertisement = 1;

        // Ticket creation timestamp (Unix time in seconds)
        uint64 t_init = 2;

        // Last modification timestamp (Unix time in seconds)
        uint64 t_mod = 3;

        // Remaining wait time in seconds
        uint32 t_wait_for = 4;

        // Ed25519 signature over (ad || t_init || t_mod || t_wait_for)
        bytes signature = 5;
    }

    // Used to indicate the encoded advertisement against the key (service ID)
    bytes advertisement = 1;

    // Used in response to indicate the status of the registration
    RegistrationStatus status = 2;

    // Used in response to provide a ticket if status is WAIT
    // Used in request to provide a ticket if previously received
    optional Ticket ticket = 3;
}

message GetAds {
    // Used in response to provide a list of encoded advertisements
    repeated bytes advertisements = 1;
}

// Record represents a dht record that contains a value
// for a key value pair
message Record {
    // The key that references this record
    bytes key = 1;

    // The actual value this record is storing
    bytes value = 2;

    // Note: These fields were removed from the Record message
    //
    // Hash of the authors public key
    // optional string author = 3;
    // A PKI signature for the key+value+author
    // optional bytes signature = 4;

    // Time the record was received, set by receiver
    // Formatted according to https://datatracker.ietf.org/doc/html/rfc3339
    string timeReceived = 5;
};

message Message {
    enum MessageType {
        PUT_VALUE = 0;
        GET_VALUE = 1;
        ADD_PROVIDER = 2;
        GET_PROVIDERS = 3;
        FIND_NODE = 4;
        PING = 5;
        REGISTER = 6; // New
        GET_ADS = 7; // New
    }

    enum ConnectionType {
        // sender does not have a connection to peer, and no extra information (default)
        NOT_CONNECTED = 0;

        // sender has a live connection to peer
        CONNECTED = 1;

        // sender recently connected to peer
        CAN_CONNECT = 2;

        // sender recently tried to connect to peer repeatedly but failed to connect
        // ("try" here is loose, but this should signal "made strong effort, failed")
        CANNOT_CONNECT = 3;
    }

    message Peer {
        // ID of a given peer.
        bytes id = 1;

        // multiaddrs for a given peer
        repeated bytes addrs = 2;

        // used to signal the sender's connection capabilities to the peer
        ConnectionType connection = 3;
    }

    // defines what type of message it is.
    MessageType type = 1;

    // defines what coral cluster level this query/response belongs to.
    // in case we want to implement coral's cluster rings in the future.
    int32 clusterLevelRaw = 10; // NOT USED

    // Used to specify the key associated with this message.
    // PUT_VALUE, GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
    // New DISC-NG capability discovery contains service ID hash for types REGISTER, GET_ADS
    bytes key = 2;

    // Used to return a value
    // PUT_VALUE, GET_VALUE
    Record record = 3;

    // Used to return peers closer to a key in a query
    // GET_VALUE, GET_PROVIDERS, FIND_NODE
    repeated Peer closerPeers = 8;

    // Used to return Providers
    // GET_VALUE, ADD_PROVIDER, GET_PROVIDERS
    repeated Peer providerPeers = 9;

    // Used in REGISTER request and response
    Register register = 21;

    // Used in GET_ADS response
    GetAds getAds = 22;
}
```

**Key Design Principles:**

- Standard Kad-DHT message types (`PUT_VALUE`, `GET_VALUE`,
`ADD_PROVIDER`, `GET_PROVIDERS`, `FIND_NODE`, `PING`) remain completely unchanged
- The `Record` message is preserved as-is for Kad-DHT routing table operations
- Logos adds two new message types (`REGISTER`, `GET_ADS`) without modifying existing types
- Advertisements are encoded as generic `bytes` (RECOMMENDED: ExtensiblePeerRecord/XPR)
to avoid coupling the protocol to specific formats
- The existing `key` field is reused for `service_id_hash` in Logos operations
- Nodes without Logos Service Discovery support will ignore `REGISTER` and `GET_ADS` messages

### Advertisement Encoding

Advertisements in the `Register.advertisement` and `GetAds.advertisements` fields are encoded as `bytes`. Implementations are RECOMMENDED to use [ExtensiblePeerRecord (XPR)](extensible-peer-records.md) encoding.

Alternative encodings MAY be used if they provide equivalent functionality
and can be verified by discoverers.

Where the encoding carries a services field (e.g. XPR's `services`), it
MUST include the `ServiceInfo` entry for the `service_id_hash` being
registered; it MAY also list `ServiceInfo` entries for other services
the advertiser supports (see
[Advertisement Signature Verification](#advertisement-signature-verification)
for how those other entries are treated).
Per [Advertisement](#advertisement),
each `REGISTER` is still scoped to
exactly one `service_id_hash`.

### REGISTER Message

Used by advertisers to register their advertisements with registrars.

#### REGISTER Request

| Field | Usage | Value |
|-------|-------|-------|
| `type` | REQUIRED | `REGISTER` (6) |
| `key` | REQUIRED | `service_id_hash` (32 bytes) |
| `register.advertisement` | REQUIRED | Encoded advertisement as `bytes` (RECOMMENDED: XPR) |
| `register.ticket` | OPTIONAL | Ticket from previous registration attempt |
| All other fields | UNUSED | Empty/not set |

**Example (First attempt):**

```protobuf
Message {
    type: REGISTER
    key: <service_id_hash>
    register: {
        advertisement: <encoded_xpr_bytes>
    }
}
```

**Example (Retry with ticket):**

```protobuf
Message {
    type: REGISTER
    key: <service_id_hash>
    register: {
        advertisement: <encoded_xpr_bytes>
        ticket: {
            ad: <encoded_xpr_bytes>
            t_init: 1234567890
            t_mod: 1234567900
            t_wait_for: 300
            signature: <registrar_signature>
        }
    }
}
```

Each `REGISTER` request MUST register an advertisement against exactly one
`service_id_hash` - the request's `key` field - and the resulting
`ad_cache` entry is scoped to that one service
(see [Advertisement Cache](#advertisement-cache)).
The advertisement's content MAY encode any further service information
as required by the discovering application.

#### REGISTER Response

| Field | Usage | Value |
|-------|-------|-------|
| `type` | REQUIRED | `REGISTER` (6) |
| `register.status` | REQUIRED | `CONFIRMED`, `WAIT`, or `REJECTED` |
| `closerPeers` | REQUIRED | List of peers for advertise table |
| `register.ticket` | CONDITIONAL | Present if status = `WAIT` |
| All other fields | UNUSED | Empty/not set |

**Status values:**

- `CONFIRMED`: Advertisement stored in cache
- `WAIT`: Not yet accepted, wait and retry with ticket
- `REJECTED`: Invalid signature, invalid ticket, or error

**Example (WAIT):**

```protobuf
Message {
    type: REGISTER
    register: {
        status: WAIT
        ticket: {
            ad: <encoded_xpr_bytes>
            t_init: 1234567890
            t_mod: 1234567905
            t_wait_for: 295
            signature: <registrar_signature>
        }
    }
    closerPeers: [
        {id: <peer1_id>, addrs: [<addr1>]},
        {id: <peer2_id>, addrs: [<addr2>]}
    ]
}
```

**Example (CONFIRMED):**

```protobuf
Message {
    type: REGISTER
    register: {
        status: CONFIRMED
    }
    closerPeers: [
        {id: <peer1_id>, addrs: [<addr1>]},
        {id: <peer2_id>, addrs: [<addr2>]}
    ]
}
```

**Example (REJECTED):**

```protobuf
Message {
    type: REGISTER
    register: {
        status: REJECTED
    }
}
```

### GET_ADS Message

Used by discoverers to retrieve advertisements from registrars.

#### GET_ADS Request

| Field | Usage | Value |
|-------|-------|-------|
| `type` | REQUIRED | `GET_ADS` (7) |
| `key` | REQUIRED | `service_id_hash` (32 bytes) |
| All other fields | UNUSED | Empty/not set |

**Example:**

```protobuf
Message {
    type: GET_ADS
    key: <service_id_hash>
}
```

#### GET_ADS Response

| Field | Usage | Value |
|-------|-------|-------|
| `type` | REQUIRED | `GET_ADS` (7) |
| `getAds.advertisements` | REQUIRED | List of encoded advertisements (up to `F_return` = 10) |
| `closerPeers` | REQUIRED | List of peers for search table |
| All other fields | UNUSED | Empty/not set |

Each advertisement in `getAds.advertisements` is encoded as `bytes` (RECOMMENDED: XPR).
Discoverers MUST verify signatures before accepting.

**Example:**

```protobuf
Message {
    type: GET_ADS
    getAds: {
        advertisements: [
            <encoded_xpr_bytes_1>,
            <encoded_xpr_bytes_2>,
            ...  // up to F_return
        ]
    }
    closerPeers: [
        {id: <peer1_id>, addrs: [<addr1>]},
        {id: <peer2_id>, addrs: [<addr2>]}
    ]
}
```

### Message Validation

#### REGISTER Request Validation

Registrars MUST validate:

1. `type` = `REGISTER` (6)
2. `key` = 32 bytes (valid SHA-256)
3. `register.advertisement` is present and non-empty
4. If `register.ticket` present:
   - Valid signature issued by this registrar
   - `ticket.ad` matches `register.advertisement`
   - Retry within window: `ticket.t_mod + ticket.t_wait_for ≤ NOW() ≤ ticket.t_mod + ticket.t_wait_for + δ`
5. Advertisement signature is valid
(see [Advertisement Signature Verification](#advertisement-signature-verification))

Respond with `register.status = REJECTED` if validation fails.

#### GET_ADS Request Validation

Registrars MUST validate:

1. `type` = `GET_ADS` (7)
2. `key` = 32 bytes (valid SHA-256)

Return empty `getAds.advertisements` list or close stream if validation fails.

#### Advertisement Signature Verification

Both registrars (on REGISTER) and discoverers (on GET_ADS response)
MUST verify advertisement signatures.
For XPR-encoded advertisements:

```text
VERIFY_ADVERTISEMENT(encoded_ad_bytes, service_id_hash):
    envelope = DECODE_SIGNED_ENVELOPE(encoded_ad_bytes)
    assert(envelope.domain == "libp2p-routing-state")
    assert(envelope.payload_type == "/libp2p/extensible-peer-record/")

    xpr = DECODE_XPR(envelope.payload)
    public_key = DERIVE_PUBLIC_KEY(xpr.peer_id)
    assert(VERIFY_ENVELOPE_SIGNATURE(envelope, public_key))

    // Verify service advertised
    service_found = false
    for service in xpr.services:
        if SHA256(service.id) == service_id_hash:
            service_found = true
    assert(service_found)
```

Discard advertisements with invalid signatures or that don't advertise the requested service.

> **Note:** The loop over `xpr.services` above is a signature-binding check,
confirming the requested `service_id_hash`
is among the services the advertiser signed.
An advertisement supports exactly the `service_id_hash`
it was registered or queried against.
Any other entries in `xpr.services` are opaque to registrars and
discoverers - they are meaningful only to the application that
ultimately receives the advertisement.

> **Note:** ExtensiblePeerRecord uses protocol strings (e.g., `/waku/store/1.0.0`) in `ServiceInfo.id`.
Logos discovery uses `service_id_hash = SHA256(ServiceInfo.id)` for routing.
When verifying, implementations MUST hash the protocol string
and compare with the `key` field (`service_id_hash`).

### Stream Management

Following standard Kad-DHT behavior:

- Implementations MAY reuse streams for sequential requests
- Implementations MUST handle multiple requests per stream
- Reset stream on protocol errors or validation failures
- Prefix messages with length as unsigned varint per
[multiformats spec](https://github.com/multiformats/unsigned-varint)

### Error Handling

| Error | Handling |
|-------|----------|
| Invalid message format | Close stream |
| Signature verification failure | `REJECTED` for REGISTER; discard invalid ads for GET_ADS |
| Timeout | Close stream, retry with exponential backoff |
| Cache full (registrar) | Issue ticket with waiting time |
| Unknown service_id_hash | Empty `advertisements` list but include `closerPeers` |
| Missing required fields | Close stream |

## Sequence Diagram

![Sequence diagram](https://github.com/user-attachments/assets/d85fab17-c636-417a-afaf-c609aa53075d)

## Advertisers

Advertisers distribute advertisements for their service across registrars.

### Distributing ads across registrars

For each service, identified by `service_id_hash`,
that an advertiser wants to advertise,
the advertiser MUST instantiate a
new advertise table, `AdvT(service_id_hash)`,
centered on that `service_id_hash`.
The advertiser MAY bootstrap `AdvT(service_id_hash)`
from the `KadDHT(peerID)` routing table using the formula
described in the [Distance section](#distance).

Each registration is scoped to one `service_id_hash`.
The advertiser SHOULD try to maintain up to `K_register`
active registrations per bucket.
It does so by selecting random registrars
from each bucket of `AdvT(service_id_hash)`.
These ongoing registrations MAY be tracked in a separate data structure.
Ongoing registrations include those registrars
at which the advertiser has an active registration or
for which there is an ongoing registration attempt.

To maintain each registration, the advertiser:

- MUST send a [REGISTER message](#register-message) to the registrar.
If there is already a cached `ticket` from a previous registration attempt
for the same `ad` in the same registrar,
the `ticket` MUST also be included in the REGISTER message.
- on receipt of the `REGISTER` response:
SHOULD add the closer peers indicated in the response to `AdvT(service_id_hash)`
using the formula described in the [Distance](#distance) section.
- MUST interpret the response `status` field and schedule actions accordingly:
  - If the `status` is `Confirmed`, the registration is maintained
  in the registrar's `ad_cache` for `E` seconds.
  After `E` seconds the advertiser MUST remove the registration
  from the ongoing registrations for that bucket.
  - If the `status` is `Wait`,
  the advertiser MUST schedule a next registration attempt to the same registrar
  based on the `ticket.t_wait_for` value included in the response.
  The Response contains a `ticket`,
  which MUST be included in the next registration attempt to this registrar.
  - If the `status` is `Rejected`,
  the advertiser MUST remove the registrar from the ongoing registrations for that bucket
  and SHOULD NOT attempt further registrations with this registrar for this advertisement.

### Example ADVERTISE algorithm

The following pseudocode block shows one way of implementing the Advertising algorithm.
Advertisers MAY follow this example.

```text
procedure ADVERTISE(service_id_hash):
    ongoing ← MAP<bucketIndex; LIST<registrars>>
    AdvT(service_id_hash) ← KadDHT(peerID)
    for i in 0, 1, ..., m-1:
        while ongoing[i].size < K_register:
            registrar ← AdvT(service_id_hash).getBucket(i).getRandomNode()
            if registrar = None:
                break
            end if
            ongoing[i].add(registrar)
            ad.service_id_hash ← service_id_hash
            ad.peerID ← peerID
            ad.addrs ← node.addrs
            SIGN(ad)
            async(ADVERTISE_SINGLE(registrar, ad, i, service_id_hash))
        end while
    end for
end procedure

procedure ADVERTISE_SINGLE(registrar, ad, i, service_id_hash):
    ticket ← None
    while True:
        response ← registrar.Register(ad, ticket)
        AdvT(service_id_hash).add(response.closerPeers)
        if response.status = Confirmed:
            SLEEP(E)
            break
        else if response.status = Wait:
            SLEEP(min(E, response.ticket.t_wait_for))
            ticket ← response.ticket
        else:
            break
        end if
    end while
    ongoing[i].remove(registrar)
end procedure
```

Refer to the [Advertiser Algorithms Explanation section](#advertiser-algorithms-explanation)
for a detailed explanation.

## Discoverers

Discoverers look up advertisers for services by querying registrars.

### Looking up services

For each service, identified by `service_id_hash`,
that a discoverer wants to find advertisers for,
the discoverer MUST instantiate a
new search table, `DiscT(service_id_hash)`,
centered on that `service_id_hash`.
The discoverer MAY bootstrap `DiscT(service_id_hash)`
from the `KadDHT(peerID)` routing table using the formula
described in the [Distance section](#distance).

The discoverer MUST attempt to find up to `F_lookup` advertisers
for this `service_id_hash`
by following the lookup procedure below.
It SHOULD perform the lookup procedure periodically,
or whenever more peers are requested by the encapsulating application.

To perform a lookup,
the discoverer MUST iterate through every bucket of `DiscT(service_id_hash)`.
It MUST start from the farthest bucket `(b_0)`,
which has the registrar nodes with the fewest shared bits to the `service_id_hash`,
gradually moving through buckets `(b_(m-1))`,
containing registrar nodes with ever increasing number of shared bits to the `service_id_hash`.
During the lookup procedure,
the discoverer SHOULD keep track of unique `foundPeers`.
terminating the procedure once `F_lookup` advertisers have been found,
or if all buckets have been traversed.

1. For each bucket, the discoverer MUST select
up to `K_lookup` random registrar peers to query.
2. For each selected registrar, the discoverer

- MUST send a [`GET_ADS` message](#get_ads-message) to the registrar
- on receipt of a `GET_ADS` response,
SHOULD add the closer peers indicated in the response to `DiscT(service_id_hash)`
using the formula described in the [Distance](#distance) section.
- SHOULD validate each `advertisement` included in the response,
and add valid advertisers to `foundPeers`.
Note that a valid response could also contain `0` `advertisements`.

This iterative procedure continues until `F_lookup` advertisers have been found,
or all buckets have been traversed.

### Example LOOKUP algorithm

The following pseudocode block shows one way of implementing the Lookup algorithm.
Discoverers MAY follow this example.

```text
procedure LOOKUP(service_id_hash):
    DiscT(service_id_hash) ← KadDHT(peerID)
    foundPeers ← SET<Peers>
    for i in 0, 1, ..., m-1:
        for j in 0, ..., K_lookup - 1:
            peer ← DiscT(service_id_hash).getBucket(i).getRandomNode()
            if peer = None:
                break
            end if
            response ← peer.GetAds(service_id_hash)
            for ad in response.ads:
                assert(ad.hasValidSignature())
                foundPeers.add(ad.peerID)
                if foundPeers.size ≥ F_lookup:
                      break
                  end if
              end for
            DiscT(service_id_hash).add(response.closerPeers)
            if foundPeers.size ≥ F_lookup:
                return foundPeers
            end if
        end for
    end for
    return foundPeers
end procedure
```

Refer to the [Lookup Algorithm Explanation section](#lookupservice_id_hash-algorithm-explanation)
for the detailed explanation.

## Registrars

Registrars are nodes that store advertisements,
by handling `REGISTER` requests,
and serve cached advertisements,
by handling `GET_ADS` requests.
Registrars MUST maintain a cache of advertisements, `ad_cache`,
that associates each `advertisement`
to only one advertiser's `peer_id`, `service_id`
and expiry timestamp based on admission time plus configured expiry time, `E`.
Once an `ad` has expired, it SHOULD be removed from the `ad_cache`.

### Handling REGISTER requests

When a registrar node receives a `REGISTER` request from an advertiser node
to admit its `ad` for a service into the `ad_cache`,
the registrar SHOULD process the request
and respond with a `REGISTER` response according to the steps below.
The registrar SHOULD include a list of closer peers (`response.closerPeers`) in the response
using the algorithm described in [Peer Table Updates](#peer-table-updates) section.

To populate the rest of the response, the registrar MUST:

1. Calculate a waiting time for the `ad`, `t_wait`,
using the formula in [Waiting Time Calculation](#waiting-time-calculation).
2. If no `ticket` is provided in the `REGISTER` request
this is the advertiser's first registration attempt for the `ad`.
Create a new signed `ticket` based on `t_wait`,
and return the signed `ticket` in a response with status `Wait`.
3. If a `ticket` is provided in the `REGISTER` request,
validate the ticket and respond with the status `Rejected` if any of the following fails:

    - `ticket.signature` contains a valid signature, issued by this registrar
    - `ticket.ad` matches the current `ad`
    - calculate the expected time of ticket submission,
    `t_scheduled`, as `t_scheduled = ticket.t_mod + ticket.t_wait`
    and verify that the actual submission time, `current_time`,
    falls within a valid registration window, `δ`,
    where `t_scheduled <= current_time <= t_scheduled + δ`.
    The duration of `δ` is up to the application,
    but SHOULD be just enough to accommodate for
    the maximum delay between the advertiser and the registrar.

4. Calculate remaining wait time
`t_remaining = t_wait - (current_time - ticket.t_init)`.
This ensures advertisers accumulate waiting time across retries
5. If `t_remaining ≤ 0`, add the `ad` to the `ad_cache`,
with an expiry timestamp set to `current_time + E`.
If an entry for this `peer_id` and `service_id` already exists,
this replaces it.
6. If `t_remaining > 0`, issue a new signed `ticket`
with `ticket.t_mod` set to `current_time`
and `ticket.t_wait_for = min(E, t_remaining)`.
The registrar SHOULD return the signed `ticket` in a response with status `Wait`.

### Example REGISTER algorithm

The following pseudocode block shows one way of implementing the algorithm to handle register requests.
Registrars MAY follow this example.

```text
procedure REGISTER(ad, ticket):
    response.ticket.ad ← ad
    t_wait ← CALCULATE_WAITING_TIME(ad)

    if ticket.empty():
        t_remaining ← t_wait
        response.ticket.t_init ← NOW()
        response.ticket.t_mod ← NOW()
    else:
        assert(ticket.hasValidSignature())
        assert(ticket.ad = ad)
        t_scheduled ← ticket.t_mod + ticket.t_wait_for
        assert(t_scheduled ≤ NOW() ≤ t_scheduled + δ)
        t_remaining ← t_wait - (NOW() - ticket.t_init)
    end if
    if t_remaining ≤ 0:
        if ad_cache.contains(ad.peer_id, ad.service_id_hash):
            ad_cache.replace(ad)
        else:
            ad_cache.add(ad)
        end if
        response.status ← Confirmed
    else:
        response.status ← Wait
        response.ticket.t_wait_for ← MIN(E, t_remaining)
        response.ticket.t_mod ← NOW()
        SIGN(response.ticket)
    end if
    response.closerPeers ← GETPEERS(ad.service_id_hash)
    return response
end procedure
```

Refer to the [Register Algorithm Explanation section](#register-algorithm-explanation)
for detailed explanation.

### Handling GET_ADS requests

Registrars SHOULD respond to [`GET_ADS`](#get_ads-message) requests from discoverers
with a `GET_ADS` response:

1. Include up to `F_return` advertisements
from the `ad_cache` for the requested `service_id_hash`.
2. Include a list of closer peers
to help discoverers populate their search table using the algorithm described in
[Peer Table Updates](#peer-table-updates) section.

### Example LOOKUP_RESPONSE algorithm

The following pseudocode block shows one way of implementing the algorithm to handle `GET_ADS` requests.
Registrars MAY follow this example.

```text
procedure LOOKUP_RESPONSE(service_id_hash):
    response.ads ← ad_cache.getAdvertisements(service_id_hash)[:F_return]
    response.closerPeers ← GETPEERS(service_id_hash)
    return response
end procedure
```

## Peer Table Updates

### Overview

While responding to both `REGISTER` requests by advertisers
and `GET_ADS` request by discoverers,
registrars play an important role in helping nodes discover the network topology.
The registrar table `RegT(service_id_hash)` is a routing structure
that SHOULD be maintained by registrars
to provide better peer suggestions to advertisers and discoverers.

Registrars SHOULD use the formula specified in the [Distance](#distance) section
to add peers to `RegT(service_id_hash)`.
Peers are added under the following circumstances:

- Registrars MAY initialize their registrar table `RegT(service_id_hash)`
from their `KadDHT(peerID)` using the formula described in the [Distance Section](#distance).
- When an advertiser sends a `REGISTER` request,
the registrar SHOULD add the advertiser's `peerID` to `RegT(service_id_hash)`.
- When a discoverer sends a `GET_ADS` request,
the registrar SHOULD add the discoverer's `peerID` to `RegT(service_id_hash)`.
- When registrars receive responses from other registrars
(if acting as advertiser or discoverer themselves),
they SHOULD add peers from `closerPeers` fields
to relevant `RegT(service_id_hash)` tables.

> **Note:** The `ad_cache` and `RegT(service_id_hash)`
are completely different data structures
that serve different purposes and are independent of each other.

When responding to requests, registrars:

- SHOULD return a list of peers to help advertisers
populate their `AdvT(service_id_hash)` tables and
discoverers populate their `DiscT(service_id_hash)` tables.
- SHOULD return peers that are diverse and distributed across different buckets
to prevent malicious registrars from polluting routing tables.

### Recommended Peer Selection Algorithm

We RECOMMEND that the following algorithm be used to select peers to return in responses.

```text
procedure GETPEERS(service_id_hash):
    peers ← SET<peers>
    RegT(service_id_hash) ← KadDHT(peerID)
    for i in 0, 1, ..., m-1:
        peer ← b_i(service_id_hash).getRandomNode()
        if peer ≠ None:
            peers.add(peer)
        end if
    end for
    return peers
end procedure
```

1. `peers` is initialized as an empty set
2. `RegT(service_id_hash)` is initialized from the node’s `KadDHT(peerID)`.
3. Go through all `m` buckets in the registrar’s table —
    1. Pick one random peer from bucket `i`.
    `getRandomNode()` function remembers already returned nodes
    and never returns the same one twice.
    2. If `peer` returned is not null then we move on to next bucket.
    Else we try to get another peer in the same bucket
4. Return `peers` which contains one peer from every bucket of `RegT(service_id_hash)`.

The algorithm returns one random peer per bucket to provide diverse suggestions
and prevent malicious registrars from polluting routing tables.
Contacting registrars in consecutive buckets divides the search space by a constant factor,
and allows learning new peers from more densely-populated routing tables towards the destination.
The procedure mitigates the risk of having malicious peers polluting the table
while still learning rare peers in buckets close to `service_id_hash`.

## Waiting Time Calculation

### Formula

The waiting time is the time advertisers have to
wait before their `ad` is admitted to the `ad_cache`.
The waiting time is given based on the `ad` itself, the advertiser
and the current state of the registrar’s `ad_cache`.

The waiting time for an advertisement MUST be calculated using:

```text
w(ad) = E × (1/(1 - c/C)^P_occ) × (c(ad.service_id_hash)/C + score(getIP(advertiser.addrs)) + G)
```

- `c`: Current cache occupancy
- `c(ad.service_id_hash)`: Number of advertisements for `service_id_hash` in cache
- `getIP(advertiser.addrs)` is a function to get the IP addresses
from the multiaddresses of the advertiser's connection information.
- `score(getIP(advertiser.addrs))`: IP similarity score (0 to 1).
Refer to the [IP Similarity Score section](#ip-similarity-score)

Section [System Parameters](#system-parameters) can be referred
for the definitions of the remaining parameters in the formula.

Issuing waiting times promote diversity in the `ad_cache`.
It results in high waiting times and slower admission for malicious advertisers
using Sybil identities from a limited number of IP addresses.
It also promotes less popular services with fast admission
ensuring fairness and robustness against failures of single registrars.

### Scaling

The waiting time is normalized by the ad’s expiry time `E`.
It binds waiting time to `E` and allows us to reason about the number of incoming requests
regardless of the time each `ad` spends in the `ad_cache`.

### Occupancy Score

```text
occupancy_score = 1 / (1 - c/C)^P_occ
```

The occupancy score increases progressively as the cache fills:

- When `c << C`: Score ≈ 1 (minimal impact)
- As the `ad_cache` fills up, the score will be amplified by the divisor of the equation.
The higher the value of `P_occ`, the faster the increase.
Implementations should consider this while setting the value for `P_occ`
- As `c → C`: Score → ∞ (prevents overflow)

### Service Similarity

```text
service_similarity = c(ad.service_id_hash) / C
```

The service similarity score promotes diversity:

- Low when `service_id_hash` has few advertisements in cache. Thus lower waiting time.
- High when `service_id_hash` dominates the cache. Thus higher waiting time.

### IP Similarity Score

The IP similarity score is used to detect and limit
Sybil attacks where malicious advertisers create multiple advertisement requests
from the same network or IP prefix.

> The IP being refered to here is NOT the ad's but the one from the advertiser connection information.

Registrars MUST use an IP similarity score to
limit the number of requests coming from the same subnetwork
by increasing their waiting time.
The IP similarity mechanism MUST:

- Calculate a score (0-1): higher scores indicate similar IP prefixes (potential Sybil attacks)
- Track IP addresses as a multiset: each IP is counted once per
`ad_cache` entry that uses it
(see [Advertisement Cache](#advertisement-cache) for what constitutes an entry)
- MUST update the count once per `ad_cache` entry, when:
  - A new entry is admitted to the `ad_cache`: MUST increment the count for that IP
  - An entry expires after time `E`: MUST decrement the count for that IP
- Recalculate score for each registration attempt

#### Tree Structure

We RECOMMEND using an IP tree data structure
to efficiently track and calculate IP similarity scores.
An IP tree is a binary tree that stores
IPs used by advertiser currently present in the `ad_cache`.
This data structure provides logarithmic time complexity
for insertion, deletion, and score calculation.
Implementations MAY use alternative data structures
as long as they satisfy the requirements specified above.
Apart from root, the IP tree is a 32-level binary tree where:

- Each vertex stores `IP_counter`, a count of `ad_cache` entries whose
IP passes through it. It is initially set to 0.
- Edges represent bits (0/1) in IPv4 binary representation
- When an entry is admitted to the `ad_cache`, its IPv4 address
increments the counters along its path once for that entry, using the
[`ADD_IP_TO_TREE()` algorithm](#add_ip_to_tree-algorithm) - a multi-service
advertiser's IP is incremented once per service, one entry per service.
- Every time a waiting time is calculated for a registration attempt,
the registrar calculates the IP similarity score for the advertiser's IP address.
using [`CALCULATE_IP_SCORE()` algorithm](#calculate_ip_score-algorithm).
- When an entry is removed from the `ad_cache` after `E`, the registrar
decrements the counters along its IP's path once for that entry, using the
[`REMOVE_FROM_IP_TREE()` algorithm](#remove_from_ip_tree-algorithm) -
the IP's effect on the score reaches zero only once every entry using
it has been removed.
- All the algorithms work efficiently with O(32) time complexity.
- The root `IP_counter` tracks the total count of `ad_cache` entries

#### `ADD_IP_TO_TREE()` algorithm

The algorithm traverses the tree following the IP's binary representation,
incrementing counters at each visited node.

```text
procedure ADD_IP_TO_TREE(tree, IP):
    v ← tree.root
    bits ← IP.toBinary()
    for i in 0, 1, ..., 31:
        v.IP_counter ← v.IP_counter + 1
        if bits[i] = 0:
            v ← v.left
        else:
            v ← v.right
        end if
    end for
end procedure
```

#### `CALCULATE_IP_SCORE()` algorithm

The algorithm traverses the tree following the IP's binary representation
to detect how many IPs share common prefixes, providing a Sybil attack measure.
At each node, if the `IP_counter` is larger than expected in a perfectly balanced tree,
it indicates too many IPs share that prefix, incrementing the similarity score.

```text
procedure CALCULATE_IP_SCORE(tree, IP):
    v ← tree.root
    score ← 0
    bits ← IP.toBinary()
    for i in 0, 1, ..., 31:
        if bits[i] = 0:
            v ← v.left
        else:
            v ← v.right
        end if
        if v.IP_counter > tree.root.IP_counter / 2^i:
            score ← score + 1
        end if
    end for
    return score / 32
end procedure
```

#### `REMOVE_FROM_IP_TREE()` algorithm

This algorithm traverses the tree following the IP's binary representation,
decrementing counters at each visited node.

```text
procedure REMOVE_FROM_IP_TREE(tree, IP):
    v ← tree.root
    bits ← IP.toBinary()
    for i in 0, 1, ..., 31:
        v.IP_counter ← v.IP_counter - 1
        if bits[i] = 0:
            v ← v.left
        else:
            v ← v.right
        end if
    end for
end procedure
```

Implementations can extend the IP tree algorithms to IPv6
by using a 128-level binary tree,
corresponding to the 128-bit length of IPv6 addresses.

### Safety Parameter

The safety parameter `G` ensures waiting times never reach zero even when:

- Service similarity is zero (new service).
- IP similarity is zero (completely distinct IP)

It prevents `ad_cache` overflow in cases when attackers try to
send `ads` for random services or from diverse IPs.

### Lower Bound Enforcement

To prevent "ticket grinding" attacks where advertisers
repeatedly request new tickets hoping for better waiting times,
registrars MUST enforce lower bounds.

Invariant: a newly issued waiting time at time `t_current`
MUST NOT be smaller than a previously issued waiting time
by more than the elapsed time since that waiting time was issued.

Formally:

```text
w_new ≥ w_previous - (t_current - t_previous)
```

For each `service_id_hash`, the registrar MUST maintain:

- `bound(service_id_hash)`: the last issued waiting time
- `timestamp(service_id_hash)`: the time at which the waiting time was issued

For each `IP` in the IP tree, the registrar MUST maintain:

- `bound(IP)`: the last issued waiting time
- `timestamp(IP)`: the time at which the waiting time was issued

The final waiting time respects the lower bound only if
both service-level and IP-level bounds are enforced.

Service-level entries are bounded by the number of distinct
`service_id_hash` values currently tracked in the registrar state.

IP-level entries are bounded by the number of distinct `IPs`
present in advertisements currently tracked in the registrar state.

**Lower bounds SHOULD be calculated as follows:**

When a `service_id_hash` first enters the registrar state,
the registrar sets:

```text
bound(service_id_hash) = 0
timestamp(service_id_hash) = current_time
```

When an IP first enters the registrar state,
the registrar sets:

```text
bound(IP) = 0
timestamp(IP) = current_time
```

When a new ticket request arrives at time `t_current`,
the registrar first calculates the base waiting time `w_base`
using the [waiting time formula](#formula).

For the corresponding `service_id_hash`,
the registrar calculates the elapsed time since the bound
was last updated:

```text
elapsed_service_time =
  t_current - timestamp(service_id_hash)
```

It then calculates the remaining service-level lower bound:

```text
remaining_service_bound =
  bound(service_id_hash) - elapsed_service_time
```

`remaining_service_bound` MAY be negative if the elapsed time
exceeds the previous bound. This is expected and MUST NOT
be clamped to zero.

The service-level waiting time is then calculated as:

```text
w_service =
  max(w_base, remaining_service_bound)
```

After the ticket is issued, the registrar updates the
service-level lower-bound state only if the base waiting time
exceeds the remaining service-level bound:

```text
if w_base > remaining_service_bound:
  bound(service_id_hash) = w_service
  timestamp(service_id_hash) = t_current
```

The same logic is applied for each IP associated with
the advertisement:

```text
elapsed_ip_time =
  t_current - timestamp(IP)

remaining_ip_bound =
  bound(IP) - elapsed_ip_time

w_ip =
  max(w_base, remaining_ip_bound)

if w_base > remaining_ip_bound:
  bound(IP) = w_ip
  timestamp(IP) = t_current
```

The final waiting time issued in the ticket is the maximum
of the service-level and IP-level waiting times:

```text
w_final = max(w_service, w_ip_1, w_ip_2, ...)
```

The lower-bound state is removed when the corresponding
entry expires.

This ensures that the final issued waiting time respects
both the service-level and IP-level lower-bound rules.

## Implementation Notes

### Client and Server Mode

Logos discovery respects the client/server mode distinction
from the base Kad-dht specification:

- **Server mode nodes**: MAY be Discoverer, Advertiser or Registrar
- **Client mode nodes**: MUST be only Discoverer

Implementations MAY include incentivization mechanisms
to encourage peers to participate as advertisers or registrars,
rather than operating solely in client mode.
This helps prevent free-riding behavior,
ensures a fair distribution of network load,
and maintains the overall resilience and availability of the discovery layer.
Incentivization mechanisms are beyond the scope of this RFC.

### Bucket Management

#### Bucket Representation

For simplicity in this RFC, we represent each bucket as a list of peer IDs.
However, in a full implementation, each entry in the bucket
MUST store complete peer information necessary to enable communication.

#### Bucket Size

The number of entries a bucket can hold is implementation-dependent:

- Smaller buckets → lower memory usage but reduced resilience to churn
- Larger buckets → better redundancy but increased maintenance overhead

Implementations SHOULD ensure that each bucket contains only unique peers.
If the peer to be added is already present in the bucket,
the implementation SHOULD NOT create a duplicate entry and
SHOULD instead update the existing entry.

#### Bucket Overflow Handling

When a bucket reaches its maximum capacity and a new peer needs to be added,
implementations SHOULD decide how to handle the overflow.
The specific strategy is implementation-dependent,
but implementations MAY consider one of the following approaches:

- **Least Recently Used (LRU) Eviction:**
   Replace the peer that was least recently contacted or updated.
   This keeps more active and responsive peers in the routing table.

- **Least Recently Seen (LRS) Eviction:**
   Replace the peer that was seen (added to the bucket) earliest.
   This provides a time-based rotation of peers.

- **Ping-based Eviction:**
   When the bucket is full, ping the least recently contacted peer.
   If the ping fails, replace it with the new peer.
   If the ping succeeds, keep the existing peer and discard the new one.
   This prioritizes responsive, reachable peers.

- **Reject New Peer:**
   Keep existing peers and reject the new peer.
   This strategy assumes existing peers are more stable or valuable.

- **Bucket Extension:**
   Dynamically increase bucket capacity (within reasonable limits) when overflow occurs,
   especially for buckets closer to the center ID.

Implementations MAY combine these strategies or use alternative approaches
based on their specific requirements for performance, security, and resilience.

## References

[0] [Kademlia: A Peer-to-Peer Information System Based on the XOR Metric](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)

[1] [DISC-NG: Robust Service Discovery in the Ethereum Global Network](https://ieeexplore.ieee.org/document/10629017)

[2] [libp2p Kademlia DHT specification](https://github.com/libp2p/specs/blob/e87cb1c32a666c2229d3b9bb8f9ce1d9cfdaa8a9/kad-dht/README.md)

[3] [Go implementation](https://github.com/libp2p/go-libp2p-kad-dht)

## Appendix

This appendix provides detailed explanations of some algorithms
and helper procedures referenced throughout this RFC.
To maintain clarity and readability in the main specification,
the body contains only the concise pseudocode and high-level descriptions.

### Advertiser Algorithms Explanation

Refer to the [Advertisement Algorithm section](#example-advertise-algorithm) for the pseudocode.

#### ADVERTISE() algorithm explanation

1. Initialize a map `ongoing` for tracking which registrars are currently being advertised to.
2. Initialize `AdvT(service_id_hash)` by bootstrapping peers
from the advertiser’s `KadDHT(peerID)`
using the formula described in the [Distance section](#distance).
3. Iterate over all buckets (i = 0 through `m-1`),
where `m` is the number of buckets in `AdvT(service_id_hash)` and `ongoing` map.
Each bucket corresponds to a particular distance from the `service_id_hash`.
    1. `ongoing[i]` contains list of  registrars with active (unexpired) registrations
    or ongoing registration attempts at a distance `i`
    from the `service_id_hash` of the service that the advertiser is advertising for.
    2. Advertisers continuously maintain up to `K_register` active (unexpired) registrations
    or ongoing registration attempts in every bucket of the `ongoing` map for its service.
    Increasing `K_register` makes the advertiser easier to find
    at the cost of increased communication and storage costs.
    3. Pick a random registrar from bucket `i` of `AdvT(service_id_hash)` to advertise to.
        - `AdvT(service_id_hash).getBucket(i)` → returns a list of registrars in bucket `i`
        from `AdvT(service_id_hash)`
        - `.getRandomNode()` → function returns a random registrar node.
        The advertiser tries to place its advertisement into that registrar.
        The function remembers already returned nodes
        and never returns the same one twice during the same `ad` placement process.
        If there are no peers, it returns `None`.
    4. if we get a peer then we add that to that bucket `ongoing[i]`
    5. Build the advertisement object `ad` containing `service_id_hash`, `peerID`, and `addrs`
    (Refer to the [Advertisement section](#advertisement)).
    Then it is signed by the advertiser using the node’s private key (Ed25519 signature)
    6. Then send this `ad` asynchronously to the selected registrar.
    The helper `ADVERTISE_SINGLE()` will handle registration to a single registrar.
    Asynchronous execution allows multiple `ads` (to multiple registrars) to proceed in parallel.

#### ADVERTISE_SINGLE() algorithm explanation

`ADVERTISE_SINGLE()` algorithm handles registration to one registrar at a time

1. Initialize `ticket` to `None` as we have not yet got any ticket from registrar
2. Keep trying until the registrar confirms or rejects the `ad`.
    1. Send the `ad` to the registrar using `Register` request.
    Request structure is described in section [Register Message Structure](#register-message).
    If we already have a ticket, include it in the request.
    2. The registrar replies with a `response`.
    Refer to the [Register Message Structure section](#register-message) for the response structure
    3. Add the list of peers returned by the registrar `response.closerPeers` to `AdvT(service_id_hash)`.
    Refer to the [Distance](#distance section) on how to add.
    4. If the registrar accepted the advertisement successfully,
    wait for `E` seconds,
    then stop retrying because the `ad` is already registered.
    5. If the registrar says “wait” (its cache is full or overloaded),
    sleep for the time written in the ticket `ticket.t_wait_for`(but not more than `E`).
    Then update `ticket` with the new one from the registrar, and try again.
    6. If the registrar rejects the ad, stop trying with this registrar.
3. Remove this registrar from the `ongoing` map in bucket i (`ongoing[i]`),
since we’ve finished trying with it.

### Discoverer Algorithms

#### LOOKUP(service_id_hash) algorithm explanation

Refer to the [Lookup Algorithm section](#example-lookup-algorithm) for the pseudocode.

1. `DiscT(service_id_hash)` is initialized by
bootstrapping peers from the discoverer’s `KadDHT(peerID)`
using the formula described in the [Distance section](#distance).
2. Create an empty set `foundPeers` to store unique advertisers peer IDs discovered during the lookup.
3. Go through each bucket of `DiscT(service_id_hash)` —
from farthest (`b₀`) to closest (`bₘ₋₁`) to the service ID `service_id_hash`.
For each bucket, query up to `K_lookup` random peers.
    1. Pick a random registrar node from bucket `i` of `DiscT(service_id_hash)` to query
        1. `DiscT(service_id_hash).getBucket(i)` → returns a list of registrars
        in bucket `i` from `DiscT(service_id_hash)`
        2. `.getRandomNode()` → function returns a random registrar node.
        The discover queries this node to get `ads` for a particular service ID `service_id_hash`.
        The function remembers already returned nodes and never returns the same one twice.
        If there are no peers, it returns `None`.
    2. A `GET_ADS` request is sent to the selected registrar peer.
    Refer to the [GET_ADS Message section](#get_ads-message)
    to see the request and response structure for `GET_ADS`.
    The response returned by the registrar node is stored in `response`
    3. The `response` contains a list of advertisements `response.ads`.
    A queried registrar returns at most `F_return` advertisements.
    If it returns more we can just randomly keep `F_return` of them.
    For each advertisement returned:
        1. Verify its digital signature for authenticity.
        2. Add the advertiser’s peer ID `ad.peerID` to the list `foundPeers`.
    4. The `response` also contains a list of peers `response.closerPeers`
    that is inserted into `DiscT(service_id_hash)`
    using the formula described in the [Distance section](#distance).
    5. Stop early if enough advertiser peers (`F_lookup`) have been found.
    For popular services `F_lookup` advertisers are generally found in the initial phase
    from the farther buckets and the search terminates.
    But for unpopular ones it might take longer but not more than `O(log N)`
    where N is number of nodes participating in the network as registrars.
    6. If early stop doesn’t happen then the search stops
    when no unqueried registrars remain in any of the buckets.
4. Return `foundPeers` which is the final list of discovered advertisers
that provide service `service_id_hash`

Making the advertisers and discoverers walk towards `service_id_hash` in a similar fashion
guarantees that the two processes overlap and contact a similar set of registrars that relay the `ads`.
At the same time, contacting random registrars in each encountered bucket using `getRandomNode()`
makes it difficult for an attacker to strategically place malicious registrars in the network.
The first bucket `b_0(service_id_hash)` covers the largest fraction of the key space
as it corresponds to peers with no common prefix to `service_id_hash` (i.e. 50% of all the registrars).
Placing malicious registrars in this fraction of the key space
to impact service discovery process would require considerable resources.
Subsequent buckets cover smaller fractions of the key space,
making it easier for the attacker to place Sybils
but also increasing the chance of advertisers already gathering enough `ads` in previous buckets.

Parameters `F_return` and `F_lookup` play an important role
in setting a compromise between security and efficiency.
A small value of `F_return << F_lookup` increases the diversity of the source of `ads`
received by the discoverer but increases search time,
and requires reaching buckets covering smaller key ranges where eclipse risks are higher.
On the other hand, similar values for `F_lookup` and `F_return` reduce overheads
but increase the danger of a discoverer receiving `ads` uniquely from malicious nodes.
Finally, low values of `F_lookup` stop the search operation early,
before reaching registrars close to the service hash,
contributing to a more balanced load distribution.
Implementations should consider these trade-offs carefully when selecting appropriate values.

### Registrar Algorithms

#### `REGISTER()` algorithm explanation

Refer to the [Register Algorithm section](#example-register-algorithm) for the pseudocode

1. Prepare a response ticket `response.ticket` linked to this `ad`.
2. Calculate how long the advertiser should wait `t_wait` before being admitted.
Refer to the [Waiting Time Calculation section](#waiting-time-calculation) for details.
3. Check if this is the first registration attempt (no ticket yet):
    1. If yes then it’s the first try. The advertiser must wait for the full waiting time `t_wait`.
    The ticket’s creation time `t_init` and last-modified time `t_mod` are both set to `NOW()`.
    2. If no, then this is a retry, so a previous ticket exists.
        1. Validate that the ticket is properly signed by the registrar
        and belongs to this same advertisement.
        2. Ensure the retry is happening within the allowed time window `δ` after the scheduled time.
        If the advertiser waits too long or too short, the ticket is invalid.
        3. Calculate how much waiting time is left `t_remaining`
        by subtracting how long the advertiser has already waited
        (`NOW() - ticket.t_init`) from `t_wait`.
4. Check if the remaining waiting time `t_remaining` is less than or equal to 0.
This means the waiting time is over.
`t_remaining` can be 0 also when the registrar decides that
the advertiser doesn’t have to wait for admission to the `ad_cache`(waiting time `t_wait` is 0).
    1. If yes, add the `ad` to `ad_cache` and confirm registration.
    If an entry for this `peer_id` and `service_id` already exists,
    this replaces it.
    The advertisement is now officially registered.
    2. If no, then there is still time to wait.
    In this case registrar does not store `ad` but instead issues a ticket.
        1. set `response.status` to `wait`
        2. Update the ticket with the new remaining waiting time `t_wait_for`
        3. Update the ticket last modification time `t_mod`
        4. Sign the ticket again. The advertiser will retry later using this new ticket.
5. Add a list of peers closer to the `ad.service_id_hash` using the `GETPEERS()` function
to the response (the advertiser uses this to update `AdvT(service_id_hash)`).
6. Send the full response back to the advertiser

Upon receiving a ticket, the advertiser waits for the specified `t_wait` time
before trying to register again with the same registrar.

Tickets can only be used within registration window `δ`,
preventing attackers from accumulating and batch-submitting tickets.
Clock synchronization is not required as advertisers only use `t_wait_for` values.

Waiting times are recalculated on each retry based on current cache state,
ensuring advertisers accumulate waiting time and are eventually admitted.
This stateless design protects registrars from memory exhaustion and DoS attacks.

The waiting time `t_wait` is not fixed.
Each time an advertiser tries to register,
the registrar recalculates a new waiting time.
The remaining time `t_remaining` is then computed as the difference between
the new waiting time and the time the advertiser has already waited,
as recorded in the ticket.
With every retry, the advertiser accumulates waiting time
and will eventually be admitted.
However, if the advertiser misses its registration window
or fails to include the last ticket,
it loses all accumulated waiting time and
must restart the registration process from the beginning.
Implementations must consider these factors
while deciding the registration window `δ` time.

This design lets registrars prioritize advertisers that have waited longer
without keeping any per-request state before the `ad` is admitted to the cache.
Because waiting times are recalculated
and tickets are stored only on the advertiser’s side,
the registrar is protected from memory exhaustion
and DoS attacks caused by inactive or malicious advertisers.
