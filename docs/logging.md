# Logging policy

Read this guide before adding or changing logs: useful logs let people diagnose runtime behavior without reading the source. Choose levels mindfully, describe actions and outcomes clearly, and use readable field names. Sensitive data must be omitted or redacted, and large field values must be bounded.

## Topics and component filtering

- Use exactly two space-separated topics in every library logging scope: `libp2p` and one stable component name.

- Name the component after its capability or protocol, using kebab case for multiword names, for example `address-manager`, `peer-id-auth`, and `hole-punching`.

- Prefer full words over implementation abbreviations, such as `connection-manager` and `ip-address`.

- Reuse the component name across its implementation and helper modules.

- Choose the component by ownership, rather than giving every file a new filter. For example, AutoTLS's ACME helpers use `auto-tls`, Mplex's coder and channels use `mplex`, and all service discovery modules use `service-discovery`.

- Do not create topics for a version, role, operation, or helper filename. Put that detail in structured fields when useful, or compile with `-d:chronicles_line_numbers:on` to identify the source module.

- Keep distinct implementations in distinct components: `gossipsub`, `floodsub`, and shared `pubsub` infrastructure; likewise individual transports and muxers. A `pubsub` filter alone therefore does not select `gossipsub` or `floodsub`.

- Remember that topics are independent tags, not a hierarchy: `libp2p autonat v2 client` creates four separate filters.

```nim
logScope:
  topics = "libp2p autonat"
```


## Choose a level

Severity represents operational impact and the action required from the library user, not the wording of a message or the presence of an `except` branch.

| Level | Audience and frequency | Meaning |
| --- | --- | --- |
| `error` | Operators; rare | An enabled component or background loop has stopped working and needs investigation. |
| `warn` | Library users; low frequency | The library remains usable, but a local configuration, API call, callback, or resource condition needs attention. |
| `info` | Operators; low frequency | A normal start, stop, or other lifecycle milestone. |
| `debug` | Developers troubleshooting one operation | A bounded result or fallback summary. |
| `trace` | Developers diagnosing traffic; potentially high frequency | Per-peer, per-message, per-stream, packet, retry, cancellation, and expected network detail. |

Malformed input, handshake failures, timeouts, and rejected peer requests are expected on a public P2P network. Use `trace`, or `debug` for a bounded summary of a whole operation; peers must not be able to create `warn`/`error` noise merely by sending invalid input. Local API misuse or an application callback exception can warrant `warn` because the library user can correct it.

Normal cancellation and handled exceptions may need no log. When returning or re-raising a failure, let the caller report it rather than duplicating the event. Individual retries use `trace` or `debug`; exhaustion warrants `error` only when it leaves an enabled component or requested feature unavailable. A cancellation contract violation can warrant `warn`; an internal invariant violation warrants `error`, or `debug` if recovered locally.

## Choose a log message

Describe the runtime action and its outcome so a reader understands what happened. Avoid vague text such as "Processing failed" and source-code narration such as "Entered handler". Keep event messages stable and put variable values in structured fields so events remain easy to search and compare.

```nim
# Vague message and opaque field name
debug "Processing failed", p = peerId

# At the end of an unsuccessful dial operation
debug "Dial failed after all addresses were tried", peerId, err = exc.msg
```

## Structured fields

Choose fields that explain the event. Names are for people reading logs, so prefer `peerId` over a local variable name such as `p`. Names must have at least three characters, except for `id` and `ip`; one-character names are never allowed.

| Field | Use |
| --- | --- |
| `err` | Human-readable exception or error-result text, normally `exc.msg`. |
| `errType` | Exception class, normally `exc.name`, only when it changes the diagnostic or operator response. |
| `peerId` | A local or remote peer identifier; add a separate direction or role field when needed. |
| `address` / `addresses` | One network or multiaddress value / a collection of them. |
| `protocol` | A negotiated or requested protocol identifier. |
| `operation` | A stable operation name when the event otherwise lacks context. |
| `attempt` / `maxAttempts` | Current and maximum retry counts. |
| `messageType` | Protocol message kind; never exception text. |
| `messageSize` | Encoded or payload size in bytes. |
| `reason` | A bounded validation, rejection, or decision reason when no exception or error result exists. |

Use `err`, not `description`, `error`, `message`, or `msg`, for exception text.

### Safe, bounded values

Sensitive data **must be omitted or redacted before logging**, at every level. This includes private keys, credentials, tokens, and sensitive payload contents; check exception text too. Truncation is not redaction: `shortLog` can still expose sensitive leading and trailing bytes or characters.

Prefer metadata such as counts, `messageType`, `messageSize`, and `reason` over complete peer-controlled messages, buffers, records, certificates, or tickets. When a preview is useful, use an appropriate `shortLog` for long strings, bytes, messages, and collections. Keep payload previews out of `warn` and `error`. Shortened identifiers help diagnosis but are not guaranteed unique.

### Type formatters

Every project-defined type used as a log field must provide `shortLog` and a `chronicles.formatIt` registration that delegates to it. Define them beside the type. `shortLog` selects a safe, bounded representation; `formatIt` applies it automatically when the value is logged:

```nim
func shortLog*(value: MyType): auto =
  (itemCount: value.items.len)

chronicles.formatIt(MyType):
  shortLog(it)
```

Reuse [the shared utilities](../libp2p/utils/shortlog.nim) for collections and `Opt[T]`. Collections preview at most five items by default; absent options use `<unset>`. Both helpers prefer the inner value's `shortLog` and otherwise use `$`, so check that each inner representation is safe and bounded. The collection `averageItemLength` argument is only an allocation hint, not an output limit.

Where the audit needs an explicit concrete overload, keep a thin wrapper that delegates to the generic helper, as in [the Rendezvous formatters](../libp2p/protocols/rendezvous/protobuf.nim).

Before submitting changes, install `lint` library with `nimble install https://github.com/iftech/nim-lint` and run `nim r linter.nim` from the repository root. `linter.nim` checks event-message style, field naming, and selected payload/formatter patterns; passing it does not replace reviewing field contents for sensitive data or unbounded output.
