# rustfs-gateway-stream — MAP

Body, byte-stream and payload primitives. **No protocol vocabulary of any kind lives here.**
This crate exists because a streaming output field would otherwise make `rustfs-gateway-types` and
`rustfs-gateway-http` depend on each other; if protocol words leak in, that cycle returns in another
shape. Three dependencies (`bytes`, `http`, `bitflags`), zero internal ones.

## Two properties to know before editing

1. **A trailer section is reachable only at end-of-stream.** `PayloadRead::Eof { trailers }` and
   `ReadProgress::Eof { trailers }` own the only `TrailingHeaders` a consumer ever sees. No
   shared mutable slot exists, so "the trailer was never inspected because the consumer looked
   too early" is not a reachable state. Absent trailers are an empty map, never `None`.
2. **Capability negotiation is named and exhaustible.** No `as_any`, no downcast. A transport
   reads `PayloadCaps` and calls a named accessor; every refusal returns the payload unchanged
   plus a named reason, and every adaptation returns an `AdaptCost` recorded in `StreamMetrics`.
3. **A refusal of the kernel-side path is attributable.** `try_into_file_region_for` answers with
   one of four named `NoZeroCopy` reasons, each counted separately, and it checks the body's
   `VerificationObligation` *before* the transport's capabilities — a body the gateway promised to
   verify is never reported as one the transport could have sent.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, re-exports, the two properties above | Always first |
| `src/payload.rs` | `Payload` (Empty/Bytes/Vectored/File/Reader/Stream), `caps`, `len_hint`, `try_into_file_region[_for]`, `try_as_vectored`, `try_into_reader`, `try_into_stream`, `AdaptRefusal` | Adding a payload shape, or negotiating a transfer strategy |
| `src/zero_copy.rs` | `TransportCaps`, `VerificationObligation`, `ZeroCopyQuery`, `NoZeroCopy` — the negotiation that replaces a downcast | A transport wants `sendfile`, or a refusal needs attributing |
| `src/observer.rs` | `ByteObserver`, `ObserverOutcome`, `ByteCounter` — several consumers of one borrowed run | Adding a digest, or asserting a single pass |
| `src/caps.rs` | `PayloadCaps` bits and `validate_caps` (the `KNOWN_LENGTH` ⇔ length-hint rule) | Adding a capability bit, or a producer is rejected at construction |
| `src/stream.rs` | Push half: `PayloadStream`, `PayloadRead`, `BoxPayloadStream` | Writing a producer that owns its buffers |
| `src/read.rs` | Pull half: `AsyncPayloadRead`, `ReadProgress`, `BoxPayloadReader` | Writing a consumer that owns its buffer |
| `src/adapt.rs` | `AdaptCost`, `Adapt`, `MemoryStream`, `MemoryReader`, `StreamToReader` (Copy), `ReaderToStream` (Buffer) | Changing what an adaptation costs, or adding an adapter |
| `src/metrics.rs` | `StreamMetrics`: `adapt_copies_total`, `adapt_copied_bytes_total`, `adapt_buffers_total`, `zero_copy_refusals(reason)`, `zero_copy_refused_bytes_total` | Wiring the counters into an exporter, or writing a zero-copy gate |
| `src/body.rs` | `Body`: the one owned body type layers above name | Passing a body through a pipeline stage |
| `src/byte_stream.rs` | `ByteStream` + `RemainingLength`: declared-length bookkeeping; short body ⇒ `IncompleteBody`, overlong ⇒ `LengthMismatch` | Wrapping a producer whose length was announced up front |
| `src/trailers.rs` | `TrailingHeaders` | Building a trailer section at the end of a decoded body |
| `src/error.rs` | `StreamError` + `StreamErrorKind`, and `bytes_before_error` | Deciding what an aborted transfer may still commit |
| `src/file_region.rs` | `FileRegion` (unix): owned fd + offset + len, overflow refused at construction | Adding a kernel-side transfer path |
| `src/tests/` | `eof_trailers` (ordering), `caps_matrix` (shape × model), `adapt_cost` (cost + counters), `zero_copy` (the four refusals and their order), `observer` (single-pass accounting), `body`, `trailers`, `file_region`, `support` (scripted producers) | Changing any behaviour above |

## Boundaries

- **Never** add an S3 or storage word — not even in a comment. It re-opens the dependency cycle.
- **Never** add a runtime downcast escape hatch. Add a named variant or a named accessor instead.
- **Never** let a `NoZeroCopy` refusal be reported without also being counted, and never reorder
  the checks in `ZeroCopyQuery::refusal`: the verification obligation must refuse first.
- An observer never fails. A consumer of the bytes that can fail is a validation step, and
  validation belongs where the failure can be turned into a wire response.
- **Never** express trailers as `Option<TrailingHeaders>` outside an `Eof` event, and never put
  them behind a shared mutable slot.
- No framing, no back-pressure policy, no `sendfile`/`splice`, no runtime: those need a driver
  and belong to the wire and transport layers.
- `unsafe` is forbidden. Boxed producers are `Pin<Box<dyn …>>` precisely so no pin projection —
  and therefore no `unsafe` — is needed.

## Verify

```bash
cargo test -p rustfs-gateway-stream            # 73 tests
cargo clippy -p rustfs-gateway-stream --all-targets -- -D warnings
bash scripts/check_layer_dependencies.sh
```
