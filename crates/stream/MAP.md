# rustfs-gateway-stream — MAP

Body, byte-stream and payload primitives. **No protocol vocabulary of any kind lives here.**
This crate exists because a streaming output field would otherwise make `rustfs-gateway-types` and
`rustfs-gateway-http` depend on each other; if protocol words leak in, that cycle returns in another
shape. Four dependencies (`bitflags`, `bytes`, `http`, `http-body`), zero internal ones; a fifth,
`tokio` with `io-util` alone, exists only behind the `tokio-io` feature and is off by default.

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
| `src/body.rs` | `Body`: the owned body and truthful `http_body::Body` view; `BodyTransport` → `RefusedBodyTransport` → `CopiedFileBody`: the opaque typestate that keeps verification attached while selecting kernel, streaming or copied delivery | Passing a body through a stage, negotiating response delivery, or implementing a copied file writer |
| `src/byte_stream.rs` | `ByteStream` + `RemainingLength`: declared-length bookkeeping; short body ⇒ `IncompleteBody`, overlong ⇒ `LengthMismatch` | Wrapping a producer whose length was announced up front |
| `src/tokio_io.rs` | `tokio-io` feature only. `TokioReadPayload`: a `tokio::io::AsyncRead` as a pull-model body, filling the consumer's own slice, held to an optional declared length. `PayloadReader`: a push-model body as `tokio::io::AsyncRead`, serving each chunk out of the producer's buffer; `trailers()` answers only after end-of-stream. Both `AdaptCost::Free` | Bridging a tokio reader, or a handler that drains a body through `AsyncRead`, to the data plane |
| `src/trailers.rs` | `TrailingHeaders` | Building a trailer section at the end of a decoded body |
| `src/error.rs` | `StreamError` + `StreamErrorKind`, and `bytes_before_error` | Deciding what an aborted transfer may still commit |
| `src/file_region.rs` | `FileRegion` (unix): owned fd + offset + len, overflow refused at construction | Adding a kernel-side transfer path |
| `src/tests/` | `eof_trailers` (ordering and concrete EOF shape), `cancellation` (drop ownership), `caps_matrix` (shape × model), `adapt_cost` (cost + counters), `zero_copy` (the four refusals and their order), `observer` (single-pass accounting), `body`, `trailers`, `file_region`, `tokio_io` (both bridges, `tokio-io` feature only), `support` (scripted producers) | Changing any behaviour above |
| `src/tests/pay_ledger.rs` | The 28 `c-pay-*` rows, each bound to a case body, named guard, or live external acceptance test; the meta-checks that stop the table rotting | Adding a payload case, or changing an external proof |
| `src/tests/pay_cases.rs`, `src/tests/pay_scale.rs` | The case bodies. `pay_scale` holds the gibibyte gate and the no-read-ahead measurement, each with the control that proves its instrument can report the opposite | Changing what a `c-pay-*` row asserts |

## Boundaries

- **Never** add an S3 or storage word — not even in a comment. It re-opens the dependency cycle.
- **Never** add a runtime downcast escape hatch. Add a named variant or a named accessor instead.
- **Never** let a `NoZeroCopy` refusal be reported without also being counted, and never reorder
  the checks in `ZeroCopyQuery::refusal`: the verification obligation must refuse first.
- An observer never fails. A consumer of the bytes that can fail is a validation step, and
  validation belongs where the failure can be turned into a wire response.
- **Never** express trailers as `Option<TrailingHeaders>` outside an `Eof` event, and never put
  them behind a shared mutable slot. `PayloadReader::trailers` is the one accessor that answers
  `None`, and `None` there means exactly "no read has observed end-of-stream yet": a body that
  ended without a trailer field answers `Some` of an empty map, and the value is filled from the
  `Eof` event alone — no producer or second consumer can write it.
- **Never** make `tokio` mandatory, inherit the workspace entry (it carries `rt`), or enable a
  tokio feature other than `io-util` in this crate: without `rt` there is no `tokio::spawn`, so
  a read-ahead task stays unwritable here. `check_no_spawn_in_stream.sh` checks every word.
- No framing, no back-pressure policy, no `sendfile`/`splice`, no runtime: those need a driver
  and belong to the wire and transport layers.
- `unsafe` is forbidden. Boxed producers are `Pin<Box<dyn …>>` precisely so no pin projection —
  and therefore no `unsafe` — is needed.

## Verify

```bash
cargo test -p rustfs-gateway-stream            # 98 tests
cargo test -p rustfs-gateway-stream --features tokio-io tokio_io   # the 23 bridge tests
cargo clippy -p rustfs-gateway-stream --all-targets --features tokio-io -- -D warnings
cargo tree -p rustfs-gateway-stream -e normal | grep -c tokio      # 0: the feature is off by default
bash scripts/check_layer_dependencies.sh
bash scripts/check_no_spawn_in_stream.sh
```
