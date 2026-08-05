# rustfs-gateway-http — crate map

The wire acceptance layer: the first stage of the pipeline, and the last place a raw
`http::Request` exists. P3-01 landed acceptance, the effective-host determination, framing rules
W-1 to W-6, and the borrowed header and query views; P3-03 added the single-pass `aws-chunked`
ingest pipeline on top of them, without reshaping them.

Four properties live here. Everything else in the crate exists to serve them.

1. **The raw request stops here.** `WireRequest::accept` consumes an `http::Request` and publishes
   no accessor returning `HeaderMap`, `Uri`, `Parts` or the request; `into_body` yields the body
   alone. `tests/boundary_guards.rs` asserts this over the source, and proves the guard can fail.
2. **Ambiguity is rejected, never resolved.** Two sources disagreeing about one fact is a
   rejection — including when they agree byte-for-byte (two identical `Content-Length` headers,
   two identical `Host` headers). The tolerant case is the probe that tells an attacker which end
   of the chain wins.
3. **Signing reads raw bytes, routing reads derived values.** `EffectiveHost::as_str` is
   normalised; the original bytes are reachable only through `raw_for_signing() -> &RawHost`.
   Normalisation is many-to-one, so a signature over the normalised form would be valid for every
   spelling that normalises to it. `RawHost` is the type `rustfs-gateway-sig`'s
   `CanonicalRequestSpec::new` accepts, and the only one — a `compile_fail` doctest on that
   constructor proves a `&str` is rejected.
4. **The chunk parser runs only when the signature says so.** `ChunkFraming::derive` is the only
   constructor of a framing decision, it reads a `PayloadFramingSource`, and that trait has no
   method that could carry `Content-Encoding`. `IngestPipeline::new` refuses a body the decision
   did not mark framed, so "the parser ran because a header said `aws-chunked`" is not reachable.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, re-exports, the three properties in full | First stop; you can often stop here |
| `src/wire.rs` | `WireRequest`, `accept`, `RawPath`, and the fixed order of checks | You are adding a rule, or wondering which rule fires first |
| `src/host.rs` | `effective_host`/`effective_host_of`, `EffectiveHost`, `RawHost`, `HostSource`, `HostError`, `MAX_HOST_BYTES` — the **only** host determination in the workspace; `rustfs-gateway-sig` consumes it | You touch anything host-, vhost- or signature-related |
| `src/framing.rs` | `Framing`, `BodyLength`, rules W-1..W-5, `validate_chunk_size_line` (W-6) | You are deciding where a body ends |
| `src/header_view.rs` | `HeaderView`, `SignedHeaderList`, canonical-header writing, the repeat and non-UTF-8 policies | You read a header, or build a canonical request |
| `src/query_view.rs` | `QueryIndex` / `QueryView`: offsets, arrival order, repeat policy | You read a query parameter, or route on one |
| `src/metadata.rs` | `x-amz-meta-*` key and value rules, including validation *after* RFC 2047 decoding | You touch user metadata |
| `src/limits.rs` | `Limits`, `LimitKind`, `ChunkLimits` (per-chunk data ceiling, metadata ceiling, chunk count, overhead ratio) | You are adding a ceiling; P3-05 owns the timeouts |
| `src/ingest/mod.rs` | `PayloadFramingSource`, `ChunkFraming`, `DecodedLength`, `validate_decoded_length` — whether the parser runs, and whether the two declared lengths agree | You touch the framing decision or the head cross-checks |
| `src/ingest/decoder.rs` | `ChunkDecoder`: chunk-size lines, the one permitted extension, CRLF rules, every header-decidable ceiling. Emits `(start, len)` events; moves no payload | You are adding a framing rule |
| `src/ingest/signer.rs` | `SigningKeyCache` (one derivation per scope), `ChunkSigner` (one HMAC per chunk, stack string-to-sign, constant-time compare), `ChunkSigningKey`, `ChunkSeed`, `ChunkScope`, `ScopeId` | You touch the chunk signature chain |
| `src/ingest/pipeline.rs` | `IngestPipeline`, `IngestPolicy`: the window, the single pass, verify-before-deliver, `decoded_bytes`, `commit_allowed`, `reject` | You are changing how an upload is read |
| `src/ingest/reject.rs` | `ChunkReject`, `ModeConfusion`, and the 400/403 split | You are adding a refusal |
| `src/reject.rs` | `WireReject`, status and error-code mapping, `may_read_body`, `must_close_connection` | You are adding a rejection, or writing the response |
| `src/text.rs` | `AsciiBuf` and the byte predicates; no protocol meaning | Rarely |
| `tests/host_ambiguity.rs` | 7 positive / 18 negative — every row of the host decision table | You changed `host.rs`; `crates/sig/tests/effective_host.rs` covers the same function from the signature side and must be run too |
| `tests/framing_smuggling.rs` | 4 positive / 19 negative — W-1..W-6 and the body ceiling | You changed `framing.rs` |
| `tests/header_and_query.rs` | 10 positive / 18 negative — tolerance, repeats, metadata, canonicalisation | You changed a view or `metadata.rs` |
| `tests/allocation_budget.rs` | The no-allocation promise, asserted structurally | You changed a view's storage |
| `tests/ingest_framing.rs` | 5 positive / 13 negative — the framing derivation, the mode/length cross-checks, the CL/TE interaction | You changed `ingest/mod.rs` |
| `tests/ingest_chunk_rules.rs` | 5 positive / 26 negative — chunk syntax and every ceiling, including the 4 GiB-chunk regression | You changed `ingest/decoder.rs` |
| `tests/ingest_verify.rs` | 3 positive / 17 negative — the signature chain, "zero bytes delivered from a failing chunk", trailer hand-off | You changed `ingest/signer.rs` or the delivery policy |
| `tests/ingest_perf_gates.rs` | 7 positive / 10 negative — the HMAC budget, the single-pass equality, compaction bounds, the zero-adapting-copy assertion | You changed the pipeline's buffering or the key cache |
| `tests/support/ingest.rs` | Wire-shaped fixtures: a scripted socket, an independently written chunk signer | You need a new malformed body shape |
| `tests/boundary_guards.rs` | Source guards: no raw-request accessor, no lossy UTF-8, lint denials, file shape | You added a public method or a file |

## Shape decisions worth not re-litigating

- **`accept` is generic over the body, not tied to one server.** The kernel stays
  transport-agnostic, and the checks run against whatever headers the transport surfaces. The
  corollary is a maintainer obligation: the facade must hand the request over **as received**. A
  transport that repairs a `Content-Length`/`Transfer-Encoding` pair itself defeats W-1 no matter
  what this crate does.
- **Views are borrowed; the request head is owned.** `WireRequest` has no lifetime parameter — a
  stage that borrowed its head would be self-referential across an await — while `HeaderView`,
  `QueryView` and `RawPath` are created on demand and hold nothing.
- **Nothing is sorted.** `SignedHeaders` is already required to be lowercase and strictly
  ascending, so the list is *verified* in one pass and each name looked up in the `HeaderMap` hash.
  Sorting every header would allocate and would order headers nobody signed.
- **Non-UTF-8 tolerance is exact, not general.** An unrelated header with unreadable bytes is
  skipped by `iter_text` (s3s#597, rustfs#3124: a proxy-injected header took down every
  `PutObject`); an `x-amz-*` or otherwise significant header, or a *signed* one, is a rejection.
  `from_utf8_lossy` appears nowhere and a guard test says so.
- **Metadata is validated twice.** Once as received and once after RFC 2047 decoding, because an
  encoded word is inert on the way in and a `\r\n` on the way out.
- **An escaped query parameter *name* is refused.** `%76ersionId` and `versionId` are one
  parameter with two spellings; a duplicate check before decoding and a lookup after it would see
  different requests.
- **A trailing root dot is stripped in the normalised host, kept in the raw one.** Routing must
  treat `b.example.com.` and `b.example.com` as one bucket; signing must not.
- **Every rejection is decidable from the head.** No rule needs a body byte, so no limit check can
  become a reason to buffer or drain — `WireReject::may_read_body` is unconditionally `false`.
  `ChunkReject` is the deliberate counterpart: it is decidable only from the body, it can be a
  `403`, and it is therefore a separate type rather than a `WireReject` variant.
- **The decoder never derives a signing key, and never will.** The four-step chain lives once, in
  `rustfs-gateway-sig`. `SigningKeyCache` takes a closure and caches the result, so this crate
  holds derived key material but implements no derivation — a security primitive written twice is
  a security primitive that drifts.
- **The consumer's read is the only per-byte copy on the ingest path.** It cannot be removed while
  `VerifyBeforeDeliver` holds, because writing unverified bytes into the consumer's buffer *is*
  delivering them. What has been removed is the per-layer poll, the per-chunk allocation, the
  re-slicing, and the extra pass per digest.
- **Framing overhead is a ratio in parts per thousand, not a float.** The comparison is on the
  data path and integer arithmetic cannot round two configurations onto one behaviour. The
  default of 50 refuses signed chunks below about 1,740 bytes; AWS SDKs do not go below 8 KiB.

- **The authority and the `Host` header are compared byte for byte.** `B.Example.COM` beside
  `b.example.com` is `HostError::Conflict`, not agreement. Case-folding the conflict check is the
  one normalisation that cannot be undone by reading the raw bytes afterwards: once the two
  sources are declared equal, only one of them is ever seen again.

## Deliberate non-dependencies

Three dependencies: `http`, `smallvec`, and `rustfs-gateway-types` for `ErrorCode`. No `hyper`, no
`aws-chunked` decoder, no percent-decoding, no clock. `rustfs-gateway-stream` is present for the
`OwnedWireRequest` alias only. Nothing here depends on `rustfs-gateway-sig`; the edge runs the other
way, which is why the host determination lives here and not there.

## Verify

```bash
cargo test -p rustfs-gateway-http                                  # 174 tests, 122 negative / 52 positive
cargo test -p rustfs-gateway-sig                                   # the signature side of the same host function
cargo clippy -p rustfs-gateway-http -p rustfs-gateway-sig --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/check_license_headers.sh
bash scripts/check_layer_dependencies.sh
bash scripts/check_ring_boundaries.sh
```

## Open for maintainer review

- `EntityTooLarge` maps to `400` in `rustfs-gateway-types`' status table, but an over-large declared body
  is answered `413` here. The divergence is deliberate; if the table is the contract, it moves.
- Only `chunked` alone is accepted as a transfer coding. `gzip, chunked` is legal HTTP and is
  refused; no S3 client is known to send it.
- `SignedHeaderList::parse` requires `host` to be signed. SigV4 requires it, but a presigned flow
  that omits it would be refused before the signature is examined.
- **The duplicated host determination is resolved: there is now one, and it is here.** P2-03 and
  P3-01 each shipped an `effective_host`; `crates/sig/src/host.rs` has been deleted and
  `rustfs-gateway-sig` re-exports this crate's types. Every point on which the two drafts differed
  was resolved towards the stricter reading, and the table is in the `src/host.rs` module docs. One
  of them changes behaviour and wants a maintainer's eye: **the authority/`Host` comparison is now
  byte-exact**, so an h2 request whose `:authority` and `host` differ only in case is a `400` where
  it used to be accepted. No S3 SDK is known to emit that shape, but a case-normalising proxy in
  front of the gateway would.
- **`MAX_HOST_BYTES` dropped from 273 to 263** in the same merge, taking the stricter of the two
  drafts' ceilings. Nothing legitimate is between the two numbers, but it is a configured default
  (`Limits::max_host_bytes`) and therefore observable.
- **The chunk string-to-sign is not checked against a published known-answer vector.** The suite
  builds the expected signature from an independently written implementation of the AWS streaming
  rules rather than calling the code under test, which catches a self-consistent mistake but not a
  shared misreading of the specification. P3-04 should add one published vector.
- **A zero-sized chunk in a non-terminal position is detected as bytes arriving after the terminal
  chunk**, which is the only position from which "the stream continues" is observable. Under a
  declared trailer section the check cannot run at all, because what follows *is* the trailer.
- **`ChunkLimits::max_overhead_permille` replaces the `f32` ratio the task described.** Integer
  parts per thousand, for the reason above; if the float is the contract, it moves.
- **A trailered upload is never `commit_allowed` at this stage.** That fails closed and is correct
  until P3-04 verifies the trailer, but it means the trailer modes are not yet end-to-end usable.
- **`SignedHeaderList` / `HeaderView::write_canonical_headers` still overlap `rustfs-gateway-sig`'s
  `SignedHeaderSet`.** Same defect shape as the host duplication — one rule in two places, s3s
  #499-versus-#632 — and not addressed by this merge. One of the two should be deleted rather than
  kept in sync.
