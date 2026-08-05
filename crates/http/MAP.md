# rustfs-gateway-http — crate map

The wire acceptance layer: the first stage of the pipeline, and the last place a raw
`http::Request` exists. P3-01 landed acceptance, the effective-host determination, framing rules
W-1 to W-6, and the borrowed header and query views; P3-02/03/05/06 build on these types without
reshaping them.

Three properties live here. Everything else in the crate exists to serve them.

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
   spelling that normalises to it.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, re-exports, the three properties in full | First stop; you can often stop here |
| `src/wire.rs` | `WireRequest`, `accept`, `RawPath`, and the fixed order of checks | You are adding a rule, or wondering which rule fires first |
| `src/host.rs` | `effective_host`, `EffectiveHost`, `RawHost`, `HostSource`, `HostError` | You touch anything host-, vhost- or signature-related |
| `src/framing.rs` | `Framing`, `BodyLength`, rules W-1..W-5, `validate_chunk_size_line` (W-6) | You are deciding where a body ends |
| `src/header_view.rs` | `HeaderView`, `SignedHeaderList`, canonical-header writing, the repeat and non-UTF-8 policies | You read a header, or build a canonical request |
| `src/query_view.rs` | `QueryIndex` / `QueryView`: offsets, arrival order, repeat policy | You read a query parameter, or route on one |
| `src/metadata.rs` | `x-amz-meta-*` key and value rules, including validation *after* RFC 2047 decoding | You touch user metadata |
| `src/limits.rs` | `Limits`, `LimitKind` | You are adding a ceiling; P3-05 owns the numbers and the timeouts |
| `src/reject.rs` | `WireReject`, status and error-code mapping, `may_read_body`, `must_close_connection` | You are adding a rejection, or writing the response |
| `src/text.rs` | `AsciiBuf` and the byte predicates; no protocol meaning | Rarely |
| `tests/host_ambiguity.rs` | 6 positive / 14 negative — every row of the host decision table | You changed `host.rs` |
| `tests/framing_smuggling.rs` | 4 positive / 19 negative — W-1..W-6 and the body ceiling | You changed `framing.rs` |
| `tests/header_and_query.rs` | 10 positive / 18 negative — tolerance, repeats, metadata, canonicalisation | You changed a view or `metadata.rs` |
| `tests/allocation_budget.rs` | The no-allocation promise, asserted structurally | You changed a view's storage |
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

## Deliberate non-dependencies

Three dependencies: `http`, `smallvec`, and `rustfs-gateway-types` for `ErrorCode`. No `hyper`, no
`aws-chunked` decoder, no percent-decoding, no clock. `rustfs-gateway-stream` is present for the
`OwnedWireRequest` alias only.

## Verify

```bash
cargo test -p rustfs-gateway-http                                  # 82 tests, 51 negative / 31 positive
cargo clippy -p rustfs-gateway-http --all-targets -- -D warnings
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
- **Overlap with `rustfs-gateway-sig` (P2-03), landing in parallel.** The boundary intended here: this
  crate owns the *wire* verdict — accept or refuse a host, and hand over `RawHost` (raw bytes plus
  source) for signing; `rustfs-gateway-sig` owns the canonical request built from those bytes.
  `SignedHeaderList` and `HeaderView::write_canonical_headers` exist so the signer never needs the
  `HeaderMap`. If P2-03's own signed-header and canonical-host types cover the same ground, one of
  the two should be deleted rather than kept in sync — one rule in two places is the s3s
  #499-versus-#632 defect shape.
