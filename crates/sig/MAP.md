# rustfs-gateway-sig — crate map

SigV2/SigV4 signature dimensions, their strict parsers, the verification-proof types, and the
canonical request. P2-01 froze the dimensions; P2-02 added the verdict, the key-material containers
and the side-channel register; P2-03 added the canonical request, the effective-host truth source
and the key derivation, on top of those types and without reshaping any of them.

Six invariants live here. Everything else in the crate exists to serve them.

1. **Framing is derived from `x-amz-content-sha256`, and from nothing else.** `PayloadMode` is
   the only source of truth, `PayloadMode::is_framed()` the only sanctioned input to "run the
   chunk parser", and no function in this crate accepts `Content-Encoding`. Corollary:
   `x-amz-decoded-content-length` is required under the two streaming modes and forbidden under
   the other four (`PayloadMode::requires_decoded_length()`).
2. **Signature material is never compared with `==` and never printed.** `Signature`, `CtBytes`,
   `SecretBytes`, `SigningKey` and `SessionToken` have no `PartialEq` and no `Debug`.
   `Signature::ct_verify` is the only comparison and the only producer of `SignatureMatch`.
3. **Every widening outcome carries a receipt.** `Verdict::Authenticated` requires that
   `SignatureMatch`; `Verdict::Anonymous` requires an `AnonymousAck` that only
   `CredentialPresence::into_evidence` produces, and only when nothing was presented. So "the
   access key exists, therefore authenticated" (MinIO CVE-2025-31489) and "verification failed,
   fall back to anonymous" both fail to compile. Rejecting needs no receipt.
4. **`effective_host()` decides the host once, from raw bytes.** hyper forwards a missing, empty or
   duplicated `Host`, and an h2 `:authority` contradicting `host`, all with a `200`; each is a `400`
   here. The canonical request accepts a `RawHost` and nothing else, so a resolver's normalised
   value cannot seed a signature — otherwise one signature is valid for four spellings of one host.
5. **Headers come from the client's `SignedHeaders`, never from a deny-list**, and the list is
   refused unless it covers `host` and every `x-amz-*` header that arrived. An unsigned `x-amz-*` is
   an unsigned instruction: SSE-C key, copy source, ACL, object lock, session token.
6. **The scope that seeds the derivation is not the scope the client sent.** `signing_key` takes a
   `VerifiedScope`, which has no constructor outside `cfg(test)` until P2-04 lands the cross-check.
   Deriving from `CredentialScope` would let a signature minted for another region or service replay.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, public re-exports, both invariants stated in full | First stop; you can often stop here |
| `src/mode.rs` | `PayloadMode` (six states), `TrailerSet`/`DeclaredTrailers`/`TrailerName`, the `x-amz-content-sha256` parse, `CanonicalPayloadToken` | You are decoding a body, deciding whether to frame it, or building a canonical request |
| `src/scheme.rs` | `AuthScheme` and its four axes: `SigFamily`, `SigLocation`, `SigIdentity`, `SigService` | You are parsing `Authorization`/query auth, or cross-checking credential scope against a route |
| `src/signature.rs` | `CtBytes<N>`, `Signature`, `Signature::ct_verify`, `SignatureMatch`, `VerifyRejection` | You are comparing signatures, or designing an authenticated verdict |
| `src/verdict.rs` | `Verdict`, `Identity`, `AuthError`, `AnonymousAck`, `CredentialPresence` | You are deciding an authentication outcome, or writing an audit record |
| `src/secret.rs` | `SecretBytes`, `SigningKey`, `SessionToken` — zeroized, unprintable, uncomparable, uncloneable; plus `SafeToLog`/`assert_safe_to_log` | You are holding key material, or about to put a value in a log |
| `src/timing.rs` | `SIDE_CHANNELS` (the T1..T10 register), `FailureFloor`, `placeholder_secret`, `LookupBudget`, `CredentialLookup` | You are on a rejection path, or about to call a credential provider |
| `src/codec.rs` | Length-exact lowercase-hex and canonical-base64 codecs | You are decoding a digest or a signature off the wire |
| `src/error.rs` | `SigParseError`, `Unimplemented` | You need the rejection reason set, or the 400-vs-501 split |
| `src/host.rs` | `effective_host`, `RawHost`, `HostSource`, `HostError` | You need the request's host — for the signature, for routing, or for an audit record |
| `src/query.rs` | `RawQuery`, the canonical query rebuild, `QueryExclusion`, and the strict percent codec | You are canonicalising a query, or encoding a URI component |
| `src/signed_headers.rs` | `SignedHeaderSet` and its six completeness rules, `UNSIGNED_HEADER_EXEMPTIONS` | You are deciding which headers a signature covers |
| `src/canonical.rs` | `UriPathCandidates`, `CanonicalRequestSpec`/`CanonicalCandidates`, `CanonicalRequest`, `StringToSign`, `SignatureMismatchDetail` | You are building or debugging a canonical request |
| `src/parse.rs` | `ScopeDate`, `AmzDate`, `CredentialScope`, `SigV4Authorization`, `PresignedParams` | You are reading the signature and its scope off a request |
| `src/derive.rs` | `VerifiedScope`, `signing_key`, `calculate_signature` (ported from `aws-sigv4`, Apache-2.0) | You are deriving a key, or wondering why the scope is a separate type |
| `src/full_chain_tests.rs` | `#[cfg(test)]` only: the miniature P2-04 loop, the tamper cases, and the runner for smithy-rs' `aws-signing-test-suite` | You changed the canonical request, the derivation, or the candidate order |
| `tests/frozen_dimensions.rs` | The `c-sig-0001`..`c-sig-0025` case suite plus two source-level guards | You changed any type here |
| `tests/verification_proof.rs` | The `c-sig-0101`..`c-sig-0128` case suite, a miniature authn stage, and the in-crate copies of the source guards | You changed the verdict, the secrets or the register |
| `tests/canonical_request.rs` | The `c-sig-0201`..`c-sig-0246`, `0255`..`0257` plaintext-level suite | You changed canonicalisation, the query codec or the signed-header rules |
| `tests/effective_host.rs` | The `c-sig-0206`..`0208`, `0247`..`0252` host suite | You changed `effective_host` or `RawHost` |
| `tests/timing.rs` | Latency-parity cases `c-sig-0107`/`0108`/`0111`. Run it with `--release` | You touched a comparison or a rejection path |

## Shape decisions worth not re-litigating

- **`PayloadMode::Base64Sha256` is not redundant.** Generic REST SigV4 signers put the payload
  checksum into `x-amz-content-sha256` as base64 (s3s#631). It carries the same 32 bytes as
  `ExactSha256` but a different canonical token, and the canonical request must reproduce what
  the client signed.
- **`TrailerSet` is not a `bool`.** It has to carry the declared names and whether a trailer
  signature follows, or the declared-versus-received cross-check cannot be written.
  `DeclaredTrailers` keeps its fields private so the empty declaration, the duplicate, and the
  third trailer are rejected at construction rather than checked later.
- **`Signature` is an enum, not `[u8; 32]`.** SigV2 signs HMAC-SHA1 and produces 20 bytes. A
  32-byte-only type would force a second signature type into existence, and that second type is
  the one that ends up with a derived `PartialEq`.
- **`CtBytes` is fixed-width.** `subtle`'s slice comparison short-circuits on a length mismatch,
  which would leak the expected length; comparing `CtBytes<N>` to `CtBytes<N>` cannot.
- **`AuthScheme` is four axes, not a flat enum.** The flat form cannot express SigV4a, cannot
  express "presigned with a session token", and drops the `service` dimension entirely — every one
  of those gaps has produced a real verification defect. The familiar flat names remain as
  constructors (`sigv4_header`, `sigv4_presigned`, `sigv2_header`, `sigv2_presigned`,
  `post_policy`, `anonymous`).
- **`SecretBytes` and `SigningKey` are `Box<[u8]>`, never `Vec<u8>` or `String`.** `zeroize` clears
  a `Vec`'s whole capacity but cannot reach the buffers a growing `Vec` already abandoned; a secret
  accumulated through 16 -> 32 -> 64 leaves two intact copies on the heap. No `Clone` on key
  material either — `clone_secret()` instead, long, ugly and greppable.
- **Key material has no `Debug` at all**, stricter than a redacting `Debug`: the absence propagates,
  so a struct holding one cannot `#[derive(Debug)]` either. The redacting-`Debug` pattern is still
  used one level up, on `SigIdentity` and `Verdict`.
- **`InvalidAccessKeyId` and `SignatureDoesNotMatch` keep distinct codes.** Clients branch on
  them; collapsing the codes would be a compatibility break. Everything else about the two is
  identical — one message, no detail fields, `FailureFloor` on the way out, and the full
  derivation run against `placeholder_secret()` for unknown keys.
- **SigV4a parses, then refuses.** `AWS4-ECDSA-P256-SHA256` and the streaming ECDSA payload values
  are recognised and rejected with `NotImplemented` (`501`). They must never fall through to the
  SigV4 path — that is an algorithm downgrade, not a fallback.
- **Two URI-path candidates, named, in a fixed order** (`CanonicalCandidates`): decoded-then-
  re-encoded first, the wire spelling second, and only when they differ. Proxies re-spell
  percent-escapes in transit (s3s#589); one candidate breaks those deployments, an open-ended set
  is a bypass.
- **`+` in a query is the byte `0x2B`, never a space** — `form_urlencoded` semantics make
  `?prefix=a+b` and `?prefix=a%20b` sign identically (measured on `aws-sigv4` 1.5.1). A duplicate
  query parameter and a duplicate `Host` header are likewise rejections rather than a choice.
- **`CanonicalRequest` and `CanonicalCandidates` have no `Debug`**: they hold every signed header
  value, one of which may be an SSE-C key. `SignatureMismatchDetail` is the only rendering route
  and stays silent unless `verbose-signature-errors` is on; no expected signature is in either.

## Deliberate non-dependencies

- **No `aws-sigv4`** (ADR-0001, `docs/msrv.md`): its two useful pure functions are ported into
  `src/derive.rs` with attribution, and the rest has three measured defects (the `+` collision, a
  deny-list for signed headers, a `panic!` when a request has no host) plus an MSRV of 1.94.1
  against this workspace's 1.89. **No `percent-encoding`**: its decoder passes `%zz` through, and a
  signature input may not have two spellings. **No `rustfs-gateway-http`**: the framing decision is made
  here and consumed there. **No serializer**: with `serde` absent, no `#[derive(Serialize)]` on key
  material can reappear without a visible dependency change — which is why `full_chain_tests.rs`
  reads the AWS suite's context files with a six-line scanner.

## Verifying a change

```bash
cargo test -p rustfs-gateway-sig                          # unit + case suites + compile_fail doctests
cargo test -p rustfs-gateway-sig --release --test timing  # latency parity; --release is required
bash scripts/check_ct_eq.sh                       # seven source guards, incl. negative-case floors
bash scripts/test_guard_scripts.sh                # proves check_ct_eq.sh can still fail
bash scripts/check_layer_dependencies.sh
```

smithy-rs' `aws-signing-test-suite` is **invoked, never vendored** (ADR-0001). Without it the run
passes and prints how to fetch it; with it, twenty-four upstream cases are asserted at all three
plaintext layers. The fetch commands are the `SUITE_HOWTO` constant in `src/full_chain_tests.rs`,
which also records the pinned revision; export `S3GATE_AWS_SIGV4_SUITE_DIR` and re-run.

The nineteen compile-time cases are `compile_fail` rustdoc examples on `CtBytes`, `Signature`,
`SecretBytes`, `SigningKey`, `SessionToken`, `SigFamily`, `PayloadMode`, `RawHost`, `derive` and
the `verdict` module, so `cargo test` runs them as doctests — next to the rule they enforce, so a
maintainer deleting a rule sees the test that forbids it in the same screen. Their `EXXXX`
annotations were each confirmed by hand: rustdoc checks only that the snippet fails, so treat the
code as documentation of intent rather than as an assertion.
