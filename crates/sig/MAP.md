# rustfs-gateway-sig — crate map

The signature dimensions and their strict parsers, the verification-proof types, the canonical
request, and the security floor that runs outside every verifier. P2-01 froze the dimensions; P2-02
added the verdict, the key material and the side-channel register; P2-03 the canonical request, the
effective host and the derivation; P2-04 the floor, and the only public route to a `VerifiedScope`.
Seven invariants live here, and everything else exists to serve them.

1. **Framing comes from `x-amz-content-sha256` and nothing else** — `PayloadMode` is the only
   source of truth, and no function here accepts `Content-Encoding`.
2. **Signature material is never compared with `==` and never printed.** `Signature`, `CtBytes`,
   `SecretBytes`, `SigningKey`, `SessionToken` have no `PartialEq` and no `Debug`; `ct_verify` is
   the only comparison and the sole producer of `SignatureMatch`.
3. **Every widening outcome carries a receipt.** `Authenticated` needs that `SignatureMatch`;
   `Anonymous` needs an `AnonymousAck` only `CredentialPresence::into_evidence` hands out. "The key
   exists, therefore authenticated" (MinIO CVE-2025-31489) and "verification failed, fall back to
   anonymous" both fail to compile; rejecting needs no receipt.
4. **`effective_host()` decides the host once, in `rustfs-gateway-http`** — re-exported here, never
   reimplemented; `CanonicalRequestSpec::new` takes a `RawHost` and nothing else.
5. **Signed headers come from the client's list, never a deny-list**, and the list is refused unless
   it covers `host` and every `x-amz-*` header that arrived.
6. **The scope that seeds the derivation is not the scope the client sent.** `signing_key` takes a
   `VerifiedScope`, and `enforce_scope` is its only public constructor: day against the skew-checked
   timestamp, region against configuration, service against the route.
7. **The floor runs outside every verifier, replaceable or not.** `SecurityFloor::admit` enforces
   skew on all three paths, the seven-day presigned ceiling, the privileged-surface fence,
   presented-means-verified and the duplicate rules, then returns a `SealedAws` or a
   `CustomAuthRequest`, neither constructible elsewhere — and a `SignatureVerifier` never receives
   an AWS-marked request, so "swap the verifier" cannot mean "swap out SigV4".

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, public re-exports, the invariants in full | First stop; you can often stop here |
| `src/mode.rs` | `PayloadMode`, `TrailerSet`/`DeclaredTrailers`, the `x-amz-content-sha256` parse | Decoding a body, or building a canonical request |
| `src/scheme.rs` | `AuthScheme` and its axes: `SigFamily`, `SigLocation`, `SigIdentity`, `SigService` | Parsing `Authorization`/query auth |
| `src/signature.rs` | `CtBytes<N>`, `Signature`, `ct_verify`, `SignatureMatch`, `VerifyRejection` | Comparing signatures |
| `src/verdict.rs` | `Verdict`, `Identity`, `AuthError`, `AnonymousAck`, `CredentialPresence` | Deciding an outcome, or writing an audit record |
| `src/secret.rs` | `SecretBytes`, `SigningKey`, `SessionToken`, `SafeToLog` | Holding key material, or about to log |
| `src/timing.rs` | `SIDE_CHANNELS` (T1..T10), `FailureFloor`, `placeholder_secret`, `LookupBudget` | On a rejection path, or calling a credential provider |
| `src/codec.rs` | Length-exact lowercase-hex and canonical-base64 codecs | Decoding a digest or a signature |
| `src/error.rs` | `SigParseError`, `Unimplemented` | You need the rejection set, or the 400-vs-501 split |
| `src/query.rs` | `RawQuery`, canonical query rebuild, `QueryExclusion`, strict percent codec | Canonicalising a query |
| `src/signed_headers.rs` | `SignedHeaderSet` and its six completeness rules | Deciding which headers a signature covers |
| `src/canonical.rs` | `UriPathCandidates`, `CanonicalRequestSpec`, `CanonicalRequest`, `StringToSign` | Building or debugging a canonical request |
| `src/parse.rs` | `ScopeDate`, `AmzDate`, `CredentialScope`, `SigV4Authorization`, `PresignedParams` | Reading the signature and its scope off a request |
| `src/derive.rs` | `VerifiedScope`, `signing_key`, `calculate_signature` (ported from `aws-sigv4`) | Deriving a key |
| `src/clock.rs` | `RequestNow`/`RequestClock`, `SkewWindow`, `ClockChecked`, `enforce_expiry` (H1, H2) | Anything time-dependent |
| `src/floor.rs` | `WireView`, `SecurityFloor::admit`, `detect_credentials`, duplicates, `X-Amz-Expires` (H2, H4, H6) | Wiring the authn stage, or adding a rule |
| `src/operation.rs` | `OperationFloor`, `AllowedSchemes`, `SchemeSlot`, `SigV2Presigned`, `FloorConfigError` (H3) | Registering an operation, or widening what it takes |
| `src/scope.rs` | `RegionSet`, `ExpectedScope`, `enforce_scope` (H5) | The cross-check, or where `VerifiedScope` comes from |
| `src/verifier.rs` | `SignatureVerifier`, `CustomAuthScheme`, `SealedAws`, `DangerAck`, replay hook (H7) | Adding a scheme, or asking what "sealed" means |
| `src/full_chain_tests.rs` | `#[cfg(test)]`: the miniature loop, tamper cases, the AWS suite runner | You changed canonicalisation or derivation |
| `tests/frozen_dimensions.rs` | `c-sig-0001`..`0025`, plus two source guards | You changed any type here |
| `tests/verification_proof.rs` | `c-sig-0101`..`0128`, a miniature authn stage | You changed the verdict, the secrets or the register |
| `tests/canonical_request.rs` | `c-sig-0201`..`0246`, `0255`..`0257` | You changed canonicalisation or the query codec |
| `tests/effective_host.rs` | `c-sig-0206`..`0208`, `0247`..`0252` — this layer's demands on `rustfs-gateway-http` | You changed `effective_host` |
| `tests/security_floor.rs` | `c-sig-0301`..`0347`: the clock, expiry and scope halves | You changed `clock.rs` or `scope.rs` |
| `tests/security_floor_schemes.rs` | `c-sig-0350`..`0380`: presence, duplicates, allow-list, sealed boundary | You changed `floor.rs`, `operation.rs` or `verifier.rs` |
| `tests/timing.rs` | Latency parity `c-sig-0107`/`0108`/`0111`; run with `--release` | You touched a comparison or a rejection path |

## Shape decisions worth not re-litigating

- **`Base64Sha256` is not redundant** (s3s#631); **`TrailerSet` is not a `bool`**; **`Signature` is
  an enum** (SigV2 is 20 bytes, and a second type is the one that gets a derived `PartialEq`);
  **`CtBytes` is fixed-width** (a slice compare leaks the expected length); **`AuthScheme` is four
  axes**, since the flat form cannot express SigV4a, presigned-with-session-token or the service.
- **Key material is `Box<[u8]>`, never `Vec<u8>`/`String`**, with **no `Debug` at all**, so the
  absence propagates to every struct that holds one.
- **`InvalidAccessKeyId` and `SignatureDoesNotMatch` keep distinct codes** (clients branch on them)
  and are identical otherwise: one message, no detail, `FailureFloor` out, and the full derivation
  run against `placeholder_secret()` for unknown keys.
- **SigV4a parses then refuses, and so does SigV2 at the floor** — falling through is a downgrade.
- **Two URI-path candidates, named, in a fixed order** (s3s#589); **`+` is `0x2B`, never a space**;
  a duplicate query parameter or `Host` header is a rejection, not a choice.
- **Nothing holding a header value has a derived `Debug`**: `CanonicalRequest`, `WireView`,
  `SealedAws` and `CustomAuthRequest` render shapes only.
- **The skew window is capped, not merely defaulted**, and the presigned ceiling is a constant, so
  a deployment may narrow the floor but never widen it; a custom operation is privileged by default.

- **Presigned URLs replay within their window** — the scheme's semantics, not a defect;
  `ReplayNonceStore` is the opt-in hook, unimplemented here.
- **`rustfs-gateway-http` is the one internal edge** (sig → http, for the effective host; the
  reverse stays absent). **No `aws-sigv4`** (ADR-0001; two pure functions ported with attribution),
  **no `percent-encoding`** (its decoder passes `%zz` through), **no serializer**.

## Verifying a change

```bash
cargo test -p rustfs-gateway-sig                          # unit + case suites + compile_fail doctests
cargo test -p rustfs-gateway-sig --features dangerous-replace-signature-verifier -- floor_still_enforced
cargo test -p rustfs-gateway-sig --release --test timing  # latency parity; --release is required
bash scripts/check_ct_eq.sh && bash scripts/test_guard_scripts.sh   # guards, plus their own tests
```

smithy-rs' `aws-signing-test-suite` is **invoked, never vendored** (ADR-0001): without it the run
passes and prints how to fetch it (`SUITE_HOWTO` in `src/full_chain_tests.rs` pins the revision).
The twenty-five `compile_fail` doctests sit next to the rule each enforces; rustdoc only checks that
a snippet fails, so the `EXXXX` annotations document intent.
