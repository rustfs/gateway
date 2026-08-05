# s3gate-sig — crate map

SigV2/SigV4 signature dimensions, their strict parsers, and the verification-proof types.
P2-01 froze the dimensions; P2-02 added the verdict, the key-material containers and the
side-channel register. Canonical request construction and key derivation land in P2-03 on top of
these types, without reshaping them.

Three invariants live here. Everything else in the crate exists to serve them.

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
| `tests/frozen_dimensions.rs` | The `c-sig-0001`..`c-sig-0025` case suite plus two source-level guards | You changed any type here |
| `tests/verification_proof.rs` | The `c-sig-0101`..`c-sig-0128` case suite, a miniature authn stage, and the in-crate copies of the source guards | You changed the verdict, the secrets or the register |
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
  express "presigned with a session token", and drops the `service` dimension entirely — and
  every one of those gaps has produced a real verification defect. The familiar flat names remain
  available as constructors (`sigv4_header`, `sigv4_presigned`, `sigv2_header`,
  `sigv2_presigned`, `post_policy`, `anonymous`).
- **`SecretBytes` and `SigningKey` are `Box<[u8]>`, never `Vec<u8>` or `String`.** `zeroize`
  clears a `Vec`'s whole capacity but cannot reach the buffers a growing `Vec` already abandoned;
  a secret accumulated through 16 -> 32 -> 64 leaves two intact copies on the heap. A `Box<[u8]>`
  is allocated once and never reallocates.
- **No `Clone` on key material; `clone_secret()` instead** — long, ugly and greppable.
- **Key material has no `Debug` at all**, stricter than the redacting `Debug` the P2-02 sketch
  proposed: the absence propagates, so a struct holding one cannot `#[derive(Debug)]` either. The
  redacting-`Debug` pattern is still used one level up, on `SigIdentity` and `Verdict`.
- **`InvalidAccessKeyId` and `SignatureDoesNotMatch` keep distinct codes.** Clients branch on
  them; collapsing the codes would be a compatibility break. Everything else about the two is
  identical — one message, no detail fields, `FailureFloor` on the way out, and the full
  derivation run against `placeholder_secret()` for unknown keys.
- **SigV4a parses, then refuses.** `AWS4-ECDSA-P256-SHA256` and the streaming ECDSA payload values
  are recognised and rejected with `NotImplemented` (`501`). They must never fall through to the
  SigV4 path — that is an algorithm downgrade, not a fallback.

## Deliberate non-dependencies

- **No `aws-sigv4`** (ADR-0001, `docs/msrv.md`); **no `s3gate-http`** — the framing decision is
  made here and consumed there, and depending on the wire layer would put both ends of that
  decision in one crate graph. **No serializer**: with `serde` absent from the manifest, no
  `#[derive(Serialize)]` on key material can be re-introduced without a visible dependency change.

## Verifying a change

```bash
cargo test -p s3gate-sig                          # unit + case suites + compile_fail doctests
cargo test -p s3gate-sig --release --test timing  # latency parity; --release is required
bash scripts/check_ct_eq.sh                       # seven source guards, incl. negative-case floors
bash scripts/test_guard_scripts.sh                # proves check_ct_eq.sh can still fail
bash scripts/check_layer_dependencies.sh
```

The seventeen compile-time cases are `compile_fail` rustdoc examples on `CtBytes`, `Signature`,
`SecretBytes`, `SigningKey`, `SessionToken`, `SigFamily`, `PayloadMode` and the `verdict` module,
so `cargo test` runs them as doctests. They sit next to the rule they enforce on purpose: a
maintainer deleting a rule sees the test that forbids it in the same screen.

Note that rustdoc does **not** verify the `EXXXX` annotation on a `compile_fail` block — it only
checks that the snippet fails. The annotations here were each confirmed by hand against `rustc`;
treat them as documentation of intent, not as an assertion.
