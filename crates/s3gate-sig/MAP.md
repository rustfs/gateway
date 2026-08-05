# s3gate-sig — crate map

SigV2/SigV4 signature dimensions and their strict parsers. Today the crate contains the **frozen
types** only (task P2-01); canonical request construction, key derivation and the verification
flow land in P2-02/P2-03 on top of these types, without reshaping them.

Two invariants live here. Everything else in the crate exists to serve them.

1. **Framing is derived from `x-amz-content-sha256`, and from nothing else.** `PayloadMode` is
   the only source of truth, `PayloadMode::is_framed()` the only sanctioned input to "run the
   chunk parser", and no function in this crate accepts `Content-Encoding`. Corollary:
   `x-amz-decoded-content-length` is required under the two streaming modes and forbidden under
   the other four (`PayloadMode::requires_decoded_length()`).
2. **Signature material is never compared with `==` and never printed.** `Signature`, `CtBytes`,
   `SecretBytes` and `SessionToken` have no `PartialEq` and no `Debug`. `Signature::ct_verify` is
   the only comparison and the only producer of `SignatureMatch`, the proof token a downstream
   `Verdict::Authenticated { identity, proof }` is expected to carry.

## Files

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Module wiring, public re-exports, both invariants stated in full | First stop; you can often stop here |
| `src/mode.rs` | `PayloadMode` (six states), `TrailerSet`/`DeclaredTrailers`/`TrailerName`, the `x-amz-content-sha256` parse, `CanonicalPayloadToken` | You are decoding a body, deciding whether to frame it, or building a canonical request |
| `src/scheme.rs` | `AuthScheme` and its four axes: `SigFamily`, `SigLocation`, `SigIdentity`, `SigService` | You are parsing `Authorization`/query auth, or cross-checking credential scope against a route |
| `src/signature.rs` | `CtBytes<N>`, `Signature`, `Signature::ct_verify`, `SignatureMatch`, `VerifyRejection` | You are comparing signatures, or designing an authenticated verdict |
| `src/secret.rs` | `SecretBytes`, `SessionToken` — zeroized, unprintable, uncomparable | You are holding key material or an STS token |
| `src/codec.rs` | Length-exact lowercase-hex and canonical-base64 codecs | You are decoding a digest or a signature off the wire |
| `src/error.rs` | `SigParseError`, `Unimplemented` | You need the rejection reason set, or the 400-vs-501 split |
| `tests/frozen_dimensions.rs` | The `c-sig-0001`..`c-sig-0025` case suite plus two source-level guards | You changed any type here |

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
- **SigV4a parses, then refuses.** `AWS4-ECDSA-P256-SHA256` and the streaming ECDSA payload values
  are recognised and rejected with `NotImplemented` (`501`). They must never fall through to the
  SigV4 path — that is an algorithm downgrade, not a fallback.

## Deliberate non-dependencies

- **No `aws-sigv4`** (ADR-0001, `docs/msrv.md`).
- **No `s3gate-http`.** The framing decision is made here and consumed there; depending on the
  wire layer would put both ends of that decision in one crate graph.

## Verifying a change

```bash
cargo test -p s3gate-sig          # unit + case suite + compile_fail doctests
bash scripts/check_ct_eq.sh       # no derived PartialEq/Eq/Debug on secret-bearing types
bash scripts/check_layer_dependencies.sh
```

The seven compile-time cases (`c-sig-0014`..`c-sig-0020`) are `compile_fail` rustdoc examples on
`CtBytes`, `Signature`, `SessionToken`, `SigFamily` and `PayloadMode`, so `cargo test` runs them
as doctests. They sit next to the rule they enforce on purpose: a maintainer deleting a rule sees
the test that forbids it in the same screen.
