# ADR-0055: SigV4a ECDSA P-256 verification and streaming

- Status: Accepted
- Date: 2026-11-27
- Trigger: licensing/dependency policy and crate boundary; pure-Rust ECDSA P-256 verification and streaming SigV4a across rustfs-gateway-sig, rustfs-gateway-http, and rustfs-gateway.
- Supersedes / Superseded by: none

## Context

`rustfs-gateway-sig` froze `SigFamily::V4a` (`AWS4-ECDSA-P256-SHA256`) and the streaming tokens `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD` and `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER` as recognised-but-unimplemented (`501 NotImplemented`) so that multi-region AWS SDK clients could never silently downgrade to SigV4 HMAC verification. Production Multi-Region Access Point and AWS SDK v2/CRT clients send SigV4a header, presigned query, and `aws-chunked` streaming uploads (with and without trailers).

Supporting SigV4a changes two governed boundaries:

1. **Dependency policy.** SigV4a verifies ASN.1 DER ECDSA signatures over NIST P-256 (`secp256r1`) with SHA-256 against a deterministic public key derived from `(AccessKeyId, SecretAccessKey)`. The workspace forbids `unsafe` code (`#![forbid(unsafe_code)]`), bans `aws-sigv4` permanently (ADR-0001), enforces `deny.toml` license/advisory gates, and targets MSRV `1.97.1`.
2. **Crate boundary.** Streaming SigV4a chunk and trailer signatures are verified inside `rustfs-gateway-http::ingest::ChunkSigner` while keypair derivation and request-head verification stay in `rustfs-gateway-sig`, coordinated through `rustfs-gateway`'s `ChunkVerification` sink without leaking private scalar material across crate boundaries or raising `check_secret_hygiene.sh`'s `.expose()` ceiling.

## Decision

1. **Pure-Rust `p256` dependency.** Add `p256 = "0.14"` (`default-features = false, features = ["ecdsa", "precomputed-tables", "std"]`) to `[workspace.dependencies]` and depend on it from `rustfs-gateway-sig` and `rustfs-gateway-http`. `aws-sigv4` remains banned under ADR-0001.
2. **Deterministic P-256 keypair derivation inside `rustfs-gateway-sig`.** Derive the P-256 scalar from `AccessKeyId` and `SecretBytes` via NIST SP 800-108 counter-mode KDF over HMAC-SHA256 (key `"AWS4A" || secret`, counter `1..=254`, label `"AWS4-ECDSA-P256-SHA256"`, context `AccessKeyId`, `L = 256`) with FIPS 186-4 B.4.2 modular reduction (`c <= n - 2`, `d = c + 1`). All secret key buffers and derived scalar bytes live in `Zeroizing` containers, never reallocate, and are wiped before returning only the public `SigV4aVerifyingKey` (33-byte SEC1 compressed point).
3. **Strict ASN.1 DER verification with high-S acceptance and sealed proofs.** Parse SigV4a signatures into `EcdsaDerSignature` (no `Debug`, `Display`, `PartialEq`, `Eq`, `Serialize`, or `Deserialize`), accepting only lowercase hex encoding strict ASN.1 DER (`8..=72` bytes) and rejecting raw 64-byte `(r||s)` encodings, trailing bytes, or uppercase hex. Because compliant AWS signers emit non-normalized `s > n/2` signatures, normalize high-S before calling `p256::ecdsa::VerifyingKey::verify`. Verification requires a `VerifiedSigV4aScope` (minted only by `enforce_sigv4a_scope` after checking clock day, service, and `x-amz-region-set`) and mints `SignatureMatch` exclusively inside `crates/sig/src/signature.rs`.
4. **Type-separated SigV4a parsing and `x-amz-region-set` rules.** Introduce `SigV4aCredentialScope` (4 fields: `<akid>/<date>/<service>/aws4_request`), `PresentedRegionSet`, `SigV4aAuthorization`, and `SigV4aPresignedParams`. `SigV4Authorization::parse` and `PresignedParams::parse` remain SigV4-only and continue refusing `AWS4-ECDSA-P256-SHA256`, making cross-family downgrade unrepresentable. Enforce singleton `x-amz-region-set` / `X-Amz-Region-Set` at H6 in `SecurityFloor`, require `x-amz-region-set` in `SignedHeaders` for header auth, and require `region_set` to contain `"*"` or a region admitted by `ExpectedScope`.
5. **Streaming SigV4a across `crates/sig`, `crates/http`, and `crates/gateway`.** Add `PayloadMode::StreamingEcdsa { trailer }` to `#[non_exhaustive] PayloadMode`, cross-checked in `SigV4Authenticator` so SigV4 requests cannot pair with `StreamingEcdsa` and SigV4a requests cannot pair with `StreamingSigned`. Publish only the 33-byte public verifying key through `ChunkVerification::new_ecdsa` into `rustfs-gateway-http::ChunkSigner::new_ecdsa`, which verifies `AWS4-ECDSA-P256-SHA256-PAYLOAD` chunks and `AWS4-ECDSA-P256-SHA256-TRAILER` trailers using a 512-byte stack buffer. Streaming chunk and trailer wire signatures accept both unpadded lowercase hex DER and AWS CRT 144-character right-`'*'`-padded lowercase hex DER, stripping trailing `'*'` before chaining `previous` into the next string-to-sign. Presigned streaming and SigV2 streaming remain refused (`501 NotImplemented`), and `AuthSchemeRef::of_scheme` keeps mapping `SigFamily::V4a` to `AuthSchemeRef::OtherSigned` for SemVer compatibility.

## Evidence

- *measured* (`rustc --version`): workspace toolchain is `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- *measured* (`cargo deny check` with `p256 = "0.14"` enabled in `crates/sig` and `crates/http`): `advisories ok, bans ok, licenses ok, sources ok`; resolved crates are `p256 v0.14.0`, `ecdsa v0.17.0`, `crypto-bigint v0.7.11`, `der v0.8.3`, and `signature v3.0.0` (all `Apache-2.0 OR MIT`), sharing existing `sha2 v0.11.0`, `digest v0.11.3`, and `zeroize v1.9.0`.
- *measured* (`cargo check -p rustfs-gateway-sig -p rustfs-gateway-http`): compiles cleanly under `#![forbid(unsafe_code)]` and all crate lint denials.
- *measured* (census of the pinned `smithy-rs` commit `cb39d6e52459b47fa8881a241ac9f78849f1bc25` `aws-signing-test-suite/v4a/` directory): 38 test cases containing 114 ECDSA DER signatures (lengths 70–72 bytes / 140–144 hex chars), of which 53/114 have `s > n/2` (high-S).
- `[inferred]` Passing only the 33-byte compressed SEC1 public verifying key across `ChunkVerification` keeps `crates/gateway/src/` at `EXPOSE_CEILING = 3` in `scripts/check_secret_hygiene.sh` and ensures no derived private scalar persists into body ingestion.

## Rejected alternatives

- **Depend on `aws-sigv4`:** permanently rejected by ADR-0001; it also hides canonical intermediates (`pub(crate)`) and carries client-oriented assumptions incompatible with this gateway's strict verification contract.
- **Use `ring` or `aws-lc-rs` for P-256 verification:** rejected because C/assembly FFI conflicts with the workspace `#![forbid(unsafe_code)]` posture and adds native toolchain/build complexity where pure-Rust `p256` meets the requirement directly.
- **Require low-S-only ECDSA signatures:** rejected because 53/114 official AWS SigV4a test-suite vectors are high-S; rejecting high-S would break compliant AWS SDK and CRT signers.
- **Add an optional region to `CredentialScope` / `SigV4Authorization`:** rejected because SigV4 (5-field scope, 32-byte HMAC) and SigV4a (4-field scope, `x-amz-region-set`, variable-length DER ECDSA) have distinct invariants; separate types keep cross-family downgrade unrepresentable.
- **Pass the derived P-256 private scalar through `ChunkVerification` to `rustfs-gateway-http`:** rejected because chunk verification needs only the public verifying key; carrying private key material across crate boundaries widens the secret surface for zero benefit.

## Consequences

- Multi-region AWS SigV4a clients (header, presigned query, and streaming `aws-chunked` with or without signed trailers) authenticate end to end while preserving the security floor (H1–H6), timing parity for unknown access keys, and type-enforced `SignatureMatch` proofs.
- Per-chunk SigV4a verification performs one P-256 ECDSA verify per chunk (inherently more CPU work than HMAC-SHA256), and `ChunkSigner`'s stack string-to-sign buffer grows from 320 to 512 bytes while remaining zero-allocation on the hot path.
- `SigV4Authorization::parse` and `PresignedParams::parse` remain strictly SigV4-only; callers wishing to parse SigV4a use `SigV4aAuthorization` and `SigV4aPresignedParams`, while `SigV4Authenticator` dispatches both families automatically based on `SealedAws::marker().family()`.
- `AuthSchemeRef` remains exhaustive without a breaking SemVer variant (`SigFamily::V4a` continues reporting `AuthSchemeRef::OtherSigned`).
