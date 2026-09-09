# rustfs-gateway-sig crate map

Agent entry point for SigV2/SigV4 parsing, canonicalization and verification.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Public signature state machine and generated policy wiring. | Start here for an authentication task or a missing signature-policy consumer. |
| `src/canonical.rs` | Canonical request construction. | A signature differs despite the same request. |
| `src/clock.rs` | Single request-time snapshot and skew policy. | Header, query, and POST-policy paths disagree about time. |
| `src/codec.rs` | Authorization wire parsing and rendering helpers. | Header authentication syntax is decoded incorrectly. |
| `src/derive.rs` | Verified scope and signing-key derivation. | An unchecked credential scope reaches HMAC derivation. |
| `src/floor.rs` | H1-H6 unconditional admission checks, and the SigV2 admission branch. | A verifier or authentication scheme appears able to bypass the security floor. |
| `src/floor_tests.rs` | The floor's own unit suite, split out at the 800-line limit. | A floor rule decidable from a `WireView` alone changes. |
| `src/mode.rs` | Authenticated payload-mode selection. | HTTP framing receives the wrong mode. |
| `src/operation.rs` | Per-operation authentication-scheme policy. | Presigned or anonymous access reaches the wrong operation. |
| `src/parse.rs` | Credential and authorization parsing. | Date, region, service, or credential fields parse incorrectly. |
| `src/post_policy.rs` | Strict browser POST-policy parsing, field enforcement, and signature proof. | A POST form condition, filename, size range, or proof changes. |
| `src/post_policy_tests.rs` | Focused unit tests for POST-policy parsing and enforcement. | A POST-policy parser control or proof changes. |
| `src/post_policy_json.rs` | Bounded duplicate-free JSON parsing for POST policies. | JSON shape, string escaping, nesting, or element limits change. |
| `src/post_policy_redirect.rs` | The `success_action_redirect` builder: scheme, authority grammar, host allowlist, and parameter placement. | A redirect URL is accepted or refused wrongly, or the `Location` shape changes. |
| `src/query.rs` | Presigned-query constraints and duplicate detection. | Query authentication, expiry, or duplicate handling fails. |
| `src/scheme.rs` | Closed authentication-scheme dimensions. | Header, query, POST, or SigV2 dispatch changes. |
| `src/scope.rs` | H5 scope cross-checks. | Credential date, region, service, or terminator validation changes. |
| `src/secret.rs` | Secret byte ownership, redaction, and constant-time boundaries. | Credential material leaks or becomes comparable. |
| `src/sig_v2/mod.rs` | SigV2's `Authorization` grammar, 20-byte signature decode, `Expires` rules and the `SigV2Policy` switch. | A legacy SigV2 client fails to authenticate, or SigV2 presigned needs turning on. |
| `src/sig_v2/sealed.rs` | `SealedSigV2`: the post-floor SigV2 request, which has no route to `SealedAws`. | A SigV2 request appears able to reach the SigV4 verifier. |
| `src/sig_v2/signer.rs` | The client half: the `Authorization` value and the presigned `Signature` a SigV2 SDK sends. | A test or the conformance suite has to produce a real SigV2 signature. |
| `src/sig_v2/timestamp.rs` | SigV2's `Date`/`x-amz-date`, in both accepted spellings, normalised into one `AmzDate`. | A SigV2 client is refused as skewed when its clock is right. |
| `src/sig_v2/string_to_sign.rs` | SigV2's six-line string-to-sign and the 35 sub-resources it covers. | A SigV2 signature differs despite the same request, or a new S3 sub-resource must be signed. |
| `src/signature.rs` | Secret-bearing signature types and constant-time comparison. | Verification or redaction changes. |
| `src/signer.rs` | Test/client request signing. | Conformance requests are signed wrongly. |
| `src/signed_headers.rs` | Signed-header parsing and canonical selection. | Header coverage differs between signer and verifier. |
| `src/timing.rs` | Constant-time comparison helpers. | Signature comparison timing changes. |
| `src/verdict.rs` | Proof-carrying authentication outcomes and errors. | Authenticated or anonymous outcomes become forgeable. |
| `src/verifier.rs` | Sealed AWS markers, custom verifier boundary, replay hook, and danger acknowledgement. | A custom or replacement verifier crosses its permitted boundary. |
| `tests/integration.rs` | Single Cargo target registering all integration-test modules. | Integration tests duplicate compile or disappear. |
| `tests/sig_v2.rs` | P2-06 evidence: sub-resource census, string-to-sign shape, `Authorization` grammar, `Expires` bounds. | Change any SigV2 contract. |
| `tests/post_object_form.rs` | `c-lim-0002`: the POST form's policy is proved before its file is read, and the file is read under `content-length-range`. | The POST Object ordering or its ceiling composition changes. |
| `tests/sig_v2_admission.rs` | P2-06 wiring evidence at the floor: SigV2 is never sealed for SigV4 and never anonymous. | Change what `SecurityFloor::admit` does with a SigV2 request. |
| `tests/compile_fail.rs` | Trybuild harness for compile-time proof boundaries. | A private witness or verified type becomes constructible. |
| `tests/security_floor*.rs` | P2-04 H1-H7 runtime evidence. | Security-floor admission or scheme policy changes. |
| `tests/*.rs` | Remaining public verification and negative matrices. | Change any signature contract. |
