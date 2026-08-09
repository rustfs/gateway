# rustfs-gateway-sig crate map

Agent entry point for SigV2/SigV4 parsing, canonicalization and verification.

| File | Responsibility | Read it when |
|---|---|---|
| `src/lib.rs` | Public signature state machine. | Start here for an authentication task. |
| `src/auth.rs` | Authorization header/query parsing. | Credentials or signed fields parse wrongly. |
| `src/canonical.rs` | Canonical request construction. | A signature differs despite the same request. |
| `src/credential.rs` | Credential scope parsing. | Date/region/service scope is wrong. |
| `src/payload.rs` | Authenticated payload-mode selection. | HTTP framing receives the wrong mode. |
| `src/presign.rs` | Presigned request constraints. | Query authentication or expiry fails. |
| `src/signature.rs` | Secret-bearing signature types and constant-time comparison. | Verification or redaction changes. |
| `src/signer.rs` | Test/client request signing. | Conformance requests are signed wrongly. |
| `src/time.rs` | Signing-time parsing and skew. | Expiry or skew decisions are wrong. |
| `src/v2.rs` | SigV2 compatibility path. | A SigV2 request fails. |
| `tests/` | Public verification and negative matrices. | Change any signature contract. |
