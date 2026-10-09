# ADR-0042: A route-bound bearer floor for zip downloads

- Status: Accepted
- Date: 2026-10-09
- Trigger: A4, an explicitly installed host verifier adds an authentication kind across the signature, facade and handler-context boundary.
- Supersedes / Superseded by: none

## Context

The zip creation operation accepts a header-signed request, but its returned download URL carries
`?token=` without a signature. The claimed GET operation currently has a privileged, header-only
floor, so that URL is refused before the host can validate its token
([issue #1400](https://github.com/rustfs/gateway/issues/1400)). The
[maintainer-delegated decision](https://github.com/rustfs/gateway/issues/1400#issuecomment-6070917305)
chooses a dedicated claim for this GET, host validation, and the existing authorization path.
ADR-0026 (g) already refuses anonymous admission for a download running with a stored principal's
authority.

The current routing rows cover the RustFS and MinIO admin prefixes. They capture the last segment
opaquely, including `.zip`; a wrong suffix can reach the GET operation and must still be refused.
The host's token validation authenticates encrypted data, checks its download ID, and rejects
`expires_at <= now`. Download preparation then authorizes the selected objects. These are separate
checks; a valid token does not grant permission to read every object.

The authentication carrier is closed by ADR-0009 and ADR-0022. The signed verdict needs a real
`SignatureMatch`, and the handler-dispatch boundary consumes `Authorized<O>`. A bearer request
needs its own evidence without changing either contract or presenting itself as a signed request.

## Decision

Install an explicit, default-denying host bearer verifier for a token claim on the zip-download GET
operation and its existing alias. Run it only after that operation's floor creates a sealed bearer
admission, and before ordinary authorization. Keep `Authenticator`, every existing field and
method of `AuthenticationOutcome`, the signed `SignatureMatch` requirement, scope-rejection
authority, and `Authorized<O>` consumption unchanged. Carry a distinct, non-forgeable bearer
receipt through an additive variant of the non-exhaustive `Verdict`, wrapped by the existing
`AuthenticationOutcome::ordinary` method. Do not change any guard, ruleset, unrelated route floor,
or the signed zip-creation path.

The receipt has private fields, no `Clone` or `Default`, and no public constructor that accepts
only a principal, a boolean, or a caller-supplied claim. The signature-side receipt producer must
invoke the explicitly installed trusted verifier on the sealed request binding; core and facade
cannot mint a receipt from identity or a boolean. Keep the existing dependency direction, with no
signature-to-core or signature-to-facade dependency. API names remain provisional until the
implementation, and must not introduce a forgeable bridge. The verifier is a declared
host trust boundary: the host performs the real AEAD verification, binds the decrypted ID to the
requested download, and checks expiry against the request's single clock reading. The kernel
binds the receipt to that admission, operation, download and verifier; another request cannot reuse
it. Missing verifier, verification failure, missing or invalid token, expiry and binding failure
deny token admission. An existing valid header-signed zip GET keeps its original signature path
even when no bearer verifier is installed. Never fabricate a `SignatureMatch` or fall back to
anonymous or legacy service.

Classify this admission as credential-verification work before expensive host validation. After
verification, the governor, both authorization stages, policy snapshot, audit and handler see the
same authenticated principal and a distinct bearer scheme. Carry only the host's opaque, immutable
verified state to the handler through a typed, read-only context path. Preserve the existing signed context
and scope paths; do not invent a signing family, signing location or `VerifiedScope` for a bearer.
Keep object authorization in place, and invoke the handler only after both authorization stages
allow the request. Use request-owned state, not a global token cache or a second token decode.

Remove the raw token from the authorization and handler contexts after verification. The receipt,
host state and their `Debug` implementations must not expose it. Refusals use closed, secret-free
errors; logs, audit fields and response bodies must not contain the token. Authentication and
authorization failure still use the existing refusal path, with no new scope-remediation authority.

The implementation must first measure legacy behaviour for mixed token/header/presigned
credentials, raw versus decoded ID and `.zip` suffix extraction, query canonicalization and
duplicate token parameters. Record the actual requests and results in #1400, with credentials
redacted. Preserve the measured wire behaviour where it meets this decision's fail-closed bounds.
Any remaining conflict or observable change needs a separate recorded decision before coding;
this ADR does not choose first-value parsing, normalization, credential precedence or a new
duplicate-token error. A malformed presented AWS credential must not be laundered through the
bearer path. Do not register an exception or mark R-062 fixed from this ADR alone.

## Evidence

- Measured: `rustc --version` returned `rustc 1.97.1 (8bab26f4f 2026-07-14)` on the review host.
- Measured: `git fetch origin main` followed by `git rev-parse origin/main` returned
  `772d3385421626aca5735e5581c5dff13a7aebff`. `git ls-tree --name-only origin/main docs/adr/ | wc -l`
  returned `43`; the highest numbered record is `0041`, so this record uses `0042`.
- Measured in the preceding read-only review at that revision: the
  [scope-rejection guard](https://github.com/rustfs/gateway/blob/772d3385421626aca5735e5581c5dff13a7aebff/scripts/check_scope_rejection_surface.sh#L190-L211)
  requires exactly three private carrier fields and
  [five visible methods](https://github.com/rustfs/gateway/blob/772d3385421626aca5735e5581c5dff13a7aebff/scripts/check_scope_rejection_surface.sh#L284-L298).
  Reproduce the source inspection with `git show 772d33854:scripts/check_scope_rejection_surface.sh`.
  These guards remain requirements, not editing targets.
- Measured in that review: `git show 772d33854:crates/sig/src/verdict.rs` shows a
  [non-exhaustive verdict](https://github.com/rustfs/gateway/blob/772d3385421626aca5735e5581c5dff13a7aebff/crates/sig/src/verdict.rs#L500-L536)
  whose signed constructor requires `SignatureMatch`. `git show 772d33854:crates/gateway/src/ext/authorizer.rs`
  shows an [exhaustive AuthSchemeRef](https://github.com/rustfs/gateway/blob/772d3385421626aca5735e5581c5dff13a7aebff/crates/gateway/src/ext/authorizer.rs#L57-L74).
- Measured in that review: the host at RustFS `5972a09cc3db94f1691d9e52059a5775602864ad` uses
  [AEAD token decoding](https://github.com/rustfs/rustfs/blob/5972a09cc3db94f1691d9e52059a5775602864ad/rustfs/src/admin/handlers/object_zip_download.rs#L319-L341),
  [ID and expiry checks](https://github.com/rustfs/rustfs/blob/5972a09cc3db94f1691d9e52059a5775602864ad/rustfs/src/admin/handlers/object_zip_download.rs#L367-L389),
  and [per-object authorization](https://github.com/rustfs/rustfs/blob/5972a09cc3db94f1691d9e52059a5775602864ad/rustfs/src/admin/handlers/object_zip_download.rs#L695-L723).
  Reproduce with `git show 5972a09cc:rustfs/src/admin/handlers/object_zip_download.rs` in that repository.
- [inferred] An additive bearer verdict can travel through `AuthenticationOutcome::ordinary`
  without changing its frozen surface. This is a design conclusion from source inspection, not a
  compiled implementation or a measured interoperability result. No bearer test or mutation has
  run in this documentation change.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| Allow this GET anonymously | Governor, authorization and audit would attribute a stored principal's download to an anonymous caller. |
| Validate only inside the handler | Authentication and both authorization stages would already have run under the wrong identity. |
| Reuse a SigV4 verdict or manufacture SignatureMatch | AEAD token validation did not verify a request signature; its evidence cannot satisfy the signed contract. |
| Add carrier fields, constructors or an identity-only bridge | This changes the frozen rejection surface and permits admission without the required proof. |
| Relax a guard or add an allowance | The new authentication kind must preserve existing boundaries; a failing guard is not permission to weaken it. |
| Cache a validated token globally or decode it again | Another request, principal, clock reading or key generation could consume state different from the one authorized. |
| Guess mixed-credential or canonicalization rules | Routing coverage does not establish legacy credential precedence or token parsing behaviour. |

## Consequences

Merge this record before the cross-crate implementation. It adds no runtime support. Keep #1400
open and R-062 `still diverging` until the implementation and archive-level differential evidence
land. The signature, facade and core retain their dependency directions; the host owns token
cryptography and RustFS data. No kernel crate may depend on RustFS to obtain those facts.

Adding the bearer spelling to exhaustive `AuthSchemeRef` is a downstream source break. The
implementation PR must bump the affected workspace versions under ADR-0004, state `BREAKING`, and
give the exact migration: callers add an explicit bearer arm, install the verifier only for the
declared claim, and read verified bearer state through the new context accessor. Existing
`Authenticator` implementations, `AuthenticationOutcome` users and signed handlers retain their
current contracts. Do not classify bearer as `OtherSigned` to avoid the migration.

Write failing acceptance cases before implementation; negative cases must outnumber positives.
The implementation receipt must include the exact command, output and deliberate red mutation
for each new assertion. At minimum, measure these controls:

| Control | Required observation | Deliberate break that must turn it red |
| --- | --- | --- |
| Real signed creation, then its token-only URL under each existing alias | The intended archive's entries and contents are returned; signed creation remains on its existing path. | Refuse every bearer; change POST admission; bind GET to another archive. |
| Principal and verified-state propagation | Governor, policy, both authorization stages, audit and handler agree on the authenticated principal; a denial in either stage prevents handler entry. | Mark it anonymous, substitute another principal/state, or skip either authorization stage. |
| Missing verifier, missing/empty/invalid token and altered ciphertext | Refusal, with no handler call or archive read. | Install an allow fallback or skip token authentication. |
| Wrong download, wrong suffix, method or neighbouring route | Refusal; no token claim applies to another operation. | Remove an ID/suffix check or widen the claim. |
| Exact expiry boundary and expired token | `expires_at <= now` refuses using the captured request clock. | Change the comparison or read a later independent clock. |
| Cross-admission receipt reuse, including concurrent requests | A receipt or host state from another admission cannot authorize this request. | Remove binding or share state across requests. |
| Non-forgeability and the old signed boundary | External construction, Default and Clone probes fail to compile; existing SignatureMatch probes remain red. | Expose a receipt constructor/field or add Default/Clone. |
| Secret sentinel | Captured contexts, Debug, logs, audit, errors and response bodies contain no raw token. | Retain the token in any one observed surface. |
| Mixed credentials, ID decoding, query canonicalization and duplicate tokens | Recorded legacy/gateway differential results meet the separately evidenced parsing decisions; invalid AWS credentials cannot recover via bearer. | Drop a presented credential, alter precedence/decoding, or choose a duplicate silently. |

Run the implementation's targeted admission, context, authorization and real archive tests, then
the complete gateway gate in order: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and
`cargo xtask verify --all` for the cross-crate wiring. Preserve all existing negative tests and
guards, including scope rejection and authorization consumption. Report actual results and any
unmeasured differential behaviour; a proposed control is not a passing result.
