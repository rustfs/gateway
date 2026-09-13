# ADR-0020: Carry the verified credential scope on the authentication verdict

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A2 (a scope the client wrote must not be spellable as a verified one) across the sig and gateway crate boundary
- Supersedes / Superseded by: none

## Context

`enforce_scope` is the only public producer of `VerifiedScope`: it cross-checks the credential
scope's day against the clock-checked timestamp, its region against the served `RegionSet` and
its service against the routed operation, and `signing_key` accepts nothing else. The built-in
`SigV4Authenticator` runs it on every SigV4 request and then discards the value:
`Verdict::Authenticated` carried an identity, a scheme and the zero-sized `SignatureMatch`, and
nothing else survived authentication.

rustfs/backlog#1762 (second slice, rustfs/gateway#748) needed the verified region and service to
build the s3s request context RustFS reads (`S3Request::region`, `S3Request::service`). With the
value gone, its harness re-parsed the `Authorization` header and re-ran `enforce_scope` itself.
That is the pattern `derive.rs` exists to prevent: a second derivation of a verified fact from
client text, which a production adapter would copy. rustfs/backlog#1752 lists this as the first
gateway gap blocking the RustFS ring-2 adapter.

## Decision

`Verdict::Authenticated` gains `scope: Option<VerifiedScope>`, declared before `proof`.
`Verdict::authenticated(identity, scheme, proof)` keeps its signature and sets `None`; the new
`Verdict::authenticated_in_scope(identity, scheme, scope, proof)` sets `Some`, and
`Verdict::verified_scope()` reads it. `VerifiedScope` stays without a public constructor, so the
only scope that can be attached is one `enforce_scope` produced. `SigV4Authenticator` attaches
exactly the value it derived the signing key from, for header, presigned and POST-policy SigV4.
SigV2 and custom schemes carry `None`; nothing infers a scope or substitutes a configured region.
The gateway's `RequestContext` exposes the same borrowed value to both `Authorizer` stages as
`RequestContext::verified_scope()`, and `rustfs_gateway::sig` re-exports `VerifiedScope`.
`RequestContext::new` has no scope parameter.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- Measured, red before the change: `cargo test -p rustfs-gateway-sig --lib verdict` failed with
  3 x `E0599 no method named verified_scope` and 2 x `E0599 no ... associated function ...
  authenticated_in_scope`; `cargo test -p rustfs-gateway --no-run` failed with 8 x `E0599`
  (7 on `Verdict::verified_scope`, 1 on `RequestContext::verified_scope`).
- Measured, green after: sig lib 141 passed, sig doctests for `verdict` 8 passed, including the
  two new `compile_fail` examples: `VerifiedScope::new` is `E0599`, and a `VerifiedScope` struct
  literal is `E0451`. The trybuild case `c-sig-0117` first failed with ``missing fields `proof`
  and `scope` ``; it now supplies `scope: None`, so its `E0063` again names `proof` alone and
  `check_sig_case_coverage.sh` keeps pinning that diagnostic.
- Measured: a request whose `Credential=` region was rewritten from `us-east-1` to the other
  served region `eu-west-1` is `SignatureDoesNotMatch` with `verified_scope() == None`
  (`a_rescoped_credential_is_rejected_and_reports_no_scope`). A client therefore cannot choose
  which region the verdict reports without holding a signature valid under that region.
- Measured: with regions `{us-east-1, eu-west-1}` (sorted first: `eu-west-1`), a request signed
  for `us-east-1` reaches both authorizer stages with `("20260102", "us-east-1", "s3")`.
- Measured: the goldens context diff (`operation_diff::context`, 25 tests) passes with the
  harness reading the verdict's scope instead of calling `enforce_scope`.

## Rejected alternatives

- **Re-derive the scope in the adapter.** That is the status quo this ADR removes: a second parse
  of client text on the far side of the authentication decision.
- **Put the region on `Identity`.** `Identity::new` is public and `Identity` is `Clone` and
  `PartialEq`, so any caller could attach any region. One principal also signs under many scopes.
- **A separate side channel, like `ChunkSink`.** `ChunkSink` exists because a signing key must not
  live on the verdict. A scope is not secret, and a sink read after the verdict adds an ordering
  obligation for a value the verdict can hold directly.
- **Make `scope` non-optional.** SigV2 and custom schemes have no credential scope, so a mandatory
  field would force a placeholder, which is the invented region this decision forbids.
- **A new `#[non_exhaustive]` variant.** It would split "authenticated" into two variants that
  every consumer must match, while the scope is an attribute of the same outcome.

## Consequences

This is a breaking change to `rustfs-gateway-sig`, 0.10.0 -> 0.11.0: code that constructs
`Verdict::Authenticated { .. }` literally, or destructures it without `..`, must add `scope`.
`Verdict::authenticated` is unchanged, so custom verifiers built on it still compile and keep
reporting `None`. `rustfs-gateway` goes 0.37.0 -> 0.38.0 because it re-exports `Verdict`. A
SigV4 authenticator that calls `Verdict::authenticated` instead of `authenticated_in_scope`
loses the scope silently. That regression is caught by the authenticator unit tests, the service
runtime test and the goldens context diff, each of which went red under that mutation. The
trybuild case `c-sig-0117` and the new `compile_fail` doctests keep the scope unforgeable.
