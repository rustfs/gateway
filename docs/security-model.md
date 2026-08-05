# Security model

What this project guarantees, what it deliberately does not, and where the boundary sits.
[SECURITY.md](../SECURITY.md) covers how to report a vulnerability; this file covers what counts
as one.

## The two declarations

**1. Signature verification cannot be skipped by accident.**

`Signature` has no `PartialEq`. The only way to compare one is `ct_verify`, and the only thing
`ct_verify` produces is a `SignatureMatch` — a zero-sized type with a private field that nothing
else in the workspace can construct. `Verdict::Authenticated` requires that value. So a code path
that looks up an access key, finds it valid, and returns "authenticated" without ever comparing a
signature does not compile.

This is aimed squarely at MinIO's CVE-2025-31489, where verification checked that an access key
existed and had write permission but never checked that the signature matched. That class of
defect is not a review problem here; it is a type error.

The anonymous path is symmetric. `Verdict::Anonymous` carries an `AnonymousAck`, obtainable only
from `CredentialPresence::into_evidence`, which fails with `CredentialsWerePresented` when the
request carried credentials. Presenting credentials therefore cannot be downgraded into an
anonymous pass.

**2. Secret-bearing values cannot be printed.**

`SecretBytes` and `SigningKey` have no `Debug`, no `Display`, and no `Clone`. Not a redacting
`Debug` — none at all, so the absence propagates to every struct that contains one and a
`{:?}` on the parent fails to compile too. Both zeroize on drop. `SafeToLog` is an explicit
opt-in marker; `assert_safe_to_log` is how a logging site proves it is passing something safe.

`scripts/check_ct_eq.sh` enforces both declarations in CI with seven rules, each with a negative
control in the guard self-test.

## Timing side channels

The register lives in `crates/s3gate-sig/src/timing.rs` as `SIDE_CHANNELS` — **data, not prose**,
so a test can assert every entry still has an owner. Ten channels, each closed here, deferred to a
named task with its interface already constrained, or accepted with the reason recorded.

Two properties of the design are worth stating outside the code:

- **The unknown-access-key path does the same work as the known one.** It signs with a placeholder
  secret and runs the full four-step derivation and comparison before answering
  `InvalidAccessKeyId`. Error codes stay distinct because S3 clients branch on them; latency parity
  plus rate limiting is the mitigation, not error-code normalisation.
- **The failure floor never sleeps.** `FailureFloor` returns the delay to wait for. A blocking
  sleep inside an async server turns a timing defence into a denial-of-service lever.

The timing test is guarded against being vacuous: a positive control that compares byte-by-byte
with early return measures 7.85x relative difference against a 0.20 tolerance, while the real
implementation measures 0.0008.

## Deployment constraint

**Never run a debug build of `s3gate-sig` in production.** `subtle`'s invariant checks are
`debug_assert!`s over secret-derived values, and they branch on secret-dependent conditions. A
debug build therefore has secret-dependent control flow that no amount of care in this crate can
remove. `subtle`'s barriers are `read_volatile`-based and documented as best-effort, so a release
build is a strong mitigation rather than a proof.

## Where the boundary sits

This framework verifies signatures, enforces presigned constraints, frames payloads, and rejects
malformed input. It does not decide who may do what: `Authorizer` is an interface it calls, and
the policy engine behind it is yours. A bug in your `Authorizer` is not a vulnerability in this
project — see the in-scope and out-of-scope lists in [SECURITY.md](../SECURITY.md).
