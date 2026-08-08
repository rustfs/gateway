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

The register lives in `crates/sig/src/timing.rs` as `SIDE_CHANNELS` — **data, not prose**,
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

**Never run a debug build of `rustfs-gateway-sig` in production.** `subtle`'s invariant checks are
`debug_assert!`s over secret-derived values, and they branch on secret-dependent conditions. A
debug build therefore has secret-dependent control flow that no amount of care in this crate can
remove. `subtle`'s barriers are `read_volatile`-based and documented as best-effort, so a release
build is a strong mitigation rather than a proof.

## Naming and normalization: your responsibilities

Three published RustFS advisories have one shape. `GHSA-8r6f-hmq2-28rg`: an object key carrying a
traversal reached the filesystem mapping. `GHSA-f4vq-9ffr-m8m3`: a copy source was authorised as a
key and then used as a path, so the write landed in a bucket nobody had checked.
`GHSA-pq29-69jg-9mxc`: an untrusted path was joined onto a root and guarded by a length check,
which is not a containment check. In each of them the value the authorisation check read was not
the value the storage layer used, and the difference between the two was the vulnerability.

**What the framework guarantees.** A bucket label and an object key are turned into a
`BucketName` and an `ObjectKey` in exactly one place — `crates/types/src/scalar/naming.rs`, reached
through `ObjectKey::materialize`, `ObjectKey::materialize_decoded` and `BucketName::materialize`.
That one place decodes percent-encoding exactly once, applies the deployment's `SlashPolicy`, runs
a safety floor no configuration can lower, and only then consults the deployment's
`NameValidator`. The value it produces is the value the authorizer is shown, the value the codec
puts into the operation input, and the value the backend receives. Nothing downstream is handed
the request path to parse again. `scripts/check_single_normalization.sh` fails the build if a
second normalisation, a second percent decoder, or a `Deref`/`AsRef<str>`/`From<String>` on
`ObjectKey` appears.

The floor refuses, whatever the validator says: an empty key, a key over 1024 UTF-8 bytes, a NUL,
a control character, a `..` segment delimited by `/` or `\`, a drive-letter or UNC root, a value
that is not UTF-8 after one decode, and a value that still spells an encoded separator after that
one decode. For a bucket label: anything outside 3..=63 bytes, a separator, a NUL, a non-graphic
byte, or a `%`. `NameValidator` returns `Stricter`, which has no `Allow` variant — the framework
ANDs its answer with the floor's, so a deployment can narrow the rules and has no way to widen
past the floor.

**What is still yours.** The framework's promise stops at handing you a validated `ObjectKey`. It
does not map that key onto a physical location, and it cannot: only you know what the root is. You
must ensure the mapped path lands inside the intended root — resolve it and compare, do not join
and measure. `GHSA-pq29` is what a length check instead of a containment check looks like. Two
further rules follow from the same argument:

- **Never re-parse, re-decode, or re-clean a name the framework gave you.** A backend that runs
  its own tidy-up is the second normalisation, and it is on the storage side of the authorisation
  decision. The conformance fixture in this repository had exactly that defect — its own
  percent decoder and its own copy-source parser — and it is now routed through the shared one.
- **`SlashPolicy` is persistence-affecting.** `SlashPolicy::Collapse` makes `a//b` and `a/b` the
  same object; switching it on a deployment that already holds data renames every object whose key
  contained an empty segment. `SlashPolicy::rewrites_keys()` answers this so a start-up posture
  report can name it. The default is `AwsPreserve`, which is the AWS semantics.

Two rules are deliberately **stricter than AWS**, and are registered as divergences in
`model/overlays/quirks/naming.toml`: a client may not name a key containing a `..` segment, and
may not name one containing a control character. Neither restricts what a backend may *hold* — an
object already stored under such a key is still listable, because the floor governs the naming
path and not the representation.

One gap, stated rather than hidden: keys arriving in a request **body** — `DeleteObjects` names its
keys there — get the floor but not the deployment's `NameValidator`, because a generated decoder
has no policy to hand. The floor is uniform; a custom validator today covers the request path and
`x-amz-copy-source`.

## Server-side encryption: your responsibilities

SSE-C is the one place in S3 where the client hands the server a raw encryption key over the wire,
in a request header. The framework's half of that is small, absolute, and not optional:

- **A customer-provided key on a cleartext connection is refused**, `400 InvalidRequest`, before
  the request body is read and for every operation. The framework does not ask a backend's
  opinion, and there is no way to reach a handler with a key that came over cleartext.
- **The key never appears on a response.** `x-amz-server-side-encryption-customer-key` and its
  `copy-source` twin are removed from every response the service writes, answered or refused. The
  algorithm and the key digest survive, because AWS returns both.
- **The key never appears in a refusal.** Every SSE refusal message is a compile-time constant. No
  key, no digest, no expected-versus-actual, and no KMS key id.
- **The key and its digest are agreed in constant time**, both decoded strictly to their exact
  widths first, and the refusal does not say which half was wrong.
- **The key does not outlive the function that hashes it.** There is no type in this workspace's
  enforcement path that stores one; the bytes live in a zeroized stack array for as long as it
  takes to compute the digest.

Two things are **yours**:

1. **The connection's security.** The framework believes exactly one source: a
   `TransportSecurity` value that your transport puts into the request's extensions.
   `X-Forwarded-Proto` is never consulted — it is a request header, so believing it would let the
   caller switch the gate off. If you terminate TLS in front of the gateway, teach the transport
   to declare it. `SseConfig::allowing_customer_keys_over_plaintext` exists for the deployment
   that cannot, and its witness has to be typed out in full for a reason.
2. **Your own handler and storage layer.** Once a decoded input reaches your backend it carries
   the key, and this framework can guarantee nothing about what you do with it. Do not log it, do
   not put it in a trace attribute, do not persist it — a multipart upload binds `MD5(key)`, never
   the key, and `check_part` is written against the digest so that you never have to store one.

The multipart rule is the one the framework can only half-enforce: every `UploadPart` must repeat
the same customer-key headers its `CreateMultipartUpload` carried. The comparison lives in
`rustfs_gateway_core::sse::check_part`, which returns a `Result` you cannot silently discard, but
the binding itself is yours to store, because this framework holds no upload state.

## Where the boundary sits

This framework verifies signatures, enforces presigned constraints, frames payloads, and rejects
malformed input. It does not decide who may do what: `Authorizer` is an interface it calls, and
the policy engine behind it is yours. A bug in your `Authorizer` is not a vulnerability in this
project — see the in-scope and out-of-scope lists in [SECURITY.md](../SECURITY.md).
