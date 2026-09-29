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
  `InvalidAccessKeyId`. A wrong signature follows the same derivation path and uses the same
  generic message, so neither the work performed nor the prose confirms that an access key exists.
- **AWS error codes remain distinct.** An unknown access key answers `InvalidAccessKeyId`, while a
  known key with a wrong signature answers `SignatureDoesNotMatch`. Timing parity and the mandatory
  credential rate limit mitigate that compatibility-required enumeration surface; changing the
  wire code would not be AWS-compatible.
- **The failure floor never sleeps.** `FailureFloor` returns the delay to wait for. A blocking
  sleep inside an async server turns a timing defence into a denial-of-service lever.

The timing test is guarded against being vacuous: a positive control that compares byte-by-byte
with early return measures 7.85x relative difference against a 0.20 tolerance, while the real
implementation measures 0.0008.

## Signed-chunk overhead limit

A signed `aws-chunked` upload pays roughly 85 bytes of framing per chunk. The
`ChunkLimits::max_overhead_permille` default remains **50**: at each ratio check, accumulated
framing bytes must not exceed 50 parts per thousand of the bytes already decoded. The check
starts only after framing exceeds `overhead_ratio_floor_bytes`, which defaults to **4,096**.
The roughly 1,740-byte estimate describes sustained small-chunk overhead, not a minimum enforced
on every chunk. Short uploads and small final chunks can fit the cumulative rule.

Local wire captures for [issue #6](https://github.com/rustfs/gateway/issues/6#issuecomment-5780820533) measured
`mc RELEASE.2025-08-13T08-35-41Z` with its embedded minio-go v7.0.90 against a loopback HTTP sink:

| Payload bytes | Signed data chunks | Framing bytes, including the zero terminator |
| --- | --- | --- |
| 4,194,427 | 64 of 65,536 bytes, then 123 bytes | 5,933 |
| 4,194,305 | 64 of 65,536 bytes, then 1 byte | 5,932 |
| 1 | 1 of 1 byte | 172 |

The first upload produced identical chunk sizes from one stdin write and 37,119 writes of at
most 113 bytes. The second also used fragmented stdin writes; client buffering can coalesce
those writes, so this does not measure reads at the signer's own input boundary. AWS CLI 2.27.49
sent a hashed payload without signed chunks to this plaintext endpoint and supplies no signed
chunk-size evidence. These captures measured framing, not signature validity or gateway acceptance.

Retain 50 permille: the observed signed streams fit the cumulative rule, including their small
tails, and provide no reason to relax it. This is evidence for the measured client and transport,
not a universal SDK compatibility claim; TLS, other clients and versions, and multipart setting
variants need their own measurements. Increase the limit through
`ChunkLimits::with_max_overhead_permille` only for a measured deployment requirement and record the evidence on issue #6, never pre-emptively.

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
For a path label, that one place decodes percent-encoding exactly once and applies the deployment's
`SlashPolicy`. For a body element or query value that its own reader has already decoded, it keeps
the literal key and does neither operation again. Every entry runs a safety floor no configuration
can lower and only then consult the deployment's `NameValidator`. The value produced is the value
the authorizer is shown, the value the codec puts into the operation input, and the value the
backend receives. Nothing downstream is handed the request path to parse again.
`scripts/check_single_normalization.sh` fails the build if a second normalisation, a second percent
decoder, or a `Deref`/`AsRef<str>`/`From<String>` on `ObjectKey` appears.

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
  report can name it. The default is `AwsPreserve`, which is the AWS semantics. A deployment in
  front of RustFS keeps the rule RustFS stored its keys under, `SlashPolicy::RustfsLegacy`: a key
  that starts with `/` is folded and every other key is kept as sent.

Two rules are deliberately **stricter than AWS**, and are registered as divergences in
`model/overlays/quirks/naming.toml`: a client may not name a key containing a `..` segment, and
may not name one containing a control character. Neither restricts what a backend may *hold* — an
object already stored under such a key is still listable, because the floor governs the naming
path and not the representation.

Keys arriving in a request **body** use the same floor and deployment validator. `DeleteObjects` is
the load-bearing case: its generated decoder receives `MetaView::names()`, threads it through every
nested XML reader and calls `ObjectKey::materialize_decoded`. The body text is already the literal
key, not an encoded path, so this entry neither percent-decodes it nor applies path-only
`SlashPolicy` rewriting. A custom validator therefore covers the request path, `x-amz-copy-source`,
and body-carried object keys under one authority without changing the body key's identity.

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

## Authorization: your responsibilities

The framework does not evaluate policy. It calls `Authorizer`, and everything behind that call is
yours. What the framework does own is the *shape* of the call, and that shape is where the known
failures of this area have been designed out.

The framework's half:

- **The verdict has three states, and two of them refuse.** `Decision::Allow` continues;
  `Decision::Deny` and `Decision::Indeterminate` both become `403 AccessDenied`. There is no
  `Result` for an authorizer to `?` a storage error through, so a policy store that cannot answer
  cannot become a `500` — and a `5xx` is the status a front end retries and, in some deployments,
  passes through. `Decision::settle` is the only place in the workspace that reads a verdict, it
  is exhaustive over all three states with no wildcard arm, and
  `scripts/check_authz_fail_closed.sh` keeps it the only one.
- **The refusal cannot choose its code.** `Denial` is a unit struct: no fields, no constructor
  taking an `ErrorCode`. A bucket you may not read and a bucket that does not exist are the same
  response, because a deployment that answered `404` for the first and `403` for the second would
  have built a private-bucket enumeration oracle out of the difference.
- **Policy is read once per request.** `PolicySource::snapshot` is called after the caller's
  identity is known and before the authorizer, and the resulting `PolicySnapshot` is handed to
  every reader through the server-derived authorization context. Client request extensions are a
  different type and are not exposed to an authorizer. Two readings inside one request are a
  window whose timing the caller chooses. `scripts/check_policy_snapshot_once.sh` asserts the
  single call site.
- **A failed reading is a refusal, not an error.** `PolicySource` returning `Err` produces
  `Indeterminate`, and the authorizer is not consulted at all — an implementation handed an empty
  snapshot cannot tell "the store is down" from "this deployment installed no source". The one
  read has a hard timeout: 250 ms by default, configurable to a non-zero value no greater than five
  seconds. A timeout follows the same `Indeterminate` path.
- **The audit event is the framework's, and the sink cannot answer back.** `AuthzAuditSink` takes
  shared references and returns `()`, and it is called after the outcome has been settled. The
  event carries the principal, authentication scheme, operation, action, every resource judged,
  **where the target's name came from** (`Host` or path), the snapshot identifier, stage, elapsed
  time, and which of the three states was reached — including the distinction the wire collapses.
  A sink panic is caught, reported as an error, and cannot change the response.
- **There is no default `Authorizer`.** `ServiceBuilder::build` returns
  `AssemblyError::MissingAuthorizer`. `DenyAllAuthorizer` is shipped and must be chosen; there is
  no allow-all type in a normal build, and no example contains an unconditional allow. The
  `dangerous-allow-all-authorizer` feature exposes one only behind a deliberately verbose
  `DangerAck`; a service assembled with it prints a named start-up warning.
- **Anonymous admission is per operation unless a deployment delegates it.** By default the
  security floor admits a request that presented nothing only to an operation that opted in. Any
  other operation refuses it before the authorizer is consulted.
  `SecurityFloor::delegate_anonymous_to_authorizer_after_listing_in_the_posture_report`
  (ADR-0021) admits it to every non-privileged operation instead. Every such request then reaches
  the authorizer with no identity, and the authorizer alone decides.
  Delegation never admits a request that presented a credential, never widens presigned or
  POST-policy access, and never reaches a privileged operation that did not opt in itself. The
  startup posture line lists every operation it makes reachable.

Four things are **yours**:

1. **The policy language and its semantics.** Wildcard expansion, condition keys, `Deny`
   precedence, resource ARNs, the whole of it. `PolicySnapshot` is opaque to the framework.
2. **Answering `Indeterminate` when you mean it.** The framework cannot tell a considered `Deny`
   from a swallowed error; only your code knows which one it reached. Every `Ok(false)` that is
   really "the record did not load" is a rustfs `GHSA-j548-9grx-fh4f` waiting to happen.
3. **Not panicking.** A panic in an authorizer is isolated and answered as `500`, never as allow.
   That keeps the authorization boundary fail closed, but retries can still amplify a panicking
   policy implementation.
4. **The timing of your own evaluation.** The framework does not equalise it. A policy engine
   whose evaluation time depends on how many statements matched leaks something about the policy
   to a caller who can measure it; see "Timing side channels" above for what the framework does
   equalise and what it does not.

### Accepted risks

- **Policy-evaluation timing is not equalised above the failure floor.** Every denied or
  indeterminate authorization pays the same minimum-latency floor, but the framework does not hide
  differences beyond that floor. An engine whose evaluation time varies with statement count can
  therefore still leak coarse policy shape.

## Credentials: your responsibilities

### SigV2 signs almost none of the query string

SigV2's `CanonicalizedResource` covers the path and a **fixed list of 35 sub-resources** —
`acl`, `uploadId`, `versionId`, `cors`, `tagging`, `lifecycle` and the rest, as re-derived from
botocore's `HmacV1Auth.QSAOfInterest`, which is what AWS's own SDKs sign with. Every other query
parameter is outside the signature. Appending `&foo=1` to a SigV2 URL therefore leaves the
signature valid, and a proxy or a client that reads `foo` reads an unsigned value.

This is a property of the SigV2 specification, not a gap in this implementation, and it cannot be
closed without breaking every conforming client: signing the parameters AWS does not sign would
reject correctly-signed requests. SigV4, by contrast, signs the whole canonical query.

Two consequences that are this framework's half:

- **SigV2 presigned URLs are refused by default.** `SigV2Policy::HeaderOnly` is the default:
  header authentication works, presigned does not. The header form at least binds the request to
  a live `Date` and an `Authorization` header rather than to a URL that travels in referrer
  headers, proxy logs and browser history. This is also the answer to MinIO #5411, where a
  rewritten SigV2 presigned URL reached an admin operation. Enabling
  `SigV2Policy::HeaderAndPresigned` is an explicit deployment decision, and the startup posture
  report names the value in force.
- **The list is a contract, not a convenience.** Dropping an entry makes correctly-signed requests
  to that sub-resource fail (s3s#517 lost 14 at once); adding one AWS does not sign fails the same
  way in the other direction. `c-sig-0530` and `c-sig-0531` pin the order and the membership.

Yours: if you route on a query parameter that is not one of the 35, do not treat a SigV2-signed
request as having authorised its value. Prefer SigV4 for anything privileged, and keep SigV2
disabled entirely (`SigV2Policy::Disabled`) if no legacy client needs it.

A second, related SigV2 property: a covered sub-resource's value is percent-decoded before it is
written into `CanonicalizedResource`, and that block separates its own entries with `&`. So
`?acl=x%26versionId%3Dy` and `?acl=x&versionId=y` produce the same string-to-sign, and one
signature is valid for both — while the router sees one parameter in the first and two in the
second. This too is the algorithm rather than this implementation: botocore computes the identical
string, so refusing it here would reject requests AWS's own SDK signs successfully. It is pinned
by `c-sig-0556` and is a third reason to prefer SigV4.

P2-06's wiring slice — the change that made SigV2 actually verify — considered diverging from
botocore here and **did not**. Diverging would mean computing a `CanonicalizedResource` no client
computes, so every correctly-signed request carrying a percent-encoded `&` or `=` inside a covered
sub-resource value would be answered `SignatureDoesNotMatch`. That is a compatibility break sold
as a security fix, and it does not even close the hole: the value is still unsigned for every
parameter outside the 35. The mitigation that does work is the one above — do not authorise on an
unsigned query parameter — plus keeping SigV2 presigned off, which is the default. If a later
change does diverge, `c-sig-0556` fails loudly rather than letting every SigV2 signature shift
quietly.

### What a SigV2 request does not sign, beyond the query string

- **The body.** SigV2 has no `x-amz-content-sha256` and no payload digest. `Content-MD5` is the
  only body binding it offers and it is optional, so a SigV2 request's body is authenticated only
  as far as the client chose to bind it. SigV4 signs a payload declaration on every request.
- **Framing.** SigV2 has no streaming form; `aws-chunked` chunk signatures are SigV4 values. A
  SigV2 request that declares one is refused `501` rather than read as if the declaration were
  absent, because the pipeline decodes framing only for a payload mode it was given and the SigV2
  path gives it none — an ignored declaration would deliver chunk headers to the operation as
  object bytes.

### Where a SigV2 request goes, and where it cannot

`SecurityFloor::admit` answers a SigV2 request with its own `Admission::SealedSigV2`, never with
the `Admission::Sealed` the built-in SigV4 verifier consumes, and there is no conversion between
the two request types. So "a SigV2 request verified as SigV4" — the algorithm downgrade — is not a
mistake an assembly can make. `Authenticator`'s SigV2 entry point defaults to a refusal, so a
deployment's own authenticator answers `501` rather than anything weaker. The POST-form SigV2
shape is refused outright: its field-level enforcement is P2-05's, and a signature checked without
those rules is worse than no signature at all.

A SigV2 credential that cannot be parsed, cannot be verified, or is presented under a policy that
does not admit it is **always a rejection** — never an anonymous request. That holds on operations
that accept anonymous access, where the two outcomes differ only in the status code;
`c-sig-0570`..`c-sig-0572` assert it against exactly such an operation.

### Presigned replay semantics

Presigned URLs are replayable within their validity window. That is an intentional property of
the AWS-compatible scheme, not evidence that the gateway failed to authenticate a request.
`ReplayNonceStore` is an opt-in single-use hook for deployments that accept the availability and
coordination cost of a strongly consistent write on the authentication path. The framework does
not install a replay store by default, and never exposes replay state through an HTTP endpoint.

A presigned URL's validity window is its signed lifetime, not the clock-skew window. The skew
window (fifteen minutes, narrowable, never widenable) holds both bounds for a header-signed or
POST-policy request, which carries no signed lifetime. For a SigV4 presigned URL it holds only
the future bound: a URL dated more than the window ahead is `RequestTimeTooSkewed`, so no URL
starts working at a time of the signer's choosing. Its past bound is `X-Amz-Date` plus
`X-Amz-Expires` (`AccessDenied`, "expired"), and `X-Amz-Expires` stays capped at seven days.
Narrowing the skew window does not shorten a presigned lifetime. This matches S3, a black-box
probe of MinIO, and the s3s revision RustFS runs (rustfs/gateway#723); `c-sig-0309`, `c-sig-0310`,
`c-sig-0336`..`c-sig-0339` and `c-sig-0590`..`c-sig-0593` hold each boundary.

`CredentialProvider` is the only extension point on the **unauthenticated** path: anybody who can
reach the port can make the gateway call it, and what it returns is a long-term secret. The
framework's half:

- **It cannot make verification not happen.** The trait returns
  `Result<CredentialLookup, ProviderError>`, never a `Verdict`.
  An empty secret is not a bypass — the derivation runs against it and the comparison fails. A
  lookup that succeeds is not authentication; only `Signature::ct_verify` produces the
  `SignatureMatch` that `Verdict::Authenticated` requires.
- **A store that cannot answer fails closed.** A backend error, timeout or isolated panic is
  counted, is never cached, and receives the same 403 response as another credential failure. It
  is never treated as an anonymous request.
- **An unknown key costs what a known one costs.** The unknown-key path derives from
  `timing::placeholder_secret`, runs the full four-step chain and completes the comparison before
  answering, so the two are not separable by latency (`timing::SIDE_CHANNELS`, row T1).
- **A credential that exists but cannot be used answers as one that does not exist.** Disabled,
  expired, presented without the session token it is bound to, or presented with a token when it is
  long-term: all four are `InvalidAccessKeyId`, byte for byte the answer an unknown access key
  gets. The session verdict is computed when the credential arrives and consumed *after* the
  signature comparison, so none of the four can answer early either.
- **A session token and a lifetime are one value.** `Credentials::with_session` takes both;
  "temporary credentials with no expiry" — the shape of GHSA-ccrv-v8v9-ch9q — is not
  representable. The lifetime is judged against the request's single clock snapshot.
- **The token is covered and bound.** `x-amz-security-token` is an `x-amz-*` header,
  so the signed-header rules require it to be in `SignedHeaders`; the query spelling is part of the
  canonical query. The framework also compares its exact wire value against the token issued with
  that access key in constant time, so a correctly signed token from another issuance is refused.
- **The unauthenticated lookup is guarded by default.** The default is a one-second hard timeout,
  a 30-second negative TTL plus deterministic 0–30-second jitter, and at most 4096 negative
  entries. Provider errors are not cached. Positive caching is absent, so deletion and rotation
  are visible on the next lookup and secret material is not retained by the framework.
- **The governor sees the work before it happens.** Any signature or session-token surface is
  classified as `ClassKind::CredentialLookup` before the provider runs, including malformed
  and forged credentials. The mandatory framework governor therefore applies its per-IP and
  credential-class budgets to the whole lookup path without parsing credentials itself; a
  deployment governor may add tighter limits but cannot remove those budgets.
- **A weakened lookup posture is visible.** `S3Service::security_posture` names whether the
  negative cache is enabled and whether the mandatory per-IP bucket is bounded or closed. A
  start-up report can print that value without downcasting the authenticator or governor.
- **Nothing that is a credential can be printed.** `SecretBytes`, `SessionToken` and `SigningKey`
  have no `Debug`, no `Display`, no `PartialEq`, no `Clone` and no serializer, and that absence
  propagates into anything holding one. `scripts/check_secret_hygiene.sh` and
  `scripts/check_ct_eq.sh` keep it that way.

Four things are **yours**:

1. **The store behind the provider.** The framework bounds calls, but the IAM or database
   implementation, its connection pool and its circuit breaker remain yours. The framework's
   per-IP quota is mandatory; a deployment `Governor` may add a store-specific quota after it.
2. **Never a blanket answer for an unrecognised key.** Return `CredentialLookup::NotFound`. A
   provider that hands the same secret to every access key it does not recognise has replaced
   authentication with a constant, and no framework rule can see that from outside.
3. **Everything the session token means.** Who issued it, whether the issuer's signature is
   genuine, what role and policy it names: the framework holds `SessionBinding`'s `issuer` and
   `inline_policy` as opaque handles and parses neither. It enforces the expiry and the binding to
   the access key, and nothing else about the token.
4. **The identity store itself** — users, key rotation and revocation. The framework has no
   positive cache; if your provider adds one, you own that window and the additional secret
   residency.

## Where the boundary sits

This framework verifies signatures, enforces presigned constraints, frames payloads, and rejects
malformed input. It does not decide who may do what: `Authorizer` is an interface it calls, and
the policy engine behind it is yours. A bug in your `Authorizer` is not a vulnerability in this
project — see the in-scope and out-of-scope lists in [SECURITY.md](../SECURITY.md).
