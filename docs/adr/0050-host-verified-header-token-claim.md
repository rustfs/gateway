# ADR-0050: A host-verified header token claim

- Status: Accepted
- Date: 2026-11-11
- Trigger: A4, an explicitly installed host verifier adds a service-level authentication kind across the signature, facade and handler-context boundary.
- Supersedes / Superseded by: none

## Context

Some hosts authenticate a non-AWS credential in a layer that runs before the gateway. RustFS does
this for OpenStack Keystone: a tower layer validates the `X-Auth-Token` header and establishes the
caller's identity for the request, and the S3 front end then serves the request as that identity
without a SigV4 signature ([issue #1586](https://github.com/rustfs/gateway/issues/1586)).

The gateway cannot express that today. A request carrying only such a header presents no AWS
credential surface, so `SecurityFloor::admit` admits it as anonymous and no `Authenticator` is
consulted. An `Authenticator` could not vouch for it either: every authenticated `Verdict`
constructor requires a `SignatureMatch`, which only a constant-time signature comparison produces.
That wall is deliberate and stays. A gateway-fronted host would therefore authorize the request as
anonymous while code behind the gateway sees the token's user.

ADR-0042 solved the same shape for one route: a query bearer claim that the floor admits only as
far as the host's verifier, whose sealed receipt becomes a verdict naming the principal. This
record decides the header-borne, service-level sibling. The issue fixes its constraints: an opt-in
at build time, exclusive admission, a sealed admission and receipt, a synchronous host verifier, a
distinct authentication scheme, secret handling for the token, and unsigned payload rules.

## Decision

Add one opt-in, `ServiceBuilder::host_verified_header_token(claim, verifier)`, taking one
`HeaderTokenClaim` (a lowercase header name) and one `HeaderTokenVerifier`. One call installs
both, so a verifier never exists without its claim. The builder writes the claim onto the
`SecurityFloor` it assembles; nothing else turns the feature on. A floor that carries a claim
without a verifier refuses every request presenting the header.

**Opt-in absent.** `SecurityFloor::admit` reads no header for this purpose, no context is changed,
and no posture line is added. A request carrying the header is treated exactly as it is today.

**The claim.** `HeaderTokenClaim::new` accepts an extension header outside the AWS namespace: `x-`
followed by lowercase ASCII letters, digits and `-`, and not `x-amz-`. The facade removes the
claimed header before the request is accepted, so the grammar admits no header that HTTP or the
signature path gives a meaning to: not `authorization`, not a framing or routing header, and,
having no `:`, no HTTP/2 pseudo-header.

**Admission is exclusive, and runs first.** When the claim is installed and the request's head
carries the claimed header, `SecurityFloor::admit` decides the request in that branch alone, before
any other rule. The answer is a sealed `Admission::HeaderToken` or `403 AccessDenied`. It is never
a sealed AWS request, a custom-scheme request, a bearer admission or an anonymous one, so no other
verifier is handed a request that carries the token. The branch refuses, before any verifier runs,
a request that also presents any other credential surface. The surfaces are the ones the floor's
own detection names, read by the default predicate whatever recognition policy is configured:

- headers: `authorization` with any value, `x-amz-security-token`, and any header under a
  registered custom scheme prefix;
- query parameters, by decoded name: `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Signature`,
  `X-Amz-Security-Token`, `AWSAccessKeyId` and `Signature`;
- a browser form of any content, which covers `x-amz-algorithm`, `x-amz-credential`,
  `x-amz-signature`, `x-amz-security-token`, `AWSAccessKeyId`, `signature` and `policy`.

A query bearer token needs no entry: an operation that declares a query bearer claim refuses the
scheme, with or without its parameter. An object-path form that routes to no operation under the
RustFS selector is not read when the token is present; the request keeps the head-only refusal of
any unrouted request. There is no precedence and no fallback from one credential to the other.

**The header's shape.** The branch then requires exactly one occurrence of the claimed header, with
a value of 1 to 8192 bytes, every byte ASCII graphic and none a comma. A repeated, empty, overlong,
non-ASCII, whitespace-bearing or list-shaped value is `403`. No occurrence is chosen over another.

**Which operations admit it.** `SecurityFloor::admits_header_token` is the one predicate; the floor
and the posture report both read it. It admits every operation that is not privileged, is not of
the STS service, declares no query bearer claim, and does not require SigV4 under every policy
(ADR-0049). It refuses privileged operations (admin, configuration, and every third-party operation
that kept its default), credential issuance (every operation of the STS service, privileged or
not), the bearer-claimed route, and a SigV4-only route. There is no per-operation opt-in for any of
them; adding one needs its own decision.

**The verifier.** `HeaderTokenVerifier::verify(&HeaderTokenRequest) -> Result<Identity,
HeaderTokenRefused>` is synchronous and is the host's trust boundary. The request exposes the
admission's one clock reading and typed, read-only access to the values the host installed in the
request before acceptance. It does not expose the token: the host's outer layer has already
validated it, and the verifier only reports the identity that layer established for this request.
There is one spelling of "no": a refusal. An absent identity is a refusal. The facade runs the
verifier inside its panic boundary; a refusal, a panic and a missing verifier are each
`403 AccessDenied`, and none becomes anonymous.

**The receipt and the verdict.** `HeaderTokenAdmission` and `HeaderTokenReceipt` have private
fields, no `Clone`, no `Default` and no public constructor. Only `SecurityFloor::admit` produces
the admission, only `HeaderTokenAdmission::verify` produces the receipt, and only that method wraps
it into `Verdict::HeaderToken`, a non-exhaustive variant with a crate-private constructor. The
verdict carries no `SignatureMatch`, no signing scheme and no credential scope. The facade accepts
a header-token verdict only from the request's own header-token admission.

**How the rest of the pipeline sees it.** The governor classes the request as credential work. The
policy snapshot, both authorization stages, the audit event, the observer and the handler see the
receipt's principal. Authorizers and audit see the new `AuthSchemeRef::HeaderToken`, never a signed
spelling, `Bearer` or `Anonymous`. A handler reads the principal through
`RequestContextView::header_token_principal`; `principal()` stays the signed principal and is
`None`.

**Payload and transport.** The request is unsigned. Its framing is decided by the same call that
decides an anonymous request's framing, and its body has no payload digest obligation. No transport
rule is added or lifted.

**The token is secret material.** The admission does not copy it, the verifier is not given it, and
no `Debug` or `Display` implementation, log event, error body or metric label of the gateway holds
it. When the claim is installed, the facade removes the claimed header from the request head after
the wire seam and before acceptance. The accepted request therefore never holds it, and neither do
the authorization contexts, the handler context, the codec's header view or the committed-response
context. The floor reads the caller's own copy of the head, taken before the wire seam, so a stage
filter can neither supply nor erase a token.

## Evidence

- Measured: `rustc --version` returned `rustc 1.97.1 (8bab26f4f 2026-07-14)` on the authoring host.
- Measured: `git rev-parse origin/main` returned `f9aa6045ec077cc41b4d5f3bdeab01d729826407`.
  `git ls-tree --name-only origin/main docs/adr/` lists `0049` as the highest numbered record, so
  this record uses `0050`.
- Measured at that revision: the facade's anonymous arm builds its verdict from the floor's
  evidence alone and calls no authenticator
  ([service.rs](https://github.com/rustfs/gateway/blob/f9aa6045ec077cc41b4d5f3bdeab01d729826407/crates/gateway/src/service.rs#L788-L794)),
  and the head copy the floor reads is taken before the wire seam
  ([service.rs](https://github.com/rustfs/gateway/blob/f9aa6045ec077cc41b4d5f3bdeab01d729826407/crates/gateway/src/service.rs#L483)).
  Reproduce with `git show f9aa6045e:crates/gateway/src/service.rs`.
- Measured at that revision: the credential surfaces listed in the decision are the ones named by
  [`detect_aws_credential_marker`](https://github.com/rustfs/gateway/blob/f9aa6045ec077cc41b4d5f3bdeab01d729826407/crates/sig/src/verifier.rs#L121-L170)
  and
  [`detect_credentials`](https://github.com/rustfs/gateway/blob/f9aa6045ec077cc41b4d5f3bdeab01d729826407/crates/sig/src/floor.rs#L265-L283),
  plus the custom scheme registry and the query bearer claim that
  [`admit_without_aws_marker`](https://github.com/rustfs/gateway/blob/f9aa6045ec077cc41b4d5f3bdeab01d729826407/crates/sig/src/floor_bearer.rs#L25-L72)
  consults.
- Measured at that revision: acceptance bounds a head at 128 fields and 16 KiB
  ([limits.rs](https://github.com/rustfs/gateway/blob/f9aa6045ec077cc41b4d5f3bdeab01d729826407/crates/http/src/limits.rs#L213-L214)).
  The claimed header is removed before that count, which is why the floor bounds it itself.
- Measured: the RustFS outer layer at `7f5fa4b8f62ed195a7887adccb47b37d505188bd` validates the token
  header and scopes the resulting credentials around the inner service call
  ([middleware.rs](https://github.com/rustfs/rustfs/blob/7f5fa4b8f62ed195a7887adccb47b37d505188bd/crates/keystone/src/middleware.rs#L159)).
  The verifier is called synchronously inside that call, so such a host can report the identity
  without the token. Reproduce with
  `git show 7f5fa4b8f:crates/keystone/src/middleware.rs` in that repository.
- [inferred] `http::HeaderMap` stores names lowercased and keeps repeated field lines as separate
  values, and the HTTP/1.1 parsers in use strip optional whitespace around a value. This is read
  from those crates' documentation and from the existing duplicate-header rule, not measured by a
  new wire test in this record.
- Measured on the implementation in this pull request: `cargo test -p rustfs-gateway-sig --doc
  header_token` ran ten compile-fail probes, each failing at the code it names: `E0451` for a
  struct literal of the admission and of the receipt, `E0624` for the admission's constructor and
  for `Verdict::header_token`, `E0599` for `clone` and `default` on both and for a `token`
  accessor on the verifier's request, and `E0639` for building `Verdict::HeaderToken` directly.
- The mutation of each new assertion, with the command that ran it, is recorded in the pull
  request that lands this record.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| Leave the request anonymous and let the host read its own identity | The governor, both authorization stages and audit would judge a request as nobody while a handler acts as a user. |
| Let an `Authenticator` or the custom-scheme verifier vouch for it | Both end at `SignatureMatch`. A token is not a signature comparison, and its evidence must not satisfy the signed contract. |
| Reuse `Verdict::Bearer` and `BearerReceipt` | That receipt is bound to one operation's resource and expiry, which the gateway compares. A header token has neither, and one scheme for both would stop a policy telling them apart. |
| Put the claim on each operation, as the query bearer claim is | The credential is service-wide. A per-operation list would have to be repeated on every standard operation and would drift. |
| A precedence rule between the token and an AWS credential | Either order lets a client choose which of two verifications it would rather pass. |
| Hand the verifier the token | The validation already happened. A second holder of the secret adds a place to log or cache it and binds nothing the request-owned state does not bind. |
| Return `Option<Identity>` beside a refusal | Two spellings of "no" invite reading one of them as "treat as anonymous". |
| Admit the token on privileged or STS operations | Admin, configuration and credential issuance stay behind a signature until a decision says otherwise. RustFS's STS endpoint is not privileged, because it admits an anonymous web-identity form, so the service is refused by name. |
| Let the claim name any header | The claimed header is removed before acceptance. A claim on a framing header would change what acceptance judges, so only an `x-` extension header can be claimed. |
| Strip the token from each context after verification, as the query token is | Every future context would have to remember. Removing the header before acceptance covers them by construction. |
| Refuse a request whose `Connection` header nominates the claimed header | A compliant intermediary removes a nominated field, which leaves the anonymous request the client could have sent anyway. At the first hop the outer layer and the floor read the same map. The nomination grants nothing, so it is given no meaning. |
| Require TLS for a header token in the gateway | The issue fixes the transport rules at those of an unsigned request. The authorizer sees both the scheme and whether the transport was secure, and can refuse. |

## Consequences

Adding `HeaderToken` to the exhaustive `AuthSchemeRef` is a downstream source break. The
implementation bumps the signature, core and facade crate versions, states `BREAKING` and gives the
migration: a `match` on `AuthSchemeRef` adds an explicit `HeaderToken` arm, and a handler that
serves such requests reads `RequestContextView::header_token_principal`.

Where this mirrors ADR-0042: a sealed admission only the floor produces, a host verifier as the
declared trust boundary, a sealed receipt, a crate-private verdict constructor, a panic boundary
that refuses, credential-work governor classing, and a service-level check that accepts the verdict
only from the request's own admission. Where it deviates, and why: the claim is service-level
because the credential is; the verifier is not given the token and returns no grant, because the
gateway has no resource or expiry to compare; there is no path beside a signature, because
admission is exclusive; and the header is removed before acceptance instead of per context.

The host owns the following, and the gateway cannot check them:

- The outer layer validates the token on every request and installs the identity in that request's
  own state. It must leave the claimed header in place, because the gateway consumes it. It must
  establish an identity from the claimed header only: an identity established from any other header
  reaches a request the gateway treats as anonymous.
- Replay policy, expiry and revocation. A header token is a bearer credential; the gateway keeps no
  token state and accepts it as often as the host does.
- A verifier that blocks stalls its request. It must only read what the outer layer left.
- A recorder or log layer outside the gateway sees the raw head. The recorded-request corpus
  redacts `x-auth-token` and `x-storage-token`; any other claimed name is the host's to redact.
- A stage filter's wire seam runs before the header is removed and sees it, as it sees
  `authorization`.

Residual, shared with ADR-0046 and tracked in rustfs/gateway#1574: `HeaderTokenAdmission::verify`
is public because the facade calls it across a crate boundary, so host code can build a
header-token verdict from an admission it obtained from `SecurityFloor::admit`. The service-level
check keeps such a verdict out of any other request's pipeline.

Threat model, and the control for each:

| Threat | Control |
| --- | --- |
| Duplicate token headers, or a list in one value | Exactly one occurrence and no comma; otherwise `403`. |
| Case variants of the name | Header names are compared lowercased; the claim is lowercase by construction. A different name, including one with `_`, is a different header and is ignored as today. |
| Whitespace variants of the value | Surrounding whitespace is the transport's to strip; a value with interior whitespace or a control byte is `403`. |
| The header beside a query bearer token, or on a bearer-claimed route | Refused: the route does not admit the scheme, with or without its parameter. |
| The header beside a presigned URL or any signing parameter | Refused by the default predicate, under the legacy recognition too. |
| The header on a browser form | Refused: a form is authenticated by its policy or not at all. An unrouted form beside the token is not read. |
| HTTP/2 pseudo-headers and repeated field lines | A pseudo-header cannot be claimed; repeated lines are duplicates. Trailers are never read. |
| A stage filter writing or deleting the header | The floor reads the caller's copy, taken before the wire seam. |
| A verifier that refuses, panics or is absent | `403`, reported as one contained-panic event for a panic; never anonymous. |
| A verdict minted for another request | Accepted only from the request's own admission. |
| The token in a log, error, `Debug` output or context | Never copied by the admission; removed from the head before acceptance. |

Guardrails: the compile-fail doctests in `crates/sig/src/header_token.rs` (forging, cloning,
default-constructing and laundering), the floor's `tests/header_token.rs`, the facade's
`tests/header_token.rs` and `tests/header_token_secrecy.rs`, and the admin dialect census in
`crates/goldens/src/rustfs_admin_dialect/header_token_tests.rs`. Negative cases outnumber positive ones,
and each new assertion is mutated once in the implementing pull request.
