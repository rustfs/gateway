# ADR-0054: A host-verified header token claim

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
`SecurityFloor` it assembles; nothing else turns the feature on. A floor that carries a claim the
builder was given no verifier for is an assembly error (`asm-header-token-unverified`): it would
refuse every request presenting the header, and a service that starts in that state is a
misconfiguration found by its users.

**Opt-in absent.** `SecurityFloor::admit` reads no header for this purpose, no context is changed,
and no posture line is added. A request carrying the header is treated exactly as it is today.

**The claim.** `HeaderTokenClaim::new` accepts an extension header that nothing else gives a
meaning to: `x-` followed by lowercase ASCII letters, digits and `-`, under none of the prefixes
`x-amz-`, `x-minio-`, `x-rustfs-`, `x-forwarded-` and `x-http-method`, and neither `x-request-id`
nor `x-real-ip`. The facade removes the claimed header before the request is accepted, so the
grammar admits no header that HTTP, the signature path, a dialect or a proxy in front reads: not
`authorization`, not a framing or routing header, and, having no `:`, no HTTP/2 pseudo-header.

**Refused aliases.** `HeaderTokenClaim::refusing_aliases` lists further header names, held to the
same grammar, under which the host's outer layer also reads the token (RustFS reads
`x-storage-token` beside `x-auth-token`). The gateway claims one header. A request that carried
only another name would be anonymous to the gateway, or its signer, while the host acted as the
token's user. A request that carries a refused alias is therefore decided by the claim's branch
and refused `403 AccessDenied`, alone, beside the claimed token or beside a valid signature, on
every operation. No context is built for it, so nothing else needs to forget the header. Refusing is chosen over
admitting under several names: one name has one shape rule and one occurrence rule, and "which of
two token headers wins" is a precedence the gateway would then own.

**Admission is exclusive, and runs first.** When the claim is installed and the request's head
carries the claimed header or a refused alias, `SecurityFloor::admit` decides the request in that branch alone, before
any other rule. The answer is a sealed `Admission::HeaderToken` or `403 AccessDenied`. It is never
a sealed AWS request, a custom-scheme request, a bearer admission or an anonymous one, so no other
verifier is handed a request that carries the token. The branch refuses, before any verifier runs,
a request that also presents any other credential surface. The surfaces are the ones the floor's
own detection names, read by the default predicate whatever recognition policy is configured:

- headers: `authorization` with any value, `x-amz-security-token`, and any header under a
  registered custom scheme prefix;
- query parameters, by decoded name: `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Signature`,
  `X-Amz-Security-Token`, `AWSAccessKeyId` and `Signature`; the three that are no marker by
  themselves but are what remains of a presigned URL, `X-Amz-Date`, `X-Amz-Expires` and
  `X-Amz-SignedHeaders`; and any of those seven `X-Amz-` names in another letter case;
- a browser form of any content, which covers `x-amz-algorithm`, `x-amz-credential`,
  `x-amz-signature`, `x-amz-security-token`, `AWSAccessKeyId`, `signature` and `policy`.

A query bearer token needs no entry: an operation that declares a query bearer claim refuses the
scheme, with or without its parameter. An object-path form that routes to no operation under the
RustFS selector is not read when the token is present; the request keeps the head-only refusal of
any unrouted request. There is no precedence and no fallback from one credential to the other.

The answer is the same under every assembly. The facade's RustFS view policies answer a malformed
header signature or presigned URL in legacy RustFS's own words before the floor runs; a request
that presents the claimed header or a refused alias skips those answers and reaches the floor,
which refuses it. Routing, addressing and wire refusals still come first, as they do for any
request: they do not depend on a credential. Skipping an answer is safe only if the floor refuses
everything that answer refused. The skipped policies read `Authorization` and the exact-case
presigned names, which the floor refuses, and one of them, the pre-routing header guard, reads
`x-amz-signature` in any letter case; that is why the floor refuses the `X-Amz-` presigned names
in any case beside a token, although no other rule of the gateway reads those spellings.
`cookie` and `proxy-authorization` are not credential surfaces anywhere in the gateway, and are
not refused here.

**Beside the SigV2 refusal (ADR-0052).** An operation that refuses SigV2 under every policy
admits a header token as any other standard operation does: the token is no SigV2 request, and
that rule lives in the scheme check, which a token request never reaches. A request that carries
the claimed header beside any SigV2 credential, in `Authorization` or in the query, is refused by
this claim's exclusivity on every operation, whether or not the operation admits SigV2. The STS
form and the zip download refuse the scheme for their own reasons above; the two metadata
listings refuse SigV2 and admit a token.

**Beside the caller's secret (ADR-0024, ADR-0053).** A caller's secret key exists only on a signed
principal, where the authenticator's lookup put it, and ADR-0053 hands it to an opted-in
operation only over a signed body. A header-token verdict has no signed principal: nothing was
looked up, so there is no secret to hand over, to any operation and under either scope of that
opt-in. `StsFormPost`, the operation ADR-0053 is about, never sees a header token at all, because
the STS service refuses the scheme; its signed-body condition is untouched by this record.

**The header's shape.** The branch then requires exactly one occurrence of the claimed header, with
a value of 1 to 8192 bytes, every byte ASCII graphic and none a comma. A repeated, empty, overlong,
non-ASCII, whitespace-bearing or list-shaped value is `403`. No occurrence is chosen over another.

**Which operations admit it.** `SecurityFloor::admits_header_token` is the one predicate; the floor
and the posture report both read it. It admits every standard S3 operation, bucket configuration
such as `PutBucketPolicy` included: the token speaks for its user on the S3 surface as a header
signature does, and the authorizer decides. It refuses privileged operations (the admin surface,
and every third-party operation that kept its default), credential issuance (every operation of the
STS service, privileged or not), an operation that takes a browser form, the bearer-claimed route,
and a route that requires SigV4 under every policy (ADR-0049). There is no per-operation opt-in for
any of them; adding one needs its own decision.

The predicate decides by attribute, so an operation added on a non-privileged floor admits the
scheme the moment it exists. Two reviewed lists make that a decision rather than an accident: the
operations of the reference backend that admit the scheme
(`crates/gateway/tests/golden/header-token-operations.txt`), and the operations of the `rustfs`
dialect that do. The dialect's list is RustFS's two metadata listings (ADR-0050), admitted
deliberately: they stand on the standard listing floor, answer what `ListObjectsV2` and
`ListObjectVersions` answer plus each object's user metadata, and the authorizer decides them as
it decides those. The first list covers the reference backend's fifty operations and nothing
else: a host registers its own set, and needs its own reviewed list, taken from the
`HEADER_TOKEN_POSTURE` line of its own assembly. A session-credential operation such as `CreateSession` must be marked to refuse
the scheme when it lands; the list is where its absence is checked.

**The verifier, and what binds the identity to the request.** A `HeaderTokenVerifier` names a
type, `Established`, and has one method, `identity(&Established, RequestNow) -> Result<Identity,
HeaderTokenRefused>`. The host's outer layer inserts a value of that type into the extensions of
each request it authenticated. `HeaderTokenAdmission::verify` reads that value from the accepted
request's own transport values, which no client can write. With no value the request is refused
and the verifier is not called; with one, the verifier is handed that value and the admission's
one clock reading, and nothing else: not the token, and no other part of the request. So the
verifier cannot report an identity for a request in which the outer layer established none, and
the implementation that needs no other state is the correct one. A thread-local, a global, a
"last authenticated" slot or a cache keyed on the connection is forbidden as the source of the
identity: each outlives one request, since requests share threads, HTTP/2 multiplexes callers onto
one connection and a keep-alive connection carries one caller after another. The slot is found by
its type, so `Established` must be a type private to the host's token layer: a newtype only that
layer constructs, never `()`, a string or a credentials struct other code also builds, or any
layer that inserts such a value establishes an identity. The kernel cannot check that. A task-local scoped
around the inner call would be sound, but the gateway could not tell it from the unsound sources,
so the typed slot is the one supported form. There is one spelling of "no": a refusal. The facade
runs the verifier inside its panic boundary; a refusal, a panic and an absent value are each
`403 AccessDenied`, and none becomes anonymous.

**The origin of the name.** `Identity` gains an origin, `AccessKey` or `HostToken`, that is part of
its equality and hash. Only `HeaderTokenAdmission::verify` marks a name `HostToken`, whatever the
verifier built. The policy source, both authorization stages, the audit event and the observer are
all handed that `Identity`, so a store keyed on it never answers a host-reported name with the
entry of the access key that shares its spelling, and no signature, custom scheme or bearer token
produces a name that passes for a host-reported one. A consumer that looks a principal up by the
bare `access_key_id()` string must branch on `Identity::origin`; that accessor's documentation
says so. The origin lives in the `Identity` value and nowhere else: `Identity::new` on the bare
name builds an access key of the same spelling, and an audit record that keeps only the name
writes two principals as one. Handlers and sinks carry the `Identity`.

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

**Shared caches.** An answer to a request served by its token carries `Vary` naming the claimed
header, appended beside whatever the response already varies on, and `Cache-Control: private`
unless the handler set a `Cache-Control` of its own. RFC 9111 section 3.5 keeps a response to a
request with `Authorization` out of a shared cache by default and gives an extension header no
such protection, so a header-token answer is not in the position a header-signed answer is in. A
handler's own `Cache-Control`, `public` included, is kept: the gateway does not overrule a handler
on caching anywhere else. That includes a `Cache-Control` an uploader stored on an object, which
`GetObject` answers: such an object goes out `public` with `Vary` on the claimed header. A cache
that honours `Vary` keeps callers apart; one that does not can serve it to another caller, as it
can for a header-signed request, where `public` also permits storing. This is a stated residual.

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
  When this change was last merged with `main`, at `6a45af45`, the same command listed `0053` as
  the highest numbered record, so this record is `0054`.
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
- Measured: the RustFS outer layer at `7f5fa4b8f62ed195a7887adccb47b37d505188bd` reads the token
  from `X-Auth-Token` and, failing that, from `X-Storage-Token`, and scopes the resulting
  credentials around the inner service call
  ([middleware.rs](https://github.com/rustfs/rustfs/blob/7f5fa4b8f62ed195a7887adccb47b37d505188bd/crates/keystone/src/middleware.rs#L159)).
  That layer holds the request mutably when it has the credentials, so it can insert them into
  the request's extensions; the second header name is why a claim can refuse aliases. Reproduce
  with `git show 7f5fa4b8f:crates/keystone/src/middleware.rs` in that repository.
- Measured through a Hyper HTTP/1 connection (`crates/gateway/tests/header_token_wire.rs`): one
  line of the claimed header is one token whatever the case of its name and whatever optional
  whitespace surrounds its value; a repeated or empty line is `403`; a line folded over two is
  answered `400` or `403` and never served; and a header nominated by `Connection` is still
  decided by the claim. HTTP/2 was not measured.
- Measured on the implementation of this record: the ten compile-fail probes in
  `crates/sig/src/header_token.rs` each fail with exactly one error. Run as ordinary doctests, they
  report `E0451` for a struct literal of the admission and of the receipt, `E0624` for the
  admission's constructor, for `Verdict::header_token` and for marking a name host-reported,
  `E0277` for `Clone::clone` on either, `E0599` for `default` on either, and `E0603` for building
  `Verdict::HeaderToken` directly. Stable `rustdoc` does not compare the code a
  `compile_fail` block names, so each probe was also made to compile by a mutation that grants
  what it forbids, and its test went red.
- The mutation of each new assertion, with the command that ran it, is recorded on
  rustfs/gateway#1586.

## Rejected alternatives

| Alternative | Reason |
| --- | --- |
| Leave the request anonymous and let the host read its own identity | The governor, both authorization stages and audit would judge a request as nobody while a handler acts as a user. |
| Let an `Authenticator` or the custom-scheme verifier vouch for it | Both end at `SignatureMatch`. A token is not a signature comparison, and its evidence must not satisfy the signed contract. |
| Reuse `Verdict::Bearer` and `BearerReceipt` | That receipt is bound to one operation's resource and expiry, which the gateway compares. A header token has neither, and one scheme for both would stop a policy telling them apart. |
| Put the claim on each operation, as the query bearer claim is | The credential is service-wide. A per-operation list would have to be repeated on every standard operation and would drift. |
| A precedence rule between the token and an AWS credential | Either order lets a client choose which of two verifications it would rather pass. |
| Hand the verifier the token | The validation already happened. A second holder of the secret adds a place to log or cache it and binds nothing the request-owned state does not bind. |
| Hand the verifier the request's whole state and let it look the identity up | It can then be written without reading the request at all, and a verifier backed by a thread-local or a connection cache hands one request another's identity with nothing in the API to notice. A typed slot the admission reads makes an absent identity a refusal before the verifier runs. |
| Accept the token under several header names | Two names need a precedence between them and double every shape rule. Refusing the alias has one answer and leaves the host's outer layer free to rename it first. |
| Hand the scheme to `PolicySource` instead of marking the identity | That changes a trait every host implements, and leaves the observer and any store keyed on `Identity` as they were. The origin travels with the value to every consumer at once. |
| Prefix the reported name, as `keystone:` would | The kernel would be inventing principal names, and a host's audit trail would no longer show the name its identity service issued. |
| Return `Option<Identity>` beside a refusal | Two spellings of "no" invite reading one of them as "treat as anonymous". |
| Admit the token on privileged or STS operations | Admin, configuration and credential issuance stay behind a signature until a decision says otherwise. RustFS's STS endpoint is not privileged, because it admits an anonymous web-identity form, so the service is refused by name. |
| Let the claim name any header | The claimed header is removed before acceptance. A claim on a framing header would change what acceptance judges, so only an `x-` extension header can be claimed. |
| Strip the token from each context after verification, as the query token is | Every future context would have to remember. Removing the header before acceptance covers them by construction. |
| Refuse a request whose `Connection` header nominates the claimed header | A compliant intermediary removes a nominated field, which leaves the anonymous request the client could have sent anyway. At the first hop the outer layer and the floor read the same map. The nomination grants nothing, so it is given no meaning. |
| Require TLS for a header token in the gateway | The issue fixes the transport rules at those of an unsigned request. The authorizer sees both the scheme and whether the transport was secure, and can refuse. |

## Consequences

`Identity` gains an origin that is part of its equality: a value built by `Identity::new` equals
what it equalled before, and nothing built before this change is `HostToken`. `AssemblyError`
gains a variant; it is non-exhaustive.

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
admission is exclusive; the header is removed before acceptance instead of per context; and the
verifier is handed a typed value the admission read from the request, where the bearer verifier
is handed the request's own token and path.

The host owns the following, and the gateway cannot check them:

- The outer layer validates the token on every request and inserts what it established into that
  request's own extensions, and inserts nothing otherwise. It must leave the claimed header in
  place, because the gateway consumes it. It establishes an identity from the claimed header only,
  and lists every other name it reads the token under as a refused alias, or renames that header
  to the claimed one before the gateway. A name the host reads and does not list is still the
  split identity described above; the gateway cannot see it.
- The kernel marks the reported name's origin. A policy source or authorizer that looks a
  principal up by the bare name string, rather than by the `Identity`, must branch on the origin
  itself, and a host whose token users and access keys are different principals should still keep
  their name spaces apart.
- `Vary` and `Cache-Control: private` are added to answers served by a token. A cache that ignores
  `Vary`, a handler that sets `Cache-Control: public`, and an object stored with one, are the
  deployment's.
- `Established` is a type private to the host's token layer, and the reported `Identity` is
  carried as a value and never rebuilt from its bare name.
- Each host keeps its own reviewed list of the operations it registers that admit the scheme.
- A proxy in front of the host removes a header that `Connection` nominates before this hop. The
  gateway decides by the head it receives.
- Replay policy, expiry and revocation. A header token is a bearer credential; the gateway keeps no
  token state and accepts it as often as the host does.
- A verifier that blocks stalls its request. It must only read what the outer layer left.
- A recorder or log layer outside the gateway sees the raw head. The recorded-request corpus
  redacts `x-auth-token` and `x-storage-token`; any other claimed name is the host's to redact.
- A stage filter's wire seam runs before the header is removed and sees it, as it sees
  `authorization`.
- The claimed header is outside the accepted head: acceptance's 128-field and 16 KiB ceilings do
  not count it, and the floor's own rule (one occurrence, 8 KiB) answers `403` at admission, after
  routing, where a wire refusal would have come first. The transport's own head limit still bounds
  it.
- One claim is in force. A second `host_verified_header_token` call replaces the first, and the
  builder's claim replaces one written onto the floor directly. A claim whose header falls under a
  registered custom scheme's prefix refuses every request presenting it. Neither is a build error;
  a claim on the floor with no verifier is.

Residual, shared with ADR-0046 and tracked in rustfs/gateway#1574: `HeaderTokenAdmission::verify`
is public because the facade calls it across a crate boundary, so host code can build a
header-token verdict from an admission it obtained from `SecurityFloor::admit` and request state
of its own making. The service-level check keeps such a verdict out of any other request's
pipeline.

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
| A verifier whose panic payload panics again when released | The payload is released under a second boundary; still `403`. |
| A token header an outer layer accepts under another name | A listed alias is `403` wherever it appears. An unlisted one is not seen by the gateway; see the duties above. |
| A verifier that answers from state shared between requests | The admission reads a typed value from the request's own extensions and refuses without one; the verifier is handed that value only. |
| A reported name spelled like an access key | The name is marked `HostToken`, which is part of `Identity`'s equality and hash. |
| A shared cache serving one caller's answer to another | `Vary` on the claimed header and `Cache-Control: private` on answers served by a token. |
| A token beside a malformed AWS credential under the RustFS profile | The profile's own answers are skipped; the floor refuses it `403`. |
| A new operation admitting the scheme unnoticed | Two reviewed lists, one per operation table, compared in tests. |
| The token sent as a trailer | Trailers are read by the payload decoder, never by the floor. |

Guardrails: the compile-fail doctests in `crates/sig/src/header_token.rs` (forging, cloning,
default-constructing and laundering), the floor's `tests/header_token.rs`, the facade's
`tests/header_token.rs`, `tests/header_token_host.rs`, `tests/header_token_secrecy.rs` and
`tests/header_token_wire.rs`, the reviewed operation list in `tests/rustfs_profile.rs`, and the
admin dialect census in
`crates/goldens/src/rustfs_admin_dialect/header_token_tests.rs`. Negative cases outnumber positive ones,
and each new assertion is mutated once by the change that adds it.
