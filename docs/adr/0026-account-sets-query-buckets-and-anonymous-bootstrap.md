# ADR-0026: Account sets, query-bound buckets, and anonymous admin bootstrap

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4, because the `Authorizer` contract grows by one question per named account, and a request for every account is asked a broader action about no subject. Also a crate boundary: what `rustfs-gateway-core`'s `SubjectRule` and `ClaimedRoute` declare, what its extraction hands the facade (`Subjects`, a query-bound bucket), and what the facade hands the `Authorizer` and the handler.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 and ADR-0025 and changes none of their decisions.

rustfs/backlog#1744 migrates RustFS's admin API onto this gateway. After ADR-0025 these items
were still open:

- a multi-subject rule, for the three bulk access-key routes;
- a bucket named in the query, for `get-bucket-quota?bucket=`;
- ADR-0024's group 7: the anonymous OIDC bootstrap, STS's `POST /` form, and
  `object-zip-downloads/{id}.zip`;
- `/health`, which ADR-0024 refused as a one-segment claim.

What RustFS does was read at `736e4fb8e8e5d527c25e4e56f352536b311b6daf`, the commit the inventory
was taken at (`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`).

- **The builtin bulk listing** (`rustfs/src/admin/handlers/service_account.rs`):
  - The parser (`:1076-1098`) collects every `users` value and silently skips an empty one. It
    reads `all` as true for `true`, `1`, `on` or `yes`, and reads `listType`.
  - Naming users and `all` together is a `400` (`:1108`).
  - The request is about the caller alone when it names nobody, or names exactly one account that
    is the caller's access key or parent (`:1123-1130`).
  - `all` needs `admin:ListUsers` (`:1132-1154`).
  - `admin:ListServiceAccounts` is always evaluated, deny-only when the request is about the
    caller alone (`:1156-1177`).
  - Named accounts are listed as named, and `all` lists every IAM user (`:1183-1199`).
- **The LDAP and OpenID variants** (`idp_compat.rs:744-790`) parse the same way (`:876-900`).
  They evaluate `admin:ListServiceAccounts` in full, and also `admin:ListUsers` for `all` or for
  any request that names an account other than the caller.
- **`get-bucket-quota`** (`quota.rs:83-97`, `:394-408`) reads the first `bucket` in the query
  when no path parameter supplies one. It checks only that the value is non-empty, then asks for
  `s3:GetBucketQuota` on that bucket.
- **The OIDC bootstrap** (`oidc.rs:97-153`): `providers`, `authorize/{provider_id}`,
  `callback/{provider_id}` and `logout`, under both prefixes, are exempted from authentication by
  `is_oidc_path`. Their handlers make no policy check.
- **`GET object-zip-downloads/{id}.zip`** (`object_zip_download.rs:65-68`, `:586-595`,
  `:319-381`) carries no signature. It reads a bearer token from `?token=`, decrypts it with a key
  derived from server-held credentials, and checks its expiry and id. The token carries the
  creating principal's authorisation snapshot.
- **`/health` and `/health/ready`** (`health.rs:33-44`) answer `GET` and `HEAD` without
  authentication, ahead of S3 routing.

One fact about this gateway matters as much as any of these, measured in `crates/sig/src/query.rs`:
`RawQuery::canonical` refuses a query that repeats a parameter name, and both the signer and the
verifier use it. Its test `malformed_and_ambiguous_queries_are_rejected` includes `a=1&a=2`. The
rule exists for s3s#176: "the signature covered both copies, the handler read one" is how a
parameter gets smuggled.

## Decision

**(a) A set of accounts: `SubjectRule::Set`.** A third subject rule,
`SubjectRule::Set { param, everyone }`, where
`everyone: Option<Everyone { param, action }>`. Extraction produces `Subjects`:

- `One(Caller)`, when the request names nobody;
- `Each([..])`, the accounts it names, each once, in request order;
- `Everyone`, when the flag is `true`.

Extraction runs once, before authentication, with the strict reader the single-subject rule
already uses: every key is decoded, and `+`, a malformed escape and a control character are
refused. The following are each a `400 InvalidArgument` naming the parameter, never the value:

- an empty member;
- a name repeated after decoding;
- more than `MAX_SUBJECTS` (32) names;
- a member longer than `MAX_SUBJECT_BYTES`;
- a flag that is not exactly `true` or `false`, or appears twice;
- the flag set to `true` next to a name.

A rule without an every-account form does not own the flag parameter, so `all=true` there widens
nothing.

**(b) One question per account, all-of across accounts, and a broader action for every account.**
The route stage asks each of the rule's actions about each account, one group per account, in
request order. `AuthRequirement::decide` combines each group with the existing `ActionRule` and
keeps the first group that is not allowed, so one refused account refuses the whole request.

A request for every account asks two groups, both about no subject (`AuthzRequest::subject` is
`None`): the operation's own actions, then the rule's broader action. Asking about no subject is
what makes the broader question broader: no own-account relaxation can answer a question that
names nobody, and no grant scoped to named accounts adds up to one that is not.

The pieces around the questions:

- A count that does not match the questions is `Indeterminate`.
- The input stage re-asks the question that decided.
- The handler reads `RequestContextView::subjects()`. `subject()` stays `None` for a set, so a
  single-subject handler cannot mistake the first account for the whole set.
- The anonymous guard is keyed on the rule, not on a question's subject. So an anonymous request
  for every account is refused before any question, even though its questions name nobody.

Registration refuses:

- a set or flag parameter outside the unreserved set;
- a flag parameter equal to the set parameter;
- a malformed every-account action;
- an every-account action that every named account is already asked, which is the one action of
  `new`, or a member of `all_of`. Such a form would need nothing a named account does not. A
  member of `any_of` is allowed, because it narrows the form to one alternative.

**(c) The three bulk rulings.** All three routes are
`admin:ListServiceAccounts about each(users, everyone=all ⇒ admin:ListUsers)`.

- For the builtin route this is RustFS's semantics exactly. Naming nobody is the caller, which a
  deployment `Authorizer` evaluates deny-only as RustFS does. A named account is asked about
  itself. `all` needs both actions, in full.
- The LDAP and OpenID variants diverge. RustFS also requires `admin:ListUsers` whenever such a
  request names an account other than the caller. The gateway cannot say "unless it is the caller"
  without deciding caller-ness in the facade, which ADR-0025 rejected. And
  `all_of(ListServiceAccounts, ListUsers)` would leave `all` with no broader action, which (b)
  refuses.
- The ruling is therefore the builtin semantics. A deployment `Authorizer` that wants RustFS's
  LDAP behaviour answers the `ListServiceAccounts` question about a non-caller account with
  `ListUsers` as well: it sees both the operation and the subject. This joins ADR-0025's recorded
  finding that the variants disagree.
- The builtin route seals its response under the caller's secret at the MinIO alias (the
  inventory's `response-on-minio-alias`), so its migration must opt in per ADR-0024 (d).

**(d) Naming two or more accounts fails closed today.** A signed request that repeats `users`
never reaches the set: SigV4 canonicalisation refuses it first. This is fail-closed, and
deliberately not relaxed here. Admitting it means changing `rustfs-gateway-sig`, which is
HIGH-RISK. The constraints that change must meet:

- the repeatable parameter is declared on the operation's `OperationFloor`, never globally;
- registration refuses a floor whose repeatable parameter is not its operation's set parameter;
- the canonical form sorts repeats by value, as AWS's does;
- the wire layer's `SINGLE_VALUED_QUERY_PARAMS` still wins.

The s3s#176 concern does not apply to that one parameter, because the facade hands every value,
and only those values, to both the `Authorizer` and the handler. The change is left to its own
reviewed task. Until then, a caller naming several accounts sends one request per account, or
`all=true`.

**(e) A bucket named in the query: `BucketParam::Query`.** `ClaimedRoute::bucket_param` becomes
`Option<BucketParam>`: `Path(name)` is ADR-0025's template binding, and `Query(name)` is new.

For a `Query` binding, the facade finds the parameter's one occurrence with the same strict reader
(`single_raw_value`), before authentication, and refuses with `400 InvalidArgument` naming it:

- a repeat in any key spelling;
- an undecodable key;
- an absent or empty value.

The raw, undecoded value then goes through `codec::bucket_label`, so a name S3 refuses as
`/{bucket}` gets the same `400 InvalidBucketName` here, an escaped spelling included. The governor,
both `Authorizer` stages, the audit event and the handler see that bucket, and a claimed request
never consults its CORS.

Registration refuses a query binding on an operation that is not `ResourceShape::Bucket`, a
parameter outside the unreserved set, and a parameter the operation's subject rule also reads. The
overlay records the binding as ` ⇒ BucketQuery("bucket")`.

The ruling for `get-bucket-quota` is `s3:GetBucketQuota` with `BucketQuery("bucket")`. It
diverges from RustFS on purpose: RustFS takes the first of two `bucket` values and checks only
that the value is non-empty.

**(f) Anonymous admin bootstrap uses the per-operation opt-in that already exists.** Each of the
four OIDC bootstrap routes is a claimed operation:

- its floor calls `allow_anonymous_after_listing_in_the_posture_report()`, so the start-up
  `SECURITY_POSTURE anonymous_reachable_ops=[…]` line names it;
- its overlay row sets `anonymous: true`, which the dialect checks in both directions;
- its action is the operation's own vendor label (`rustfs:OidcAuthorize`), because RustFS makes no
  IAM check there and an `admin:` spelling would read as one.

The `Authorizer` is still asked, with no identity, so a deployment can refuse. Presigned requests
stay refused, and nothing else in the claim becomes anonymous. The other OIDC routes (`config`,
`validate`) are ordinary `sigv4-admin`.

**(g) Two group-7 routes stay with RustFS, for recorded reasons.**

**`GET object-zip-downloads/{id}.zip`** needs two things, and neither is only a routing change:

1. **An affixed parameter.** `{id}.zip` is still refused as `ParameterWithAffix`. Supporting it
   means a suffix-literal segment kind:
   - a raw segment matches when it ends with the literal and the rest is a one-segment value;
   - extraction decodes only the rest, and refuses a dot segment there;
   - overlap is decided literal against affixed, and affixed against affixed. Two affixed
     segments are disjoint only when neither suffix ends the other.
2. **A bearer credential.** The route authenticates by a token in the query, not by a signature.
   Admitting it anonymously under (f) would let the governor, the `Authorizer` and the audit
   record see an anonymous caller for a download that acts with a stored principal's authority.
   And it would put a bearer credential in the query, where ADR-0024 (f) refused presigned URLs
   for the same reason.

   The direction, for an amendment of ADR-0009 and ADR-0022: a per-operation bearer scheme on the
   `OperationFloor` names the token parameter. A deployment-supplied verifier resolves the token
   to its principal and expiry, and fails closed. The verdict is then authenticated under a
   distinct scheme, and the token never reaches logs, audit or the handler context. That touches
   the verdict surface `check_scope_rejection_surface.sh` guards and the `Authenticator` contract,
   so it is not done here.

**STS `POST /`** has no surface in this gateway. Its action is in the form body, which pre-body
routing cannot read. Its authentication is mixed:

- `AssumeRole` is SigV4-signed under the `sts` service, over the form body;
- the web-identity, LDAP and client-grants forms are unsigned and carry a token.

It needs its own ADR: a `POST /` row discriminated by content type, a body read before
authentication like the PostObject form bridge, and an `sts` credential scope.

**(h) `/health` belongs in the server's probe layer, and lands with the ring-2 assembly.** The
probe matches exact paths, admits `GET` and `HEAD` only, is anonymous, and answers from a
deployment readiness source, all ahead of the S3 service. It is not S3 routing and not a claim.

It necessarily shadows path-style `GET|HEAD /health` and `/health/ready`: a listing or `HEAD` of a
bucket named `health`, and its key `ready`. RustFS does exactly that today. So the probe must be an
explicit, opt-in assembly choice that the start-up report names.

It must compare exact paths. `rustfs-gateway-server`'s `PrefixDispatch` compares raw prefixes with
`starts_with`, so a `/health` route there would also capture `/healthy/…`, which is a whole bucket.

It is not implemented here, because its readiness facts (storage, IAM, lock quorum) are RustFS's.
`/profile/cpu` and `/profile/memory` remain two-segment claims under ADR-0024.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The RustFS semantics above were read at `736e4fb8`. The file and line references are in Context.
- `rustfs-gateway-core`, measured by `cargo test -p rustfs-gateway-core --lib -- authz:: registry::reject`:
  - `authz/rule_tests.rs` holds extraction and registration faults for a set: order, decoding,
    empty, duplicate, bound, flag, contradiction, and a flag the rule does not own.
  - `authz/plan_tests.rs` holds the questions and their settling: one refused account refuses a
    set; any-of applies per account; every account is refused without the broader action; a
    mismatched count and an every-account request under a rule without the form are
    `Indeterminate`.
  - `authz/query.rs` holds the strict single-value reader.
  - `registry/reject_rule_tests.rs` holds the set-rule registrations and every query-binding
    refusal.
- The pipeline, measured by `cargo test -p rustfs-gateway --test integration -- action_rules_runtime`:
  - an anonymous set request, including `all=true`, is refused without a question;
  - a signed every-account request asks both actions, and is refused without the broader one.
- The proof, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_proof`:
  - `set_tests.rs` covers the three bulk routes, the query-bound quota route, and a request naming
    several accounts that cannot be signed;
  - `anonymous_tests.rs` covers the four OIDC bootstrap routes, with exactly those four admitting
    anonymous requests under the predicate `SECURITY_POSTURE` prints.
- `crates/sig/src/query.rs`, `malformed_and_ambiguous_queries_are_rejected`: a repeated parameter
  is refused by the canonicaliser that the signer and verifier share.
- The one-question path allocates nothing new. `question_count`, `question` and `decide` read the
  requirement and borrow the subjects, and `tests/request_allocations.rs` passes unchanged
  [inferred from the code, measured by that test].

## Rejected alternatives

| Alternative | Why it lost |
|---|---|
| Parse the set as RustFS does: skip empty members, keep duplicates, read `all=yes` | The facade and a handler that re-parses would disagree about which accounts were judged, which is the disagreement ADR-0025 closed for one subject. |
| Ask the `Authorizer` once, with the whole set | An existing `Authorizer` reads one subject, which is a silent allow for the rest. |
| Expand every account into a question per existing account | The gateway cannot enumerate accounts, and it would be unbounded. The flag with a broader action is what RustFS itself checks. |
| A `Subject::Everyone` variant for the every-account questions | An `Authorizer` that reads `name() == None` as "the caller" would relax exactly the question meant to be broadest. Asking about no subject has no such reading. |
| Require the every-account action to differ from all of the operation's actions | It forbids an any-of rule narrowed to one alternative. The real fault is a form that asks nothing more, which is what registration refuses. |
| Admit repeated query parameters in SigV4 now, or globally | Global admission reopens s3s#176 for every parameter. A per-operation declaration is a HIGH-RISK signature change and gets its own reviewed task. |
| A comma-separated `users` list | No RustFS or MinIO client sends one [inferred]. It would only move the ambiguity into the value. |
| Decode a query-bound bucket before validating it | `%70hotos` would become `photos` here while S3 refuses `/%70hotos`, the reason ADR-0025 validates the raw segment. |
| Anonymous OIDC through `delegate_anonymous_to_authorizer…` | That setting applies to the whole assembly. The per-operation opt-in names exactly four operations in the posture report. |
| Admit `{id}.zip` anonymously now | Its authority is a stored principal's, not an anonymous caller's. Doing so would settle the bearer-credential question by default. |
| `/health` as a one-segment claim, or through `PrefixDispatch` | The first is refused by ADR-0024, because it shadows a bucket. The second captures `/healthy/…` too. |

## Consequences

- **BREAKING**: `rustfs-gateway-core` 0.40.0 and `rustfs-gateway` 0.47.0.
  - `SubjectRule` gains `Set`, and `SubjectError` gains `Duplicate`, `TooMany`, `Contradictory`
    and `Flag`. Exhaustive matches must add them.
  - `SubjectRule::extract` returns `Subjects`. A single subject is `Subjects::One(subject)`.
  - `ClaimedRoute::bucket_param` is `Option<BucketParam>`: write `Some(BucketParam::Path("bucket"))`
    where `Some("bucket")` was. `ClaimedEntry::bucket_param` returns `Option<BucketParam>`.
  - `RequestContextView::with_subject` is now `with_subjects(Option<Subjects>)`. `subject()` is
    `None` for a set request, and `subjects()` is new.
  - `Combined::deciding` indexes questions, not actions.
  - New public items: `Everyone`, `Subjects`, `MAX_SUBJECTS`, `Question`,
    `AuthRequirement::{question_count, question, decide, everyone_action}`, `single_raw_value`,
    `QueryParamError` and `BucketParam`.
- **Enforcement:**
  - the tests under Evidence;
  - the registration refusals;
  - the overlay cross-check against `AuthRequirement::render` (` about each(…)`) and
    `render_claimed_route` (` ⇒ BucketQuery(…)`);
  - the posture predicate for the anonymous opt-ins.
- **ADR-0024's migration plan changes as follows:**
  - The three bulk routes are ruled, and naming a single account works. Naming several waits for
    (d)'s signature change.
  - `get-bucket-quota` is resolved.
  - In group 7, the four OIDC bootstrap routes are resolved. `{id}.zip` and STS `POST /` stay
    with RustFS under (g).
  - In group 8, `/health` is decided under (h) and lands with the ring-2 assembly.
