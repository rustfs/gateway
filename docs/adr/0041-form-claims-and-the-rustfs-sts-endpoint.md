# ADR-0041: Form claims, and RustFS's STS endpoint behind one

- Status: Accepted
- Date: 2026-10-07
- Trigger: axiom A4, because whether a request is a dialect's is decided by a reviewed claim per route, and RustFS's STS endpoint is a route no path claim and no S3-table row can express. Also a crate boundary: `rustfs-gateway-dialect-rustfs-admin` now serves a route ADR-0032 (b) left with RustFS.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 and ADR-0032 and leaves their text unchanged. It is the "own ADR" for
STS `POST /` that ADR-0026 (g) asked for.

The target is a one-shot replacement: RustFS keeps no legacy S3 stack, so every route that stack
authenticates today must be authenticated by the gateway, exactly as legacy RustFS authenticates
it ([rustfs/gateway#1232](https://github.com/rustfs/gateway/issues/1232)). ADR-0032 (b) published
STS `POST /` in the dialect's `STAYING` list; served by RustFS without the legacy stack, it would
lose its signature check.

What legacy RustFS does with that route, from source (rustfs/rustfs `95268a3b9`, the legacy stack at
its pinned revision):

- **Which requests.** `is_sts_query_request` (`rustfs/src/server/layer.rs:878-886`): `POST`, the raw
  path exactly `/`, and a first `Content-Type` value that is visible ASCII and whose part before the
  first `;`, trimmed, equals `application/x-www-form-urlencoded` ignoring ASCII case. Nothing else is
  read: not the host, not the query.
- **Before anything S3.** The admin router's `is_match` asks that predicate
  (`rustfs/src/admin/router.rs:3266-3269`), and the legacy stack asks a custom route before it
  classifies the path (`ops/mod.rs:885` at `0.17.0`). So a virtual host naming a bucket RustFS would
  refuse, and a query naming `delete` or `x-id`, are still STS.
- **Authentication.** The legacy stack verifies whatever signature the request carries, as for any
  request: a SigV4 header under any service RustFS allows (`s3`, `sts`, `s3tables`;
  `rustfs/src/server/http.rs:166-173`), hashing the body itself for an `sts` scope without
  `x-amz-content-sha256` (`ops/signature.rs:794`, rustfs/gateway#1230), a presigned URL, and SigV2 by
  header or presigned. Then a declared body past 1 MiB is `400 EntityTooLarge` (`ops/mod.rs:446-448`),
  then `check_access` lets an unsigned STS request through and any signed one
  (`router.rs:3325-3332`).
- **The handler.** `AssumeRoleHandle` reads `Action` from the body (`rustfs/src/admin/handlers/sts.rs:187-194`):
  `AssumeRole` refuses a request without credentials (`400 InvalidRequest "get cred failed"`) and
  checks its own IAM policy; `AssumeRoleWithWebIdentity` authenticates by the token in the body; any
  other action is `400 InvalidArgument`. No policy is asked before the handler.
- **The answer.** RustFS's STS layer writes the request identifier on an STS answer itself, and its
  request-context layer leaves STS out of the S3 answers it identifies
  (`rustfs/src/server/layer.rs:172-179`).

Nothing in the gateway could express the route. A path claim (ADR-0024) is a prefix of at least
two segments, so it never covers `/`. An S3-table row is never asked under
legacy RustFS's operation selection (rustfs/gateway#1127) for a `POST /` it reads as
`DeleteObjects`, and a refused bucket label is answered before routing.

## Decision

**(a) A dialect may install a form claim.** A `FormClaim` names an exact raw path. It covers a
`POST` of exactly that path whose first `Content-Type` value is visible ASCII and names
`application/x-www-form-urlencoded` before its first `;`, trimmed of spaces and tabs, compared
ASCII case-insensitively. It covers it on every host, every endpoint face and whatever the query;
it reads nothing else. The router asks form claims first, then path claims, then the S3 table. The
media type is fixed rather than a field: S3 sends no form body of its own (its browser upload is
`multipart/form-data`), and one consumer needs no other. A form claim is refused when its path is
not absolute, has an empty or dot segment or a trailing `/` (the root aside), spells a byte outside
RFC 3986's unreserved set, or is one segment: that is the bucket position, and a claim there would
take the bucket's own `POST`s (`?delete`) from S3 on every host, which ADR-0024's depth rule exists
to prevent. It must carry a reason and evidence. Two form claims on one path, and a form claim whose
path an installed path claim covers, refuse the router.

**(b) One operation per form claim, recorded as its selector.** `DialectBuilder::declare_form`
takes the claim and a precedence. The overlay row records the claim as
`FormClaim(POST "<path>")`, and the operation is service-level. The pipeline treats
a form-claimed request as claimed: no bucket from the host, no bucket CORS, the claimed-route body
ceiling of the RustFS profile, and, under legacy RustFS identification, no identifier written by
this service. Start-up prints `FORM_CLAIM_POSTURE claimed_forms=[POST path@dialect]` when one is
installed, on a line of its own so `DIALECT_POSTURE` keeps its shape.

**(c) RustFS's STS endpoint is `rustfs:StsFormPost`, behind the dialect's form claim on `/` and
`application/x-www-form-urlencoded`.** It leaves `STAYING` and is listed in a new `FORM_ROUTES`
record, generated from the inventory like every other operation and bound back to it. Its action is
the vendor label `rustfs:AssumeRoleHandle` (ADR-0032 (a): the handler's name), asked of the
authorizer with or without an identity; RustFS's adapter allows it, because legacy RustFS asks no
policy before its handler. Its codec hands the body over as it arrived (`RequestBodyMode::Full`) and
answers what the handler answers. Its floor is not privileged and opts in to anonymous requests,
which the posture report lists:

- an unsigned request reaches the handler, as legacy RustFS lets it;
- a header signature under `s3`, `sts` or `s3tables` is verified under the RustFS profile's signing
  services, an `sts` scope over the body's digest (rustfs/gateway#1230);
- a presigned URL is admitted where the assembly admits presigned URLs on standard operations
  (ADR-0035), and a SigV2 one where the floor admits SigV2, as the RustFS profile does.

Legacy-compat (rustfs/backlog#2684): a presigned URL signs neither the `Content-Type` nor the body,
and the predicate reads neither host nor query, so any `POST` URL presigned for the path `/` (one
for `POST /`, or a virtual-hosted `DeleteObjects` URL, `POST /?delete` on a bucket's host) resent
with a form body lets whoever holds it choose the `Action`, session policy and duration of the
credentials it mints under the signer's identity. Kept so a client that presigns its STS call keeps
working; the intended future behaviour is a privileged floor, header signatures only. The comment
sits on the floor in the generated operation, and `sts_parity` pins the `DeleteObjects` case on both
stacks.

**(d) A SigV2 signature names the bucket the host names.** Legacy RustFS reads the host before any
route claims the request, so its SigV2 canonical resource carries the host's bucket label even when
a claim then reads the path path-style or the label is one its bucket rules refuse. The facade took
the bucket after the legacy split had re-read a claimed request, and refused such signatures.
`HostResolver::signing_bucket`, a provided method fed by the request's one `resolve` answer, now
names the label; `LegacyRustfsVirtualHosts` names it even when it refuses the bucket, and every
other resolver names the bucket it resolved. An assembly without the legacy split never re-reads a
virtual-hosted request, so its signatures are unchanged. Legacy-compat (rustfs/backlog#2684): under
the legacy split a claimed request on a bucket's host signs `/{bucket}/{claimed path}`, the resource
a path-style SigV2 request for the key `{claimed path}` in that bucket signs, so a captured
signature of one replays as the other within its `Date` window, with the same method and headers.
Kept because a SigV2 client of legacy RustFS signs that resource; the intended future behaviour is
the classified bucket, none for a claimed request. The comment sits on the trait method.

**(e) Known differences, both failing closed.** The facade's request acceptance refuses a repeated
or non-UTF-8 `Content-Type` `400` before anything routes; legacy RustFS reads the first value and
serves STS when it names the form type (`sts_parity` pins the repeated case on both stacks). And
the claimed-route body ceiling reads the declared length only: a form-claimed body with no
`Content-Length` (a chunked transfer) is not stopped at 1 MiB as it streams. Under
`refuse_unsized_buffered_bodies_as_legacy_rustfs` a signed one is `411` before it is read, and an
anonymous one is read up to the buffered-body ceiling and then refused `411`.
How legacy RustFS reads an unsized body is rustfs/gateway#1173's to settle, for every buffered
route at once.

**(f) What stays as it was.** The admin claims, their rows and fallbacks, the OIDC bootstrap, the
table catalog and the profiling claims are unchanged. The two object-zip-download routes and the
four `/health` routes stay in `STAYING` for the reasons ADR-0032 (b) gives; RustFS's custom S3-shaped
extension routes (`replication-*`, `lambdaArn`, `events`) and its website hosts are not decided here.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- Measured by `cargo test -p rustfs-gateway-core --test integration dialect_form_claims`: 15 cases,
  11 negative. The four routing cases first failed at a router that ignored form claims (the
  refusal cases already passed against the validation written beside them, so their mutations below
  are their evidence). They cover every host and face, S3 operation keys in the query, legacy
  RustFS's selection reading `POST /?delete` as `DeleteObjects` without the dialect, the media
  type's spellings, the first value only, a value that is not visible ASCII, every grammar rule, an
  overlay row not recording the claim, a bucket resource, and overlaps inside a dialect, across two
  and with a path claim.
- Measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin`: the STS operation's routing with
  and without the dialect under both selections, every near miss reaching what it reaches without
  the dialect, its floor, action, codec and record, and the census: 312 operations, six staying
  routes, one form route, 366 inventory routes.
- Measured by `cargo test -p rustfs-gateway-goldens --lib sts_parity`: one request matrix sent to the
  pinned legacy stack — configured as `rustfs_s3_config` configures it, with RustFS's STS predicate
  and access check as its route — and to an assembled gateway with the RustFS profile's
  authentication, routing and answer switches. For every row the two stacks answer the same status,
  code and message, write the same identifiers (none), and hand their STS handler the same caller
  and body or none: nine signature forms reaching the handler, four anonymous bodies, thirteen host,
  query and media-type spellings (SigV2 on a virtual host among them, and a bucket label RustFS
  refuses), a presigned `DeleteObjects` URL under SigV4 and SigV2 resent as a form, four forged
  credentials, a signature over another body, four near misses, and a body past 1 MiB with a valid
  and a forged signature. An unknown key is `403` on both, `NotSignedUp` from the oracle's callback
  where RustFS IAM says `InvalidAccessKeyId`; a repeated `Content-Type` is pinned as the difference
  (e) records.
- Measured by `cargo test -p xtask -- rustfs_admin_dialect`: the generator plans the STS route behind
  its form claim from the inventory's facts, refuses a stale form route, and refuses an inventory row
  that no longer records an anonymous, buffered `StsFormPost` route.
- Measured over raw sockets against a legacy RustFS build, recorded in
  [#1232](https://github.com/rustfs/gateway/issues/1232): header-signed `AssumeRole` under `sts` and
  `s3`, SigV2 and SigV4 presigned all issue credentials; anonymous web-identity and `AssumeRole`
  requests reach the handler; the media type's case and parameters do not matter, a longer media
  type is not STS; a virtual-hosted `POST /` is STS whatever its bucket label and query; `POST //` is
  not; a body past 1 MiB is `400 EntityTooLarge`.
- Every assertion added here has a mutation that turns it red; the PR lists each.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| A one-segment path claim on `/` | It would take every request away from S3. A claim's depth rule exists because the first segment is a bucket. |
| An S3-table dialect row with a media-type predicate | Legacy RustFS's selection reads a virtual-hosted `POST /?delete` as `DeleteObjects` before an added row is asked, and a refused bucket label is answered before routing; a new predicate kind would also widen the lattice for one route. |
| Route STS ahead of the gateway in RustFS | RustFS keeps no legacy stack to verify the signature with; the end state is that the gateway authenticates every signed route. |
| A privileged, header-only floor | Legacy RustFS verifies presigned STS calls and they mint credentials today; refusing them breaks a client RustFS serves. Recorded as a Legacy-compat item instead. |
| Read `Action` before authentication and route each action to its own operation | Legacy RustFS dispatches on `Action` in its handler, after authentication; reading a body before authentication to route it would be a new unauthenticated read. |
| A claim that also matches the method, host or query by predicate | The STS predicate reads none of them; every added dimension is one more way to disagree with it. |

## Consequences

- **BREAKING** in `rustfs-gateway-core`: `ClaimLookup` gains `Form`, `Dispatch` gains `form`,
  `RouteBuildError` and `DialectError` gain variants, and `ClaimedTable::is_empty` counts form
  claims. In `rustfs-gateway-dialect-rustfs-admin`: `STAYING` loses `POST /`, the crate exports
  `FORM_ROUTES` and `FormRouteRecord`, and the dialect declares `rustfs:StsFormPost`, reachable
  anonymously and listed in `SECURITY_POSTURE anonymous_reachable_ops=[…]`.
- A deployment that installs the dialect and registers no STS handler answers a form `POST /` with
  `501`, where S3 routing answered before; RustFS registers its handler, as for every operation.
- Enforcement: the tests listed under Evidence; the form-claim grammar and overlap refusals at
  dialect assembly and router build; the overlay cross-check of the rendered claim; the generator's
  refusals; and the posture line.
