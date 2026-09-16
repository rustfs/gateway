# ADR-0030: Bound buckets, query buckets and the trailing-slash heal route for RustFS's order-5 admin routes

- Status: Accepted
- Date: 2026-09-16
- Trigger: axiom A4, because which bucket an admin operation is authorised on is decided per route and per parameter, and the `Authorizer` is asked about that bucket. Also a crate boundary: `rustfs-gateway-core`'s `PathTemplate` accepts a template it refused before, `rustfs-gateway-dialect-rustfs-admin` declares a bucket for nineteen operations (`AdminOperation::BUCKET`, `RouteRecord::bucket`), and RustFS's handlers must read the bucket from the request context instead of the path or the query.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 to ADR-0029 and leaves their text unchanged. It applies ADR-0025 (c)
(`BucketParam::Path`) and ADR-0026 (e) (`BucketParam::Query`), which built the mechanism and
proved it on one route each, to the generated dialect; ADR-0027 (a) said a bucket parameter "waits
for its group to take ADR-0025's binding", and the generator refused it until now.

rustfs/backlog#1744 generates the `rustfs` dialect from the recorded inventory
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, RustFS `736e4fb8`) with
`cargo xtask rustfs-admin-dialect`. Orders 1 to 4 landed in rustfs/gateway#801, #805 and #819:
221 operations on 442 rows.

ADR-0024's order 5 is five registration groups and 22 routes: `quota_handler` 7,
`on_demand_migration` 6, `heal` 5, `durability_handler` 3 and `usage_prefix` 1. Raising the
migrated order to 5, the generator refused the first `{bucket}` template it met
("`{bucket}` is a bucket, which waits for ADR-0025's bucket binding"). Seventeen routes carry
`{bucket}`; one of them, `POST heal/{bucket}/{prefix}`, carries a second parameter. Five routes
are custom-auth: four `S3Action` (`GET get-bucket-quota`, `GET quota/{bucket}`,
`GET quota-stats/{bucket}`, `POST quota-check/{bucket}`) and one `MultipleActions`
(`GET usage/{bucket}`). Two routes name their bucket only in the query: `GET get-bucket-quota`
and `PUT set-bucket-quota`. One route is registered with a trailing slash: `POST heal/`.

What each handler does was read at `736e4fb8` (`rustfs/src/admin/handlers/**`) before the
generator was given its rules:

- **The three `s3:GetBucketQuota` reads check the action on the bucket.**
  `GetBucketQuotaHandler`, `GetBucketQuotaStatsHandler` and `CheckBucketQuotaHandler` call
  `validate_admin_request_with_bucket` with `S3Action::GetBucketQuotaAction` and the bucket
  (`quota.rs:399-408`, `:585-594`, `:658-667`). `GetBucketQuotaHandler` serves both
  `quota/{bucket}` and `get-bucket-quota`, and reads the bucket from the template parameter or,
  failing that, the first `bucket` query value (`bucket_from_params_or_query`, `quota.rs:83-96`);
  an empty bucket is `400 InvalidRequest` after authentication.
- **Every other order-5 handler checks an admin action on no bucket and reads the bucket
  afterwards.** `SetBucketQuotaHandler` and `ClearBucketQuotaHandler` check
  `admin:SetBucketQuota` through `validate_admin_request`, whose `evaluate_admin_actions` passes
  an empty bucket (`auth.rs:66-85`); `SetBucketQuotaHandler` also serves `set-bucket-quota` and
  reads `bucket` from the query. The durability handlers check `admin:ConfigUpdate` the same way
  (`durability.rs:122-142`). The on-demand-migration handlers check their admin action, then
  confirm the bucket exists and answer `404` when it does not (`authorize_for_bucket`,
  `on_demand_migration.rs:392-404`). `HealHandler` checks `admin:Heal` and reads `bucket` and
  `prefix` from the route parameters afterwards (`heal.rs:73-76`, `:1340-1357`).
- **`BucketPrefixUsageHandler` authorises with the `datausageinfo` gate**, any of
  `admin:DataUsageInfo` and `s3:ListBucket`, on no bucket (`usage_prefix.rs:70-79`); ADR-0025 (d)
  already ruled that binding `{bucket}` here is a deliberate tightening.
- **`POST /rustfs/admin/v3/heal/` is registered with its trailing slash** in `route_policy.rs:347`
  and asserted that way in `route_registration_test.rs:200`, `:1327`; the same handler serves
  `heal/{bucket}` and `heal/{bucket}/{prefix}`. RustFS routes with `matchit`, which matches
  `/heal/` and `/heal` as different paths, so a request without the slash reaches no route. The
  `{prefix}` parameter is one segment, as `matchit` reads `{prefix}`, so the gateway's
  whole-segment parameter matches exactly what RustFS matches.
- **`PathTemplate::parse` refused a trailing slash** (`TemplateRejection::TrailingSlash`), and
  `PathTemplate::matches` compares segment for segment, so `/rustfs/admin/v3/heal/` could be
  spelled by no row.

## Decision

**(a) A `{bucket}` template parameter is the operation's bucket.** The generator binds it as
`BucketParam::Path("bucket")` on every route whose template carries it, and the operation declares
`ResourceShape::Bucket`. That is ADR-0025 (c)'s mechanism applied uniformly: the governor, both
`Authorizer` stages, the audit event and the handler context see the bucket and no key, and the
raw segment meets the S3 bucket-name rules before authentication. The bucket stays among the
decoded path parameters too, so a handler that reads `RequestContextView::path_params()` still
finds it; `RequestContextView::bucket()` is the authorised value.

For `usage/{bucket}` and the three `s3:GetBucketQuota` reads this matches or completes what
RustFS checks. For the thirteen admin-action routes (`durability`, `on-demand-migration`,
`quota` PUT and DELETE, `heal/{bucket}` and `heal/{bucket}/{prefix}`) it is a tightening: RustFS
asks its policy about the action on no resource, the gateway asks about the action on the bucket.
A policy that grants the admin action on `*` is unaffected; a policy scoped to a bucket resource
now takes effect. This is the same choice ADR-0025 (d) made for `usage/{bucket}`, taken once for
the whole order rather than route by route, because a `{bucket}` parameter that were not the
bucket would be a route whose authorisation resource the reviewer cannot read off the template.
`{warehouse}` takes the same binding when order 6 migrates; the generator refuses a template with
two bucket parameters.

**(b) The two compat quota routes bind a query bucket.** `GET get-bucket-quota` and
`PUT set-bucket-quota` name their bucket only in the query, so the generator binds
`BucketParam::Query("bucket")` on both, from a list of `(method, path, parameter)` next to the
rulings (`QUERY_BUCKETS`). The `GET` is ADR-0026 (e)'s ruling, `s3:GetBucketQuota`; the `PUT` is
the inventory's own `admin:SetBucketQuota`, bound so that the two spellings of one handler are
authorised on the same resource. The facade reads the parameter exactly once before
authentication and answers `400 InvalidArgument` naming it for a repeat in any spelling, an
undecodable key, or an absent or empty value; RustFS reads the first of several and refuses only
an empty one, after authorisation. That divergence is recorded per operation in the generated
module documentation. A signed request cannot repeat `bucket` today: SigV4 canonicalisation
refuses the duplicate first, so two buckets fail closed at the signature, as two accounts do
(ADR-0026 (d)). The generator refuses a query bucket on a route whose template already
names one, one spelled outside RFC 3986's unreserved set, one that is the query key selecting a
form, one a subject rule of the same operation reads, and one listed for no migrated route.

**(c) A template may end with `/`, and then matches exactly that path.** `PathTemplate::parse`
accepts a trailing `/` as an empty last literal segment; every other empty segment is still
refused as `EmptySegment`, and `TemplateRejection::TrailingSlash` is removed. Such a template
matches a request path with that trailing `/` and nothing else: not the path without it, not a
second `/`, not a longer path. A parameter never matches an empty segment (ADR-0024 (b)), so a
trailing `/` and a parameter in the same position share no path: `heal/` and `heal/{bucket}`
overlap nothing and declare no shadowing, in core's `overlap_path` and `refines` and in the
generator's shadowing rule alike. `PathClaim` keeps refusing a trailing slash: a claim names a
prefix, a template names a path.

So `POST /rustfs/admin/v3/heal/` is `rustfs:PostV3Heal` (the name drops the empty segment), with
the alias `/minio/admin/v3/heal/`, and `POST /rustfs/admin/v3/heal` names no operation inside the
claim, as in RustFS. The other four heal routes are ordinary: `heal/{bucket}` and
`heal/{bucket}/{prefix}` bind their bucket under (a) and hand `prefix` on as a service-level
parameter under ADR-0027 (a).

**(d) The order-5 rulings.** `GET quota/{bucket}`, `GET quota-stats/{bucket}`,
`POST quota-check/{bucket}` and `GET get-bucket-quota` are `s3:GetBucketQuota` on the bound
bucket (ADR-0025 (d)). `GET usage/{bucket}` is `anyOf(admin:DataUsageInfo, s3:ListBucket)` on the
bound bucket (ADR-0025 (d)). Every other order-5 route carries the inventory's own action.

**(e) What the dialect declares.** `AdminOperation` gains `const BUCKET: Option<BucketParam>`,
`None` by default, and `Declare` passes it as the `ClaimedRoute`'s `bucket_param`; the overlay row
records the binding after the rows, as core renders it (` ⇒ BucketParam("bucket")` or
` ⇒ BucketQuery("bucket")`), with `resource: ResourceShape::Bucket`. `RouteRecord` gains
`bucket: Option<BucketParam>`, the same value. A bound operation's module cites this ADR and, for
a query bucket, ADR-0026.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The route counts come from a `python3` pass over the inventory's rows by group, measured:
  22 routes, 17 with `{bucket}`, 2 with a query bucket, 5 custom-auth, 1 with a trailing slash.
- The RustFS semantics were read at `736e4fb8e8e5d527c25e4e56f352536b311b6daf`. The file and
  line references are in Context.
- Core, measured by `cargo test -p rustfs-gateway-core --lib -- route::claim` and
  `cargo test -p rustfs-gateway-core --test integration -- dialect_claims_refusals`: three unit
  tests on the trailing slash (exact match, every other empty segment refused, no overlap with a
  parameter), and the malformed-template table with `/acme/admin/v1/x//` as `EmptySegment`.
- The generator, measured by `cargo test -p xtask -- rustfs_admin_dialect`: the drift check over
  248 files; a template bucket, a query bucket and a service-level template rendered; a trailing
  slash kept, named and shadowing nothing; five query-bucket refusals and three template refusals;
  and the recorded plan's 17 + 2 bindings, its five order-5 rulings and its five pending groups.
- The dialect, measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin`: 486 rows route;
  53 parameters across 44 templates refuse a dot segment, a separator and nothing, and the one
  path an empty `{bucket}` spells is the `heal/` row; the `heal/` row by exactly its path; every
  claimed entry carries its record's binding, 17 by template and 2 by query; and every operation's
  resource is `Bucket` exactly when its record binds one.
- The proof, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_dialect`:
  every row is asked about its bound bucket or none and hands its handler the same; 34 template
  rows and 4 query rows refuse seven invalid bucket names as `400 InvalidBucketName` before the
  `Authorizer` is asked; the query rows refuse an absent or empty `bucket` as
  `400 InvalidArgument` naming it, and a repeated one cannot be signed; a denial's question names
  the bucket on all 38 bound rows; and
  `POST heal/` is reached by exactly its path, `POST heal` is the claim's `501`.
- Every assertion added here has a mutation that turns it red. The PR lists each mutation.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Bind `{bucket}` only where RustFS checks a bucket (the four `s3:GetBucketQuota` reads and `usage/{bucket}`) | Thirteen routes would carry a `{bucket}` that is not the bucket, which a reviewer cannot tell from the template, and `PUT quota/{bucket}` would be authorised on nothing while `GET quota/{bucket}` is authorised on the bucket. The uniform rule is the one ADR-0025 (c) described. |
| Leave `set-bucket-quota` service-level, as RustFS authorises it | The same handler behind `PUT quota/{bucket}` would then be authorised on the bucket under one spelling and on nothing under the other. |
| Spell `heal/` as `/rustfs/admin/v3/heal` and let the matcher ignore a trailing `/` on the request | A trailing `/` would then reach every one of 243 operations, where RustFS answers 404; and `heal` without the slash would be served, where RustFS does not. |
| Defer `POST heal/` alone and migrate the other four heal routes | The pending table counts groups, not routes, and a request inside the claim that matches no row is the claim's `501`, so RustFS could not serve the one route itself. |
| Keep `TemplateRejection::TrailingSlash` for a template ending in two slashes | `//` at the end is two adjacent separators, which `EmptySegment` already names; a variant nothing produces is a false promise. |

## Consequences

- **BREAKING**: `rustfs-gateway-core` 0.43.0 and `rustfs-gateway-dialect-rustfs-admin` 0.5.0.
  - `TemplateRejection::TrailingSlash` is removed; a template ending in `/` parses.
  - `AdminOperation` gains `const BUCKET: Option<BucketParam>` with a default; a hand-written
    implementation compiles unchanged.
  - `RouteRecord` gains `bucket`. A literal adds `bucket: None`.
- **Enforcement:** the tests listed under Evidence; the registration refusals of ADR-0025 (c)
  and ADR-0026 (e); the overlay cross-check against `render_claimed_route`; the generator's
  refusals of a second bucket parameter, a stale or misplaced query bucket, and an empty segment
  that is not a trailing `/`.
- **RustFS's handlers**, when they register against this dialect, read the bucket from
  `RequestContextView::bucket()` and never from the path or the query; the on-demand-migration
  handlers keep their existence check and `404`.
- **ADR-0024's migration plan:** order 5 is resolved. Still open: `{warehouse}` takes (a) when
  order 6 migrates; everything orders 7 and 8 already listed.
