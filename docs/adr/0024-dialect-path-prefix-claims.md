# ADR-0024: Dialect path-prefix claims, path templates, alias rows, a per-operation caller secret and service-level operations

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4, because the caller-secret hand-off moves from the granularity of an authenticator to the granularity of an operation. Also a crate boundary: what `rustfs-gateway-core`'s router hands the facade (a claimed row and its typed path parameters), and what the facade hands the `Authorizer` for a service-level operation.
- Supersedes / Superseded by: none

## Context

This ADR refines ADR-0022's secret hand-off rule and leaves the rest of ADR-0022 unchanged.

rustfs/backlog#1744 migrates RustFS's admin API onto this gateway as dialect operations. The
first slice, rustfs/gateway#778, recorded a live inventory of 356 RustFS admin routes
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, RustFS `736e4fb8`). It proved
three of them as `rustfs:` extension operations
(`crates/goldens/src/rustfs_admin_proof.rs`). It also found six gaps, each pinned by a test.

1. **A path literal does not make an admin row disjoint from S3.** The route lattice treats the
   path and the target as independent dimensions. So `GET /rustfs/admin/v3/info` on a path
   literal overlaps every standard `GET` object row, and under `ShadowingPolicy::EveryOverlap` it
   owes one declaration per row: 10 for a `GET` and 11 for a `PUT`. `docs/dialects.md` said such a
   row "overlaps nothing", which is wrong.
2. **No path template.** 145 of the 356 routes carry path parameters.
3. **One route row per operation.** 251 routes are also served at `/minio/admin/…`. The 31
   routes that seal a request or response body with the caller's secret do so only at that alias.
4. **The secret hand-off is all or nothing per authenticator.** 325 of the 356 routes never need
   the secret, yet with ADR-0022's switch on, every handler in the assembly holds it.
5. **A service-level admin action was authorised with a bucket.** The path-style resolver reads
   `/rustfs/admin/…` as bucket `rustfs`, and the facade passed that bucket to the `Authorizer`
   even though the operation declared `ResourceShape::Service`.
6. **Presigned admin requests were never ruled on.** `OperationFloor::custom` admits header
   signatures only.

The inventory's prefixes, measured: 251 routes under `/rustfs/admin` (240 `v3`, 11 `v4`), 49
under `/iceberg`, 49 under `/_iceberg`, 4 under `/health`, 2 under `/profile`, and 1 at `/`. Within
one prefix and one method, exactly three pairs of routes overlap. Two are
`/iceberg/v1/buckets/{warehouse}` against `/iceberg/v1/{warehouse}/namespaces` (and the
`/_iceberg` pair). The third is `POST /rustfs/admin/v3/tier/clear` against
`/rustfs/admin/v3/tier/{tiername}`.

## Decision

**(a) A dialect claims path prefixes, and S3 routing never sees inside them.**
`DialectOverlay::claims` lists `PathClaim { prefix, reason, evidence }` entries next to the
operations, and review happens there. The router asks the claimed table first:

- If a claim covers the request, a claimed row answers it or nothing does. In the second case the
  answer is `501` with `NO_CLAIMED_ROUTE_MESSAGE`. The request is never handed to the S3 table.
- Otherwise the S3 table decides, exactly as before.

A claim covers a request only when all of these hold:

- it is path-style (`RouteRequestParts::host_named_bucket` is false);
- it is on the standard endpoint (`HostClass::Standard`);
- it has no ARN in the bucket position;
- its raw path equals the prefix or continues it with `/`.

The prefix is compared byte for byte with the raw path, like every routing value.

A claim must satisfy these rules:

- It is at least **two segments deep**, spelled only in RFC 3986 unreserved characters, with no
  empty, `.` or `..` segment and no trailing `/`.
- It carries a reason and non-blank evidence.
- It overlaps no other installed claim, from any dialect.
- At least one of its dialect's rows sits inside it.
- No S3-table row may pin a path literal inside it.

Every installed claim is listed at start-up as `DIALECT_POSTURE claimed_prefixes=[prefix@dialect,…]`.

**Buckets named `rustfs` or `minio`.** In a path-style request the first segment is the bucket.
So a one-segment claim (`/health`, `/rustfs`, `/iceberg`) would take a whole bucket away from S3,
and it is refused with `ClaimRejection::ShadowsABucket`. A two-segment claim such as
`/rustfs/admin` takes only the path-style spelling of the keys `admin` and `admin/…` in the bucket
`rustfs`, which is what RustFS's admin router does today. Everything else stays S3:

- the bucket itself (`GET /rustfs`, `PUT /rustfs`, `?location`);
- every other key in it;
- the same keys spelled virtual-hosted;
- a percent-encoded spelling of the prefix (`/rustfs/%61dmin/…`), which is an ordinary object
  request for the decoded key, authorised as `s3:GetObject`.

**(b) Path templates inside a claim.**
A `ClaimedRow { template, selector }` has a template such as `/rustfs/admin/v3/tier/{tier}`,
built from literal segments and whole-segment `{name}` parameters. The template starts with its
claim's segments. The selector names exactly one method and may add query or header predicates. It
may name no target, path literal, host class or ARN form, because the claim decides those.

A parameter matches one non-empty raw segment that is not a dot segment in any spelling (`.`,
`..`, `%2e`, `%2E%2e`, …) and carries no `/`, `\`, `%2F` or `%5C`. So a template never matches
across segments.

After routing and before authentication, the facade calls `PathTemplate::extract`. It decodes each
value once and refuses a malformed escape, invalid UTF-8, a separator, a dot segment or a control
character. The refusal is a `400 InvalidArgument` that names the parameter and never echoes the
value. Handlers read the values from `RequestContextView::path_params()`, as `get(name)` or
`parse::<T>(name)`. A parameter sharing a segment with literal text (`{id}.zip`) is refused as
`ParameterWithAffix` in this slice.

Claimed rows owe no declaration against the S3 table, because they cannot overlap it. Between
themselves they get the S3 table's own rules:

- an overlap at one precedence is a `Conflict`;
- an overlap across precedences needs a `ShadowingDecl` between the two dialect operations;
- a stale or unsourced declaration is refused.

**(c) Alias rows.**
`DialectBuilder::declare_claimed::<O>(ClaimedRoute { precedence, rows, shadows })` gives one
operation any number of rows, typically the canonical `/rustfs/admin/…` row and its
`/minio/admin/…` alias. The overlay row records all of them, rendered by `render_claimed_rows`
as `PathTemplate("…") ∧ Method(…) ∨ …`, so an alias is reviewed like the canonical row. Declaring
one name both ways is `DeclaredTwice`.

**(d) The caller secret has an operation-level opt-in and an assembly-level scope.**
`OperationSpec::hand_caller_secret_to_handler()` sets a private flag, which
`receives_caller_secret()` reads. The authenticator's switch is unchanged:
`SigV4Authenticator::hand_caller_secret_to_handlers()`, or `AuthenticationOutcome::with_caller_secret`
from a custom authenticator, still decides whether a looked-up secret is available at all. Which
handlers receive it is now the assembly's decision:

- By default, only the operations that opted in. For every other operation the facade drops the
  `SecretBytes`, zeroized, on the line that reads the verdict, before any authorisation or body
  read.
- `ServiceBuilder::hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()`
  restores ADR-0022's every-handler scope. It exists because the migration seam
  (`Principal::from_handler`, rustfs/backlog#1752) refuses to invent the secret that s3s's
  `Credentials` always carries, so the ring-2 adapter must hand it to every S3 handler it wraps.

The scope sits on the assembly, not in `AuthenticationOutcome`. That surface is closed at
ADR-0009's fields plus ADR-0022's one secret (`scripts/check_scope_rejection_surface.sh`), and an
assembly flag is one the start-up report can name:
`DIALECT_POSTURE … caller_secret_scope=opted-in|every-operation`. Everything else about the value
is unchanged from ADR-0022:

- it is off by default;
- it attaches to an authenticated principal only;
- it is exposed only through `CallerSecretKey::expose_secret`;
- it has no `Clone` and no `PartialEq`, and its `Debug` prints `<redacted>`.

A standard operation that opts in is refused at registration
(`RegistryError::StandardOperationReceivesCallerSecret`), so a standard operation holds the secret
only under the explicitly widened scope. Opted-in operations are listed as
`DIALECT_POSTURE … caller_secret_ops=[…]`.

**(e) Service-level operations get no bucket.**
`ResourceShape::Service` already means "the service itself"; the defect was that the facade
ignored it. Now, when the routed operation declares `ResourceShape::Service`, or when a claimed row
routed it, the facade addresses the request as `TargetKind::Service` with no host bucket. So the
governor, both `Authorizer` stages, the audit event, the committed-response context and the
handler's `RequestContextView` all see no bucket and no key. The raw path still reaches the
signature and the context unchanged. A claimed operation that declares a `Bucket` or `Object`
resource is refused (`ClaimedOperationNamesAResource`), because inside a claim nothing supplies one.

**(f) Presigned admin requests are refused by default.** A dialect operation keeps
`OperationFloor::custom`, which admits header signatures only. A presigned request to a claimed
operation is a `403` before the `Authorizer` is asked anything. An operation may opt in only
through `OperationFloor::allow_presigned`, which lists it in `presigned_allowed_ops`. No
operation opts in until a RustFS admin client is shown to presign that route.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- Inventory counts, measured by a `python3` pass over
  `crates/goldens/src/migration_inventory/rustfs_admin_routes.json`:
  - 356 routes;
  - 145 with a `{…}` segment;
  - 251 with `minio_admin_alias`;
  - 31 with a `caller_secret_body` other than `none`;
  - prefixes 251 / 49 / 49 / 4 / 2 / 1 as listed above;
  - 3 overlapping same-method pairs inside one prefix;
  - 1 route (`GET /rustfs/admin/v3/object-zip-downloads/{id}.zip`) with an affixed parameter;
  - 107 routes with a `{bucket}` or `{warehouse}` parameter (96 in `table_catalog`, 11 among
    `quota_handler`, `on_demand_migration`, `durability_handler`, `heal` and `usage_prefix`).
- Declarations in the proof, measured by `git show de85ca85:crates/goldens/src/rustfs_admin_proof.rs | grep -c "    claims("`
  (55) and `grep -c "    ahead_of(" crates/goldens/src/rustfs_admin_proof.rs` (34): the #778 proof carried 55. The 21 for its two path-literal rows (10 + 11) are
  gone, because their operations are now claimed rows that owe none. The 34 for
  `ReplicationMetricsV2` remain. That operation is an S3-shaped request by design
  (`GET /{bucket}?replication-metrics=2`), and each of its overlaps is a real routing decision
  about a request a client can send, such as `?acl&replication-metrics=2`.
- Tests, measured by `cargo test -p rustfs-gateway-core` and
  `cargo test -p rustfs-gateway --test integration -- dialect_claims_runtime request_context_runtime`:
  - `crates/core/tests/dialect_claims.rs` and `dialect_claims_refusals.rs` hold the rules.
  - `crates/core/src/route/claim.rs` unit tests hold the matcher.
  - `crates/gateway/tests/dialect_claims_runtime.rs` holds the pipeline: no bucket at either stage,
    typed values, the claim's own `501` and the `400` both before authorisation, and the
    virtual-hosted, presigned and anonymous negatives.
  - `crates/gateway/tests/request_context_runtime.rs` holds the per-operation secret.
  - Three compile-fail doctests pin `PathParams` (`E0451`), `ClaimedEntry::new` (`E0624`) and
    `OperationSpec::caller_secret` (`E0616`).
- The every-operation scope is load-bearing, measured: switching the goldens seam harness to the
  per-operation scope turns all 20 `operation_diff::*::context` tests red, because the seam
  refuses to build an s3s credential without a secret.
- Matching allocates nothing and is not `async`: `PathClaim::covers` and `PathTemplate::matches`
  split a borrowed `&str`, and `crates/core/tests/purity_guard.rs` scans both new route files
  (measured).

## Rejected alternatives

| Alternative | Why it lost |
|---|---|
| Keep path-literal rows and write the declarations | 356 routes × 10–11 declarations that all say the same thing. The first model upgrade that adds an object `GET` row makes every one of them owe one more. |
| A `PathPrefix` or `PathTemplate` variant of `Predicate` inside the S3 lattice | `Predicate` mirrors the frozen `spec/ir.schema.json` one for one. And to make the rows disjoint, every S3 row would have to reject claimed paths, which makes each S3 selector depend on which dialects are installed. |
| A cell-wide declaration ("this row stands in front of every row in its method and target") | It silently approves a routing change the moment a model upgrade adds a row to the cell. That is the reason `ReplicationMetricsV2` keeps its 34 declarations. |
| One-segment claims that "reserve" a bucket name (`/health`, `/iceberg`) | A whole bucket becomes unreachable path-style while it stays creatable and readable virtual-hosted. That is a bucket half-owned by S3, and a claim must never shadow a bucket name. |
| Apply claims to virtual-hosted requests too, as RustFS's router does | The path of a virtual-hosted request is a key, so the claim would capture that key in every bucket. |
| Decide the claim on the decoded path | That adds a second decode on the pre-authentication path. The encoded spelling gains nothing: it is an ordinary S3 request, authorised as one. |
| Keep the secret per authenticator (ADR-0022 alone) | 325 of 356 routes would hold a key they never read. |
| Replace ADR-0022's every-handler scope with the per-operation one outright | The s3s migration seam cannot build credentials without a secret and must not invent one. Measured: with only the per-operation scope, all 20 goldens context-diff tests over `PutObject` and `GetBucketLocation` fail with `the gateway authenticator did not hand the caller's secret to the handler`. |
| Carry the scope in `AuthenticationOutcome` as `Option<(SecretBytes, scope)>` | This was the first implementation. `check_scope_rejection_surface.sh` refuses it, measured, because the outcome is a closed surface and a second secret-bearing shape is exactly what that guard exists to stop. It also leaves the scope invisible to the start-up report. |
| Record the secret opt-in on the dialect declaration or overlay | The pipeline reads the routed operation's spec, and the overlay is not consulted per request. The spec flag is private, so it cannot be flipped after the fact, and the posture report lists it. |
| A new `ResourceShape` variant for "no resource" | `ResourceShape::Service` already says it. The defect was the facade ignoring it, not a missing word. |
| Admit presigned admin requests by default, or per authenticator | We found no RustFS admin client that presigns an admin route [inferred]. A presigned URL is a bearer credential in a log line, and a per-operation opt-in already exists and is reported. |

## Consequences

- **BREAKING**: `rustfs-gateway-core` 0.37.0 and `rustfs-gateway` 0.45.0.
  - `DialectOverlay` gains `claims`: add `claims: &[]`.
  - `RouteRequestParts` gains `host_named_bucket`: pass `false` for path-style, or
    `ResolvedHost::bucket().is_some()`.
  - `Dispatch` gains `claimed`.
  - `RouteBuildError`, `DialectError` and `RegistryError` gain variants.
  - `hand_caller_secret_to_handlers()` now reaches only the operations whose spec calls
    `OperationSpec::hand_caller_secret_to_handler()`. An adapter that needs the secret in every
    handler (the s3s seam) adds
    `ServiceBuilder::hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()`.
  - A `ResourceShape::Service` operation is authorised with no bucket even when its path names one.
- Enforcement:
  - the tests listed under Evidence;
  - `crates/core/tests/purity_guard.rs` (routing stays synchronous and store-free);
  - the `DIALECT_POSTURE` start-up line;
  - the overlay cross-check, which refuses a claimed route whose rows the overlay does not
    record.
- **Migration plan, by registration group.** Counts are routes in the inventory.
  - **Claims to install:** `/rustfs/admin` and `/minio/admin` in the `rustfs` dialect, plus
    `/iceberg/v1` and `/_iceberg/v1` for the table catalog.

  | Order | Groups | What this ADR already gives | What they still need |
  |---|---|---|---|
  | 1 | `system` (9): `info`, `storageinfo`, `metrics`, `update`, `v4/runtime/capabilities` | claimed rows, `/minio/admin` aliases, service-level actions | the 4 custom-auth routes (`MultipleActions` 1, `NotImplemented` 3) need their own ruling |
  | 2 | `diagnostics` (12), `profile_admin` (6), `rebalance` (3), `bucket_meta` (4), `extensions` (2), `module_switch` (2), `object_data_cache` (2), `cluster_snapshot`, `gateway_key_inventory`, `inspect_archive`, `plugins_catalog`, `tls_debug` (1 each) | everything: plain `sigv4-admin`, no template, no secret | nothing |
  | 3 | `kms` (35), `site_replication` (22; 1 sealed), `config_admin` (9; 6 sealed), `batch_job` (5; 1 sealed), `tier` (7; includes the `tier/clear` versus `tier/{tiername}` overlap, which needs one declaration), `ilm_transition` (11), `scanner` (5), `audit` (3), `plugins_instances` (4), `pools` (6; 2 `MultipleActions`) | templates, aliases, the per-operation secret | a ruling for each `MultipleActions` route |
  | 4 | `user` (37; 14 sealed; 11 custom), `idp_compat` (13), `mfa` (8; 6 `CredentialOnly`), `account` (2), `replication_handler` (6) | the per-operation secret on exactly the sealed routes | the `CredentialOnly` and `ContextualAuthorization` rulings (authorise against the caller's own identity) |
  | 5 | `quota_handler` (7), `on_demand_migration` (6), `durability_handler` (3), `heal` (5), `usage_prefix` (1) | templates | a template parameter bound as the authorisation bucket: 11 routes carry `{bucket}`, and they are service-level only until that binding exists |
  | 6 | `table_catalog` (98) | claims at `/iceberg/v1` and `/_iceberg/v1`, templates, one declaration for each `buckets/{warehouse}` pair | the same bucket binding, for `{warehouse}` (96 routes) |
  | 7 | `oidc` (8; 4 anonymous bootstrap), `sts` (2; `POST /` form), `object_zip_download` (2; `{id}.zip`) | claimed rows for the signed half | anonymous acknowledgement per route; `POST /` stays an S3-table row with its declarations; affixed parameters |
  | 8 | `health` (6): `/health`, `/health/ready`, `/profile/cpu`, `/profile/memory` | `/profile/cpu` and `/profile/memory` can be two-segment claims | `/health` is a one-segment path and is refused as a claim. It belongs in the server's probe layer, ahead of the S3 service, or stays with RustFS. |
