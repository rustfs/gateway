# ADR-0027: Service-level template parameters, literal-over-parameter shadowing, and the caller secret for RustFS's order-3 admin routes

- Status: Accepted
- Date: 2026-09-14
- Trigger: axiom A4, because what a claimed row's template parameter authorises (a bucket, or nothing) and which operation a literal segment selects are decided per parameter and per row, not per dialect. Also a crate boundary: what `rustfs-gateway-dialect-rustfs-admin` hands RustFS (typed path parameters and, on eight operations, the caller's secret), and what a `rustfs-gateway-core` codec refusal may name.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 and ADR-0025, and changes none of their decisions.

rustfs/backlog#1744 generates the `rustfs` dialect from the recorded inventory
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, RustFS `736e4fb8`) with
`cargo xtask rustfs-admin-dialect`. Orders 1 and 2 landed in rustfs/gateway#801: 45 routes and 48
operations. The generator refused every route it had no rule for.

Raising the migrated order to 3 adds 10 registration groups and 107 routes: `kms` 35,
`site_replication` 22, `ilm_transition` 11, `config_admin` 9, `tier` 7, `pools` 6, `batch_job` 5,
`scanner` 5, `plugins_instances` 4 and `audit` 3. The generator refused them for three reasons.

1. **Templates.** 17 of the 107 routes carry path parameters: 19 parameters with 13 names
   (`tiername`, `tier`, `key_id`, `job_id`, `export_id`, `control_id`, `transaction_id`,
   `intent_id`, `target_type`, `target_name`, `id`). ADR-0024 left open whether a parameter binds
   as the authorisation bucket. ADR-0025 (c) gave the binding only to `{bucket}` and `{warehouse}`.
2. **One overlap.** `POST /rustfs/admin/v3/tier/clear` and `POST /rustfs/admin/v3/tier/{tiername}`
   both accept `POST …/tier/clear`. ADR-0024 counted this as the one same-method overlap in the
   `/rustfs/admin` prefix and said it needs one declaration.
3. **Custom auth.** `GET pools/list` and `GET pools/status` are `MultipleActions`. ADR-0025 (d) ruled
   them `any_of(admin:ServerInfo, admin:Decommission)`, but the generator had no rule for them yet.

Eight order-3 routes seal a body with the caller's secret: six in `config_admin`, `start-job` and
`site-replication/edit`. The generator already mapped the inventory's `caller_secret_body` column
to ADR-0024 (d)'s per-operation opt-in. No earlier route had used it.

What RustFS does was read at `736e4fb8`:

- **No order-3 parameter is a bucket.** A tier, a KMS key, an ILM job, a recovery record, a
  transaction, a scanner intent, an audit target and a plugin instance are all service-level
  objects. Each handler authorises with an empty bucket. The inventory records a `sigv4-admin`
  action with no bucket for all 17 routes.
- **A literal beats a parameter.** RustFS's admin router (`rustfs/src/admin/router.rs`) is
  `matchit` 0.9.2, which tries a static segment before a parameter whatever the insertion order.
  `route_policy.rs:362-363` registers both `tier` routes, and `route_registration_test.rs:1335`
  expects `POST /v3/tier/clear` to route.
- **The pools gate is any-of.** `ListPools` and `StatusPool` both call `authorize_admin_request`
  with `ServerInfoAdminAction` then `DecommissionAdminAction` (`handlers/pools.rs:498-502`,
  `:588-593`). That helper returns at the first allowed action (ADR-0025).
- **The secret is used only under the MinIO alias.** `read_compatible_admin_body` and
  `encode_compatible_admin_payload` (`admin/utils.rs`) decrypt or encrypt only when the path is
  under `/minio/admin`. At `/rustfs/admin` the same handler reads and writes plain JSON.

## Decision

**(a) A template parameter that is not `{bucket}` or `{warehouse}` is service-level.** The
operation keeps `ResourceShape::Service` and `bucket_param: None`. So the governor, both
`Authorizer` stages, the audit event and the handler context see no bucket and no key, exactly as
for the group's plain routes. The handler reads each value, decoded once, from
`RequestContextView::path_params()` under the inventory's own name. ADR-0024's matcher and
`PathTemplate::extract` already refuse, before authentication, a dot segment in any spelling, an
encoded separator, an empty value, invalid UTF-8 and a control character.

The generator accepts a template only under these conditions:

- every parameter is a whole segment named by a lowercase identifier (`[a-z_]+`);
- no name repeats;
- the names, in path order, equal the inventory's `path_params`;
- none is `bucket` or `warehouse`.

It refuses each of the following:

- an affixed parameter (`{id}.zip`);
- a malformed name;
- a repeated name;
- a list that disagrees with the inventory;
- a bucket parameter. That route waits for its group to take ADR-0025's binding.

An operation's name spells a parameter as `By` and its words: `rustfs:GetV3TierByTier`,
`rustfs:DeleteV3AuditTargetByTargetTypeByTargetNameReset`.

**(b) A literal segment stands in front of the parameter it meets, as in RustFS's router.** The
generator compares every two declared operations. It skips a pair with a different method, a
different query form, a different segment count, or two different literals at one position. For
each remaining overlapping pair:

- if one route has a literal wherever the other has one, and a literal somewhere the other has a
  parameter, it is the winner. The winner's operation emits one `ShadowingDecl` against the other,
  with RustFS's router and this ADR as evidence. `AdminOperation::shadows` carries it into
  `ClaimedRoute::shadows`.
- The winner must come first in inventory order, so that it has the lower precedence. If it comes
  later, the pair is refused.
- An overlap that no literal orders (`tier/{a}` against `tier/{b}`, or `a/{x}/c` against
  `a/b/{y}`) is refused.

Core's claimed table still checks each declaration in its direction and refuses a stale one.
Order 3 produces exactly one declaration: `rustfs:PostV3TierClear` shadows
`rustfs:PostV3TierByTiername`. `POST …/tier/clear` is the clear command, and every other segment
(`clears`, `CLEAR`, `hot`) is a tier name. A tier literally named `clear` cannot be addressed by
`POST`, which is also true on RustFS.

**(c) The pools rulings are ADR-0025's, now in the generator.** Both `pools/list` and
`pools/status` become `anyOf(admin:ServerInfo, admin:Decommission)`. The overlay row cites
ADR-0025. A later inventory that reclassifies either route reopens the ruling, because the
generator refuses a ruling whose recorded class changed.

**(d) The per-operation secret covers both rows of the eight sealed operations.** An operation opts
in to the caller's secret exactly when its inventory row's `caller_secret_body` is not `none`. Those
are `request-on-minio-alias`, `response-on-minio-alias` and `request-and-response-on-minio-alias`,
and the gateway treats all three the same. Every other operation is never handed the secret,
whatever the authenticator's switch says.

The opt-in is per operation, as ADR-0024 (d) made it. So the canonical `/rustfs/admin` row of a
sealed operation also carries the secret, although RustFS uses it only under `/minio/admin`. The
handler tells the two apart by the raw path in its context, as RustFS's
`is_compat_admin_request` does today.

**(e) A codec refusal may name an underscored member.** `ErrorContext::codec` validated a refusal's
member as an error code: a letter, then letters and digits. A malformed value in `{target_type}`
was therefore answered `500 InternalError` rather than ADR-0024's `400 InvalidArgument` naming the
parameter. That affects 8 of the 13 order-3 parameter names. A member now admits `_` after its
first letter. An error code is unchanged.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- Counts, measured by `cargo xtask rustfs-admin-dialect` and a `python3` pass over the inventory:
  - 107 order-3 routes become 107 operations, and the dialect now declares 155 operations on 310
    rows;
  - 17 templated routes with 19 parameters, none named `bucket` or `warehouse`;
  - 8 sealed operations;
  - 1 shadowing declaration;
  - `PENDING` lists 15 groups with 204 routes (orders 4–8).
- RustFS facts, read at `736e4fb8e8e5d527c25e4e56f352536b311b6daf`: the file and line references
  are in Context. `matchit = "0.9.2"` is in the workspace `Cargo.toml`, and its static-first
  priority is the crate's documented matching rule [inferred from the crate's documentation, not
  re-measured here].
- The generator, measured by `cargo test -p xtask --bin xtask rustfs_admin_dialect` (15 tests):
  - the drift check (157 files);
  - `By` naming;
  - the pools rulings;
  - the recorded opt-ins, exactly the eight sealed routes;
  - a templated route's parameters;
  - nine template refusals;
  - the one shadowing pair, and three overlaps it cannot order.
- The dialect, measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin` (15 tests):
  - every row routes;
  - every method on every row, plus near misses, reaches exactly what a matcher written in the
    test from ADR-0024's rule says;
  - 380 dot-segment, separator and empty values reach no row;
  - `tier/clear` wins over the `tier` templates and is the only declaration;
  - exactly the eight operations hold the secret;
  - no claimed entry binds a bucket.
- Through the facade, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_dialect`
  (11 tests):
  - every row is asked exactly its actions, about no bucket, no key and no account;
  - each handler is handed its decoded parameters;
  - exactly the 16 rows of the eight sealed operations hold the caller's secret, and it is the
    caller's;
  - the three any-of rows are authorised by either action;
  - 190 malformed parameter values are refused before the `Authorizer` is asked: `400
    InvalidArgument` naming the parameter without echoing the value, or the claim's `501`.
- The member rule, measured by `cargo test -p rustfs-gateway-core --test error_resolution`.
  Before (e), the goldens test answered `500 InternalError` for
  `DELETE /rustfs/admin/v3/audit/target/%ff/target_name-1/reset`.

## Rejected alternatives

| Alternative | Why it lost |
|---|---|
| Bind the first template parameter as the bucket, as ADR-0025 does for `{bucket}` | A tier, a KMS key or a job id would then have to satisfy S3's bucket-name rules. A policy on a bucket named `hot` would authorise tier `hot`, and RustFS authorises none of these on a bucket. |
| A per-route list of service-level parameters in the generator | 13 names across 17 routes, each needing its own review. The fact being reviewed is the same every time: the name is not `bucket` or `warehouse`, and the inventory records a service-level action. |
| Order the overlap by precedence alone, with no declaration | Under ADR-0024 an undeclared cross-precedence overlap is refused by design. A later inventory that adds a literal would then change routing silently. |
| Reorder the precedences so that a literal always wins, whatever the inventory order | Precedence is inventory order, which reviewers and `ROUTES` read. A generator that reorders silently hides the one case it should refuse: a literal that sorts after its parameter. |
| Split each sealed operation into a canonical operation without the secret and an alias operation with it | One RustFS handler would need two registrations and two names for one route. ADR-0024 (c) made an alias a row of the same operation. The secret is already confined to 8 of 155 operations, and the handler reads the path, as RustFS does. |
| Rename underscored parameters (`{targetType}`) so they pass the old member rule | The handler would read a name RustFS's router does not use, and the generated template would diverge from the inventory it is checked against. The refusal was a validation defect, not a naming rule. |
| Widen `valid_identifier` for error codes too | An error code is a wire token clients match on. Only the member, a diagnostic that names what was refused, needs the underscore. |

## Consequences

- `rustfs-gateway-dialect-rustfs-admin` 0.2.0:
  - 107 new operations;
  - `AdminOperation::shadows`, a provided method defaulting to none;
  - every existing operation's precedence renumbered in inventory order (overlay only; no
    request changes where it routes).
- `rustfs-gateway-core` 0.41.1: `ErrorContext::codec` admits `_` in a member. Nothing that was
  admitted before is refused now.
- Enforcement:
  - the generator's refusals and its drift check (`--check`, and the xtask test in
    `cargo test --workspace`);
  - core's claimed-table declaration checks;
  - the tests listed under Evidence.
- Goldens' assembled service tunes `framework_governor_rates`. Each test sends all 310 rows from
  one client, past the framework limiter's default burst of 256. The limiter stays in force.
- **ADR-0024's migration plan changes as follows:** order 3 is migrated. Order 4 next needs
  ADR-0025's `CredentialOnly` and `ContextualAuthorization` rules and the multi-subject rule
  (ADR-0026). Orders 5 and 6 need the bucket binding that (a) deliberately withholds from every
  other parameter.
