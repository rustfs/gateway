# ADR-0037: Refreshing the admin dialect from RustFS main: enum-dispatched handlers, new groups, and removed routes

- Status: Accepted
- Date: 2026-09-30
- Trigger: axiom A4, because which admin routes the gateway serves, and with which facts, is decided per inventory route. Also a crate boundary: `rustfs-gateway-dialect-rustfs-admin` declares seven operations it did not, removes one, and changes what one matches; RustFS registers its handlers against those names.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 to ADR-0032 and ADR-0036 and leaves their text unchanged.

The dialect is generated from an inventory recorded from one RustFS commit
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`), by a script that reads three
RustFS authorities — the route policy, the registration matrix and the insert sites — and refuses
to write unless they agree. The inventory was recorded at `736e4fb8` (2026-09-14). RustFS will run
its whole admin API on the gateway, so the dialect must serve the routes RustFS main serves
(rustfs/gateway#1172).

Against RustFS main `3268c42e00b375859b4535d53fe219b02d7bfe31` the script refused:

- **An enum-dispatched handler.** `register_integrity_routes`
  (`rustfs/src/admin/handlers/integrity.rs:40-51`) inserts five routes from a loop whose rows carry
  one handler value per route, `&Handler(Route::Readiness)`, wrapped by the insert as
  `AdminOperation(handler)`; the script knew only rows that carry the operation itself. The one
  `impl Operation for Handler` dispatches on the variant (`integrity.rs:90-158`): only `Create` and
  `Control` read a body, sealed with the caller's secret under the MinIO alias
  (`read_compatible_admin_body`, `:128`, `:143`). Read as a whole, the handler would record all
  five routes as buffering a body and holding the caller's secret.

Read with that shape, the inventory gains ten routes and loses two; every other route's facts —
method, template, group, auth mode, action, custom-auth class, handler, sealing and body kinds — and
the eight query-discriminated extension routes are unchanged:

| Route | Change | RustFS |
|---|---|---|
| `GET v3/integrity/readiness` (`admin:ServerInfo`), `GET v3/integrity/{bucket}/inventory` (`admin:InspectData`), `POST v3/integrity/{bucket}/jobs` (`admin:StartBatchJob`), `GET v3/integrity/{bucket}/jobs/{job_id}` (`admin:DescribeBatchJob`), `POST v3/integrity/{bucket}/jobs/{job_id}/control` (`admin:StartBatchJob`) | added, a new registration group `integrity` | rustfs/rustfs#8065; `route_policy.rs:1588-1617` |
| `GET v3/target/{target_type}/{target_name}/subscriptions` (`admin:GetBucketTarget`) | added to `user` | rustfs/rustfs#8001; `route_policy.rs:315-320` |
| `POST {warehouse}/catalog/warehouse-index/backfill` under `/_iceberg/v1` and `/iceberg/v1` (`admin:MigrateTableCatalog`) | added to `table_catalog` | rustfs/rustfs#7677, merged by #7935; `route_policy.rs:1034-1039`, `:1324-1329` |
| `GET v3/metrics` → `GET v3/realtime` (`admin:GetMetrics`) | renamed; RustFS main registers no `v3/metrics` | rustfs/rustfs#8046; `route_policy.rs:323`, `handlers/system.rs:168-172` |
| `POST v3/heal/{bucket}/{prefix}` → `POST v3/heal/{bucket}/{*prefix}` | a catch-all (ADR-0036) | rustfs/rustfs#7653, merged by #7935; `route_policy.rs:355` |

## Decision

**(a) An enum-dispatched handler is read per variant.** The script accepts a registration loop
whose rows are `&Type(Enum::Variant)` and whose insert wraps the row's value in
`AdminOperation(..)`, and records `Type(Enum::Variant)` as the route's handler. It reads that
route's body facts from what the variant reaches: every arm of `match self.0` the variant does not
take, and the branch of each `if matches!(self.0, ..) { .. } else { .. }` it does not take, are left
out. What is left can over-approximate what the variant runs, never leave any of it out. Any other
use of `self.0` — bound to a name, inside a larger condition, a guarded pattern, an `else if`,
handed to a function of another file — is refused, as is a loop row of any other shape. So the
three integrity reads record no body and no secret, and only `Create` and `Control` opt in to the
caller's secret (ADR-0024 (d), ADR-0027 (d)).

**(b) A registration group the inventory gains is placed at the order whose rule its routes
need, by a reviewed edit of the plan.** The generator keeps refusing an unplaced group.
`integrity` goes to order 5: four of its five routes carry `{bucket}`, which ADR-0030 (a) binds as
the operation's bucket — a tightening, as for every order-5 route, because RustFS authorises each
of the five admin actions on no bucket (`authorize_admin_request`, `integrity.rs:93`) — and
`{job_id}` is service-level (ADR-0027 (a)).

**(c) A route RustFS removes is removed with its operation; a renamed route is a new operation.**
`rustfs:GetV3Metrics` is removed and `rustfs:GetV3Realtime` added. No alias is kept for the old
path: RustFS main answers it with nothing, and a row RustFS does not register is a route the
gateway would serve alone.

**(d) A route whose template changes keeps the operation its name derives.** The heal catch-all is
still `rustfs:PostV3HealByBucketByPrefix` (a `{*name}` spells `By` and its words, like `{name}`);
its rows now use ADR-0036's catch-all, so it matches every prefix RustFS matches, one byte or more,
separators included. The generator refuses an overlap involving a catch-all, for which it has no
ordering rule; RustFS's three heal routes have none.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- RustFS was read at `3268c42e00b375859b4535d53fe219b02d7bfe31`; the file and line references
  are in Context. The script's `--check` against that commit exits 0, and against `736e4fb8` the
  extended script still writes the previously recorded inventory byte for byte, so no fact of an
  existing route moved because the script changed.
- The script, measured by `python3 scripts/test_rustfs_admin_route_inventory.py`: RustFS's
  integrity shape yields five sites with their variants and each variant's facts; the whole
  handler read as one would not; a `_` arm is taken only by a variant no earlier arm took; a plain
  loop is unchanged; and thirteen shapes are refused.
- The generator, measured by `cargo test -p xtask -- rustfs_admin_dialect`: the drift check, the
  recorded plan's groups and orders, its caller-secret opt-ins by name, the catch-all's name and
  template, and the refusal of a catch-all that is a bucket or overlaps another route.
- The dialect, measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin`, and the service,
  measured by `cargo test -p rustfs-gateway-goldens --lib -- rustfs_admin_dialect`: every row routes
  and is asked about exactly its bucket or none; the new routes; the heal catch-all over several
  segments, and none for an empty prefix.
- Every assertion added here has a mutation that turns it red. The PR lists each one.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Record the integrity routes' facts from the whole handler | Three reads would buffer a body and hold the caller's secret, which RustFS never does for them. |
| A hand-written fact table for enum-dispatched routes | The inventory must be regenerated, not edited; a table beside the script is a second authority that drifts. |
| Keep `rustfs:GetV3Metrics` as an alias of `realtime` | RustFS main registers no `v3/metrics`; the gateway would serve a route RustFS does not have. |
| A new order for groups added after ADR-0032 | The order says which rule a group's routes need, and `integrity` needs exactly order 5's. |
| Leave the heal catch-all with RustFS (`STAYING`) until later | A deployment would have to keep a router in front of the gateway for one route; ADR-0036 serves it. |

## Consequences

- **BREAKING**: `rustfs-gateway-dialect-rustfs-admin` 0.8.0. `rustfs:GetV3Metrics` is removed;
  `rustfs:GetV3Realtime`, `rustfs:GetV3TargetByTargetTypeByTargetNameSubscriptions`,
  `rustfs:PostIcebergByWarehouseCatalogWarehouseIndexBackfill` and five `rustfs:…V3Integrity…`
  operations are new; `rustfs:PostV3HealByBucketByPrefix` matches every prefix of one byte or more.
- **RustFS's handlers**, when they register against the dialect: the integrity handler reads the
  bucket from `RequestContextView::bucket()` and `job_id` from `path_params()`; the heal handler
  reads `prefix` from `path_params()` decoded once and must not decode it again (ADR-0036); a
  deployment that registered `GetV3Metrics` registers `GetV3Realtime`.
- **Enforcement:** the script's refusals and its test; the generator's refusal of an unplaced group
  and of a catch-all overlap; the drift check; the tests listed under Evidence.
