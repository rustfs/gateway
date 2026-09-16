# ADR-0031: The table catalog's two surfaces as claims and alias rows, `{warehouse}` bound, and first-divergence shadowing

- Status: Accepted
- Date: 2026-09-16
- Trigger: axiom A4, because which prefixes a dialect owns, which of two spellings of a route is the operation, and which route a crossed overlap reaches are decided per dialect and per route pair, not per handler. Also a crate boundary: `rustfs-gateway-dialect-rustfs-admin` installs two more path-prefix claims and declares 49 operations whose alias rows are inventory routes of their own; the generator's shadowing rule widens.
- Supersedes / Superseded by: none

## Context

This ADR extends ADR-0024 to ADR-0030 and leaves their text unchanged. ADR-0024's migration plan
already names order 6's needs: "claims at `/iceberg/v1` and `/_iceberg/v1`, templates, one
declaration for each `buckets/{warehouse}` pair", and "the same bucket binding, for `{warehouse}`".
ADR-0030 (a) gave `{warehouse}` the binding. What was still open is how the two surfaces relate,
what the operations are called, and how a crossed overlap is ordered.

rustfs/backlog#1744 generates the `rustfs` dialect from the recorded inventory
(`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`, RustFS `736e4fb8`). Orders 1
to 5 landed in rustfs/gateway#801, #805, #819 and #823: 243 operations on 486 rows.

Order 6 is one registration group, `table_catalog`, and 98 routes: the Iceberg REST catalog. The
inventory records them as 49 pairs, `surface: table-catalog` under `/_iceberg/v1` and
`surface: table-catalog-compat` under `/iceberg/v1`, each pair identical in method, template,
parameters, action, handler, body kinds and secret, and none with a `minio_admin_alias`. All 98
are `sigv4-admin`; none is custom-auth or query-discriminated. 48 pairs carry `{warehouse}`, 44 of
them with further parameters (`namespace`, `table`, `view`, `job`, `ref`); the two `GET v1/config`
routes carry none. Five pairs hand their body on unread (`handed-on`). Raising the migrated order
to 6, the generator refused the first route it met ("not under `/rustfs/admin/`").

What RustFS does was read at `736e4fb8`:

- **Both prefixes are admin paths.** `is_admin_path` accepts `/_iceberg/v1/config` and
  `TABLE_CATALOG_PREFIX/config` (`rustfs/src/admin/router.rs:3566-3571`), and
  `register_table_catalog_route` registers every route twice
  (`route_registration_test.rs:439-440`, `:636-637`; `route_policy.rs:1002-1040`, `:1281-1344`).
  So a path-style bucket named `iceberg` already loses its `v1/…` keys on RustFS; `_iceberg` is no
  legal bucket name.
- **RustFS routes with `matchit`**, whose trie tries a static child before a parameter child at
  each segment. For `GET /iceberg/v1/buckets/{warehouse}` against
  `GET /iceberg/v1/{warehouse}/namespaces`, the request `/iceberg/v1/buckets/namespaces` takes the
  static `buckets` child at the third segment and matches there, so the `buckets/{warehouse}` route
  wins. The generator's rule from ADR-0027 (b) refused this pair as one "no literal orders": each
  side has a literal the other meets with a parameter.
- **The table catalog authorises on the warehouse, and mostly on a finer object path.**
  `authorize_table_catalog_resource_request` calls the IAM check with
  `AdminResourceScope::bucket_object(warehouse, object_path)`, where the object path is the
  namespace, table or view (`handlers/table_catalog/mod.rs:1134-1162`). Three handlers authorise on
  no bucket: `GetCatalogConfigHandler`, `MaterializeTableCatalogMigrationHandler` and
  `CancelTableCatalogMigrationHandler` (`authorize_table_catalog_request`, `mod.rs:1061-1073`;
  `config.rs`). `GetCatalogConfigHandler` reads an optional `?warehouse=` from the query
  (`warehouse_from_config_query`, `mod.rs:1896`).
- **A `handed-on` body** is read by the catalog engine, not by the handler: RustFS passes the
  request body on without buffering it.

## Decision

**(a) Two more claims.** The dialect claims `/_iceberg/v1` and `/iceberg/v1`, each two segments
deep as ADR-0024 (a) requires, with the same router evidence as the admin claims. A request inside
either is answered by a claimed row or by the claim's `501`. A path-style bucket named `iceberg`
loses its `v1/…` keys, exactly as on RustFS; nothing else about that bucket changes, and no bucket
can be named `_iceberg`.

**(b) The compat surface is the alias row.** A `/iceberg/v1/…` route is declared as no operation of
its own: it is the alias row of the `/_iceberg/v1/…` operation, as `/minio/admin/…` is of
`/rustfs/admin/…` (ADR-0024 (c)). The generator knows two surfaces, each a canonical prefix, a
compat prefix, a name tag and where the alias comes from: the admin API's alias comes from the
route's own `minio_admin_alias` flag; the table catalog's comes from a second inventory row. The
generator finds that twin — same method, group, template parameters, query discriminators, auth
mode, action, custom class, handler, secret class and body kinds, and no MinIO flag — and refuses a
canonical route without one, a twin that differs in any of those facts, and a compat row whose
canonical route the inventory does not record. So the dialect declares 49 operations on 98 rows,
and the pending census counts the 98 inventory routes they cover.

**(c) Names carry the surface.** A table-catalog operation is named `Method`, `Iceberg`, then the
path words after `/_iceberg/v1/`: `rustfs:GetIcebergConfig`, `rustfs:PutIcebergBucketsByWarehouse`,
`rustfs:PostIcebergByWarehouseNamespacesByNamespaceTablesByTable`. Admin operations keep their
names; the tag is empty for that surface.

**(d) A crossed overlap is ordered by its first divergence.** ADR-0027 (b) stands where it
applied; where two same-length rows of one method each have a literal the other meets with a
parameter, the first position at which one side is a literal and the other a parameter decides,
and the literal wins, as `matchit` decides it. The winner must still come first in inventory order,
so it has the lower precedence, and the overlap is declared with a `ShadowingDecl` as before; a
crossed pair whose first divergence favours the later route is refused, and so is a pair no
literal orders. In the recorded inventory this adds exactly one declaration:
`rustfs:GetIcebergBucketsByWarehouse` stands in front of `rustfs:GetIcebergByWarehouseNamespaces`
(`buckets` before `{warehouse}`), on both rows.

**(e) `{warehouse}` is the bucket; the finer object path stays with RustFS's `Authorizer`.** Under
ADR-0030 (a), every route carrying `{warehouse}` binds `BucketParam::Path("warehouse")` and
declares `ResourceShape::Bucket`: 48 operations, 96 rows. The gateway hands both `Authorizer`
stages, the governor, the audit event and the handler the warehouse as the bucket and no key; the
namespace, table and view are decoded path parameters in `RequestContextView::path_params()`, and
the object-path refinement RustFS applies today (`bucket_object(warehouse, namespace/…)`) is the
`Authorizer`'s to keep, from those parameters. For the two `catalog/migration` write routes, which
RustFS authorises on no bucket, the binding is a tightening of the kind ADR-0030 (a) records. The
two `config` routes stay service-level: their optional `?warehouse=` is not a binding (an absent
query bucket is refused by ADR-0026 (e), and RustFS answers without one), so the handler reads it,
as on RustFS.

**(f) A `handed-on` body is the live stream.** The generated codec's input is `ByteStream` with
`RequestBodyMode::Streaming`, the same as a streamed body: the gateway neither buffers nor reads
what RustFS hands on.

## Evidence

- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, measured.
- The route counts come from a `python3` pass over the inventory's `table_catalog` rows, measured:
  98 routes in 49 pairs, 48 pairs with `{warehouse}`, 5 pairs `handed-on`, 2 routes with no
  parameter, no custom-auth or query-discriminated route.
- The RustFS semantics were read at `736e4fb8e8e5d527c25e4e56f352536b311b6daf`. The file and
  line references are in Context.
- The generator, measured by `cargo test -p xtask -- rustfs_admin_dialect`: the drift check over
  297 files; names for both surfaces; a compat row declared as its canonical route's alias and
  refused when the twin is missing, differs, or has no canonical route; the crossed pair ordered by
  its first divergence, and refused when that favours the later route; the recorded plan's 49
  table-catalog operations with their aliases, 48 `{warehouse}` bindings, the one shadowing, and
  292 operations with four pending groups.
- The dialect, measured by `cargo test -p rustfs-gateway-dialect-rustfs-admin`: 584 rows route;
  177 parameters across 92 templates refuse a dot segment, a separator and nothing; four claims
  assemble; the two declared shadowings; every claimed entry carries its record's binding, 65 by
  template and 2 by query; the census by group with `table_catalog` at 49 and 18 routes pending.
- The proof, measured by `cargo test -p rustfs-gateway-goldens --lib rustfs_admin_dialect`: every
  one of the 584 rows is asked about its bound bucket or none and hands its handler the same; every
  compat row is exactly one operation's alias and no operation; 130 template rows refuse seven
  invalid bucket names before the `Authorizer`; a denial names the bucket on all 134 bound rows;
  the 576 presignable rows are refused at the floor.
- Every assertion added here has a mutation that turns it red. The PR lists each mutation.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Declare the 98 routes as 98 operations, one per surface | Two operations per handler, identical but for a prefix, doubles the generated surface for nothing a reviewer can use, and gives RustFS two names to register one handler under. The compat prefix is what `/minio/admin` already is: a second spelling. |
| Derive the compat alias from a flag, as for `/minio/admin` | The inventory records the compat routes as rows, not as a flag, and a row can differ from its twin. Pairing rows keeps the inventory the authority and refuses a divergence. |
| Bind `{warehouse}` and the object path (`namespace/table`) as bucket and key | A claimed route binds one bucket (ADR-0025 (c)); a key would need a second binding and an S3 key's rules, and the object path is RustFS's own resource spelling, not a key. The parameters reach the `Authorizer` decoded; the refinement is its to make. |
| Bind the `config` routes' optional `?warehouse=` | A query binding refuses an absent parameter (ADR-0026 (e)); RustFS answers `config` without one. |
| Keep ADR-0027 (b) as written and refuse the crossed pair | The pair is RustFS's, ordered by `matchit`; refusing it would leave `buckets/{warehouse}` unmigrated with no fact against it. |

## Consequences

- **BREAKING**: `rustfs-gateway-dialect-rustfs-admin` 0.6.0. Installing the dialect now claims
  `/_iceberg/v1` and `/iceberg/v1`; `CLAIMS` has four entries. No type changes. `rustfs-gateway-core`
  is unchanged.
- **Enforcement:** the tests listed under Evidence; the claim rules of ADR-0024 (a); the
  generator's twin refusals; the overlay cross-check against `render_claimed_route`.
- **RustFS's handlers**, when they register against this dialect, read the warehouse from
  `RequestContextView::bucket()` and the namespace, table, view, job and ref from
  `RequestContextView::path_params()`, and register one handler per operation under its
  `rustfs:…Iceberg…` name for both spellings.
- **ADR-0024's migration plan:** order 6 is resolved. Still open: order 7 (`oidc`, `sts`,
  `object_zip_download`) and order 8 (`health`), as already listed.
