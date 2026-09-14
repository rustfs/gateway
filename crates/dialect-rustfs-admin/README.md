# rustfs-gateway-dialect-rustfs-admin

RustFS's admin API as gateway dialect operations (rustfs/backlog#1744, ADR-0024 to ADR-0027).

RustFS consumes this crate: it installs the dialect and registers its own handlers. Nothing here
depends on RustFS, and no handler lives here.

- `rustfs_admin_dialect()`: the `/rustfs/admin` and `/minio/admin` path-prefix claims and one
  claimed operation per migrated route, each with its MinIO alias row.
- One type per operation under `ops`, generated from the recorded route inventory
  (`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`) by
  `cargo xtask rustfs-admin-dialect`. Each carries its name, rows, action, specification, floor
  and codec. An input is `()` when RustFS reads no body, the raw bytes when it buffers an opaque
  JSON or binary body, and the live stream when it streams one. Every output is an
  `AdminResponse`.
- `ROUTES` records the inventory facts each operation was generated from, and `PENDING` lists the
  registration groups that are not migrated yet, with their route counts.

Every operation is privileged and header-signed only: never anonymous, never presigned, and never
handed the caller's secret unless its inventory row says RustFS seals a body with it.

A template parameter (`{tiername}`, `{key_id}`, …) names no bucket: the operation stays
service-level, and its handler reads the decoded value from `RequestContextView::path_params()`
(ADR-0027). Where a literal segment meets another route's parameter (`POST tier/clear` and
`POST tier/{tiername}`), the literal's operation declares that it stands in front, as RustFS's
router decides.

```rust,ignore
let dialect = rustfs_admin_dialect().expect("the generated record and declarations agree");
let service = ServiceBuilder::new()
    .dialect(&dialect)
    .register::<ops::get_v3_info::GetV3Info, _>(Arc::clone(&admin))
    // ... one `register` per operation, or `fold_every_operation` with a generic handler.
    .build()?;
```

Regenerate after the inventory changes:

```text
cargo xtask rustfs-admin-dialect          # writes src/ops/*.rs and src/table.rs
cargo xtask rustfs-admin-dialect --check  # fails when a generated file is stale
```
