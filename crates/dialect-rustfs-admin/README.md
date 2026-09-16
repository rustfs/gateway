# rustfs-gateway-dialect-rustfs-admin

RustFS's admin API as gateway dialect operations (rustfs/backlog#1744, ADR-0024 to ADR-0030).

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

A `{bucket}` template parameter is the bucket the operation is authorised on
(`BucketParam::Path`, ADR-0025 (c), ADR-0030): the raw segment meets the S3 bucket-name rules
before authentication, the authorizer is asked about that bucket, and the handler reads it from
`RequestContextView::bucket()`. The two compat quota routes (`get-bucket-quota`,
`set-bucket-quota`) name their bucket in the `bucket` query parameter, read exactly once
(`BucketParam::Query`, ADR-0026 (e)). Every other template parameter (`{tiername}`, `{key_id}`,
`{prefix}`, …) names no bucket: the operation stays service-level, and its handler reads the
decoded value from `RequestContextView::path_params()` (ADR-0027). Where a literal segment meets
another route's parameter (`POST tier/clear` and `POST tier/{tiername}`), the literal's operation
declares that it stands in front, as RustFS's router decides. `POST heal/` keeps the trailing `/`
RustFS registers it with, and matches exactly that path (ADR-0030).

An operation that acts on an account says whose (ADR-0025, ADR-0026, ADR-0028), and the facade
reads it once, before authentication:

- **The caller's own** (`account/*`, `mfa/challenge`, `accountinfo`): the request cannot name
  another account, and the action is the operation's own `rustfs:` label, because RustFS makes no
  IAM check there. The authorizer is still asked.
- **One account named in the query** (`accessKey`, `user` or `userDN`): an absent account is the
  caller or a `400`, as RustFS answers it. The handler reads `RequestContextView::subject()` and
  never the query.
- **A set** (`list-access-keys-bulk` and its LDAP and OpenID variants): each `users` account is
  asked about, and `all=true` also needs `admin:ListUsers`. The handler reads
  `RequestContextView::subjects()`. A signed request cannot repeat `users` today (ADR-0026 (d)),
  so naming several accounts fails closed.

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
cargo xtask rustfs-admin-dialect          # writes src/ops/*.rs, src/table.rs and src/table/*.rs
cargo xtask rustfs-admin-dialect --check  # fails when a generated file is stale
```
