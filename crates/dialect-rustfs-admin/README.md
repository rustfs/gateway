# rustfs-gateway-dialect-rustfs-admin

RustFS's admin API and Iceberg REST table catalog as gateway dialect operations (rustfs/backlog#1744, ADR-0024 to ADR-0032).

RustFS consumes this crate: it installs the dialect and registers its own handlers. Nothing here
depends on RustFS. Backend handlers live in RustFS; this crate supplies only the two fixed
authenticated fallback handlers (ADR-0039).

- `rustfs_admin_dialect()`: the `/rustfs/admin`, `/minio/admin`, `/_iceberg/v1`, `/iceberg/v1`,
  `/profile/cpu` and `/profile/memory` path-prefix claims and one claimed operation per migrated
  route, each with its MinIO alias row or, for the table catalog, its `/iceberg/v1` compat row
  (ADR-0031); the two profiling triggers have no alias (ADR-0032).
- One type per operation under `ops`, generated from the recorded route inventory
  (`crates/goldens/src/migration_inventory/rustfs_admin_routes.json`) by
  `cargo xtask rustfs-admin-dialect`. Each carries its name, rows, action, specification, floor
  and codec. An input is `()` when RustFS reads no body, the raw bytes when it buffers an opaque
  JSON or binary body, and the live stream when it streams one. Every output is an
  `AdminResponse`; the two synthetic fallbacks use `()` and their fixed handlers.
- `ROUTES` records the inventory facts each operation was generated from, `PENDING` lists the
  registration groups that are not migrated yet (none today), and `STAYING` lists the four
  `/health` routes the gateway deliberately does not serve, each with its reason: a deployment
  keeps routing those itself (ADR-0032).
- `EXTENSION_ROUTES` records RustFS's eight S3-shaped extension routes (rustfs/backlog#2753):
  `PUT /{bucket}?replication-reset`, `GET /{bucket}?replication-reset-status`,
  `?replication-metrics=2` and `?replication-metrics` (two operations, as RustFS splits them),
  `?replication-check`, `GET /{bucket}/{key}?lambdaArn=…`, and `?events=…` on the service and on a
  bucket. RustFS's router claims each by method, target and that one query discriminator before
  its S3 service reads anything else, so no path-prefix claim can take them: each is an S3-table
  row (`ExtensionOperation::ROUTE`, declared with `DialectBuilder::declare`) placed ahead of every
  standard row of its method and target, and every one of those overlaps is declared, computed
  from the generated route table. Under legacy RustFS's selection (`Selection::RustfsLegacy`) the
  same discriminators name the same operations, ahead of `x-id` and every operation key. Each is
  authorised by the inventory's IAM action on the bucket or object the path names, reads no body,
  and is walked by `fold_every_extension`. The two notification listeners are long-lived streams:
  a handler answers `AdminResponse::stream`.
- The object-zip-download pair (`POST object-zip-downloads`, `GET object-zip-downloads/{id}.zip`)
  is claimed like every other admin route (rustfs/backlog#2753). Both floors are privileged, under
  the caller's own vendor labels `rustfs:CreateObjectZipDownload` and `rustfs:DownloadObjectZip`;
  RustFS's handler keeps its own per-resource S3 checks on the minting body. The download's
  `{id}.zip` segment is one opaque `{+id}` capture (ADR-0040): the handler reads `id` as the whole
  segment, suffix included, and validates it against the token. A minted download URL presented
  with its `?token=` and no header signature is `403` here: ADR-0026 (g) refused admitting the
  route anonymously, and the bearer scheme it points to is not built yet.

Every operation is privileged and header-signed only: never anonymous, never presigned, and never
handed the caller's secret unless its inventory row says RustFS seals a body with it. The one
exception is RustFS's four OIDC bootstrap routes (`oidc/authorize/{provider_id}`,
`oidc/callback/{provider_id}`, `oidc/logout`, `oidc/providers`), which admit an anonymous request:
the floor's per-operation opt-in lists them in the start-up posture report, their action is their
own `rustfs:` label, and the authorizer is still asked, with no identity (ADR-0026 (f), ADR-0032).

A `{bucket}` or `{warehouse}` template parameter is the bucket the operation is authorised on
(`BucketParam::Path`, ADR-0025 (c), ADR-0030): the raw segment meets the S3 bucket-name rules
before authentication, the authorizer is asked about that bucket, and the handler reads it from
`RequestContextView::bucket()`. The two compat quota routes (`get-bucket-quota`,
`set-bucket-quota`) name their bucket in the `bucket` query parameter, read exactly once
(`BucketParam::Query`, ADR-0026 (e)). Every other template parameter (`{tiername}`, `{key_id}`,
`{prefix}`, …) names no bucket: the operation stays service-level, and its handler reads the
decoded value from `RequestContextView::path_params()` (ADR-0027). Where a literal segment meets
another route's parameter (`POST tier/clear` and `POST tier/{tiername}`; `GET buckets/{warehouse}`
and `GET {warehouse}/namespaces`), the literal's operation declares that it stands in front, as
RustFS's router decides (ADR-0027, ADR-0031). `POST heal/` keeps the trailing `/`
RustFS registers it with, and matches exactly that path (ADR-0030).

Admin and table-catalog route declarations spell native single-segment captures as `{+name}`
(ADR-0040). They match one nonempty raw segment and decode it once as UTF-8 data, including
encoded separators, dot segments and controls. Handlers validate the meaning of that data; bucket
bindings still validate the raw bucket name. `ROUTES` retains the original inventory spelling, and
`{*prefix}` remains a trailing catch-all.

After registered rows, the dialect declares `AdminV4Fallback` and `AdminFallback`. Both require
a header signature and caller-only authorization at both stages, without a secret or bucket.
The v4 prefix returns empty 426; other unmatched admin paths return 501 `NotImplemented`.
A registered operation's denial or error is never retried through a fallback. Literal prefixes
matter: `/v40` and an encoded spelling of `/v4` do not select the downgrade.

These two synthetic operations have no native inventory record and are outside
`fold_every_operation`. Register their fixed handlers separately, including when using that
fold for the backend operations. For native body ordering, the deployment must select the
existing RustFS bodyless policy as shown below. Its CORS layer remains responsible for the
legacy `OPTIONS` answer before routing.
Select `SigV4Authenticator::verify_paths_as_legacy_rustfs` for native percent and encoded-slash
signature spelling; the router still receives the original target. Add
`verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES)` so the table catalog verifies the path
Iceberg clients sign, the wire spelling encoded once more, as RustFS does since rustfs/rustfs#8291.
Table-catalog parameters, like admin ones, capture one raw segment (ADR-0040): a namespace whose
levels are joined by `%1F` reaches its handler, which validates what the value means. A handler
that decides by the spelling as sent, as RustFS's `namespace_from_path_value` does by looking for
`.`, reads the raw segment (`PathTemplate::raw_value` over the request's raw path), not the decoded
one.

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
    .accept_mismatched_payload_digests_without_a_body()
    .leave_bodies_of_bodyless_operations_unread()
    .register::<ops::admin_v4_fallback::AdminV4Fallback, _>(Arc::new(ops::admin_v4_fallback::AdminV4Fallback))
    .register::<ops::admin_fallback::AdminFallback, _>(Arc::new(ops::admin_fallback::AdminFallback))
    .register::<ops::get_v3_info::GetV3Info, _>(Arc::clone(&admin))
    // ... one `register` per operation, or `fold_every_operation` with a generic handler.
    .require(&OperationSet::of([ops::admin_v4_fallback::NAME, ops::admin_fallback::NAME]))?
    .build()?;
```

Migration from 0.8: add both fixed-handler registrations, permit their caller-only vendor actions
in the authorizer where appropriate, and validate opaque admin ids in backend handlers. A
missing fallback handler is rejected by this explicit `require` check. Without that check,
unregistered operations retain the framework's pre-authentication 501; that deployment does
not provide this compatibility. No native inventory record is added or removed.

Migration from 0.10: table-catalog handlers now receive every nonempty raw segment their
parameters capture, `/`, `..` and controls included once decoded, where 0.10 refused them before
authentication; validate them as RustFS's catalog does. Install
`verify_paths_double_encoded_under(TABLE_CATALOG_PREFIXES)` so Iceberg clients authenticate.

Regenerate after the inventory or generator changes:

```text
cargo xtask rustfs-admin-dialect          # writes src/ops/*.rs, src/table.rs and src/table/*.rs
cargo xtask rustfs-admin-dialect --check  # fails when a generated file is stale
```
