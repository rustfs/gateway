# ADR-0033: MinIO's bucket-configuration members are part of every assembly's HTTP codec

- Status: Accepted
- Date: 2026-09-29
- Trigger: axiom A4, because a vendor element becomes part of the dialect-neutral request and response codec instead of an `ExtField` a deployment selects (ADR-0007, ADR-0018, `docs/dialects.md` dimension 2).
- Supersedes / Superseded by: none

## Context

Legacy RustFS builds its S3 layer with MinIO support, so six MinIO members of bucket-configuration
XML reach the RustFS body: `ExpiryUpdatedAt` (lifecycle document), `DelMarkerExpiration` (lifecycle
rule), `ExpiredObjectAllVersions` (lifecycle expiration), `DeleteReplication` (replication rule),
and `ExcludedPrefixes` / `ExcludeFolders` (versioning). The gateway skipped them, so a write that
RustFS applies was answered `200` and installed without them (rustfs/backlog#1752).

`docs/dialects.md` places a vendor child element in dimension 2, selected per deployment through an
`ExtField` vtable. No generated HTTP codec has an extension slot today; the vtable exists only on
the persisted-XML path.

## Decision

The six members are synthesized into the model through `model/overlays/**` and decoded, validated
and re-encoded by every assembly, unconditionally. There is no per-deployment opt-in.

The gateway replaces the legacy stack as RustFS's S3 HTTP layer and serves no other product, and
nothing is deployed yet, so matching legacy RustFS exactly outranks keeping these members out of assemblies
that would not use them. The per-deployment opt-in once tracked in rustfs/gateway#1063 is
therefore not planned.

The decision covers exactly these six members, because legacy RustFS accepts and applies them.
Every other vendor or future element keeps dimension 3's lenient skip (`c-lifecycle-0018`'s
`FutureKnob`), and a new member joins this list only with its own `rd-` ruling showing that legacy
RustFS accepts it.

The members must round-trip losslessly through the generated legacy seam in both directions, so a
rollback to the legacy stack, or a client's read-modify-write through the gateway, never loses one.
A value the seam cannot carry is refused with a typed conversion error, never dropped.

## Evidence

- RustFS main applies the members: `DelMarkerExpiration` and `ExpiredObjectAllVersions` in the
  lifecycle evaluator (https://github.com/rustfs/rustfs/blob/1e7065101d7de4ebacabd249db5b4debbf5baa68/crates/lifecycle/src/core.rs#L219-L273,
  https://github.com/rustfs/rustfs/blob/1e7065101d7de4ebacabd249db5b4debbf5baa68/crates/lifecycle/src/core.rs#L593), `DeleteReplication` in the replication rules
  (https://github.com/rustfs/rustfs/blob/1e7065101d7de4ebacabd249db5b4debbf5baa68/crates/replication/src/config.rs#L248), and `ExcludedPrefixes` / `ExcludeFolders` in the
  versioning check (https://github.com/rustfs/rustfs/blob/1e7065101d7de4ebacabd249db5b4debbf5baa68/crates/ecstore/src/bucket/versioning/mod.rs#L42-L80). It replaces a client's
  `ExpiryUpdatedAt` with its own stamp before it stores the document
  (https://github.com/rustfs/rustfs/blob/1e7065101d7de4ebacabd249db5b4debbf5baa68/rustfs/src/app/bucket_usecase.rs#L2383-L2396).
- A local legacy RustFS run (staging `gateway/integration` at 7f98de76f, `RUSTFS_S3_STACK=legacy`)
  answered `200` to a lifecycle rule carrying `DelMarkerExpiration` and `ExpiredObjectAllVersions`
  and returned both on `GetBucketLifecycleConfiguration`, and answered `200` to a versioning
  document carrying `ExcludedPrefixes` and `ExcludeFolders`.
- `crates/goldens/src/operation_diff/minio_config.rs`, measured by `cargo test -p
  rustfs-gateway-goldens`: for each member the RustFS body receives the same configuration through
  the gateway as through the pinned legacy stack, a document without the members is handed over
  alike, and a malformed value is refused by both stacks (rulings rd-cfg-0002 to rd-cfg-0006).
- The read half, in the same file: a lifecycle or replication configuration RustFS stored with the
  members, answered through the seam and the gateway's encoder and written back, hands RustFS
  exactly the rules it stored, and one stored without them gains none. Legacy RustFS answers
  `GetBucketVersioning` without the two versioning members and `GetBucketLifecycleConfiguration`
  without `ExpiryUpdatedAt` (the pinned legacy stack has no such output members), so the gateway
  reads carry none either.
- The persistence bridge (`crates/types/src/persistence/dto_bridge*`) carries every member from the
  persisted document to the DTO and back to the same parsed document.
- `c-lifecycle-0018`, `c-lifecycle-0040`, `c-replication-0037` and `c-bucketconfig-0062`, measured
  by `cargo test -p rustfs-gateway-conformance`; the guard mutations on `c-lifecycle-0018` are
  listed in the PR that introduced this record.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Gate the members per deployment (dimension 2 in production: a `dialect` mark in the overlay and IR, a decoder that reads them only when the assembly selects MinIO XML extensions) | A protected IR change plus codec-emitter work for a selection only RustFS would ever make; the gateway serves no other product, and nothing is deployed. |
| Keep skipping the members | RustFS applies them; a write answered `200` and installed without them silently changes lifecycle, replication and versioning behaviour. |
| Accept every vendor element globally | The compatibility rule is legacy RustFS, not MinIO: legacy RustFS refuses an element it does not know, so carrying one would store configuration it never had. |

## Consequences

- `c-lifecycle-0018` and `crates/core/tests/lifecycle_roundtrip.rs` now assert that
  `DelMarkerExpiration` survives a re-encode; an unknown sibling is still skipped.
- A malformed value of any of the six members is refused before the handler, as on legacy RustFS
  (`c-lifecycle-0040`, `c-replication-0037`, `c-bucketconfig-0062`).
- Serving a second product that must not accept these members requires a new ADR that moves them
  behind dimension 2; until then, they are ordinary model members.
- Legacy RustFS refuses an unknown element or a repeated singleton element with `400 MalformedXML`,
  where the generic decoder skips the one and keeps the first of the other. That applies to every
  member, these six included, and is rustfs/gateway#1078, not this decision.
