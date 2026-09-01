# `rustfs-gateway-fs`

`rustfs-gateway-fs` is the inspectable filesystem reference backend for `rustfs-gateway`. It exists
to prove that the public `Handler` and `ServiceBuilder` APIs are sufficient to assemble a real S3
service without a private adapter.

This bounded implementation supports `CreateBucket`, `HeadBucket`, `DeleteBucket`, `PutObject`,
`GetObject`, `HeadObject`, and `DeleteObject`. `FsBackend::supported_operations` and
`FsBackend::register_crud` are generated from one crate-local operation list so the advertised set
and the production registry cannot drift independently.

The backend is intentionally not production storage. It does not promise crash consistency,
multi-process coordination, hostile concurrent filesystem mutation resistance, multipart uploads,
versioning, lifecycle processing, or listing. Bucket names never become raw path components and
object keys never become paths; symbolic-link roots and storage components are refused.

The remaining capabilities belong to later slices of rustfs/backlog#1741 rather than this core CRUD
slice.
