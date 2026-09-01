# `rustfs-gateway-fs`

`rustfs-gateway-fs` is the inspectable filesystem reference backend for `rustfs-gateway`. It exists
to prove that the public `Handler` and `ServiceBuilder` APIs are sufficient to assemble a real S3
service without a private adapter.

This bounded implementation supports bucket and version-aware object CRUD plus `ListObjects` and
`ListObjectsV2`, `ListMultipartUploads`,
`GetBucketVersioning`, `PutBucketVersioning`, `ListObjectVersions`, `CreateMultipartUpload`,
`UploadPart`, `ListParts`, `CompleteMultipartUpload`, and `AbortMultipartUpload`.
`FsBackend::supported_operations`, `FsBackend::register_crud`, and
`FsBackend::register_multipart`, `FsBackend::register_versioning`, and
`FsBackend::register_listing` consume one crate-local operation list so the advertised set and the
production registry cannot drift independently.

Both object listings derive their current-object view from the persisted version records, order keys
by their exact UTF-8 bytes, and roll delimiter groups into page-counted common prefixes. V1 markers
and V2 scoped opaque continuation tokens resume within that same ordering. Prefix, start-after,
maximum page size, URL encoding, and restart recovery all use that one persisted ordering.

Upload initiation records the opaque upload id and initiation time beside the existing bucket/key
capability record. Upload listing validates and enumerates that same persisted authority, orders by
the exact `(key, upload-id)` byte pair, rolls delimiter groups into page-counted common prefixes,
and resumes with the required key/upload-id marker pair after restart. Abort and completion retire
the authority before it can appear in a later page.

Version records use opaque identifiers from a persistent monotonic sequence. Enabled buckets retain
every object version and publish delete markers; suspended buckets replace only the `null` version.
Explicit version reads and deletes remain available, and a deterministic version census orders each
key's records newest first. Ordinary PUT and completed multipart uploads publish through that same
authority, so composite multipart entity tags and version identities remain stable after restart.
Persisted status, counters, records, and bodies fail closed when malformed or replaced by symbolic
links.

Multipart state remains separate from published objects. Completion validates a strictly ordered,
duplicate-free part list, retires the upload capability, and publishes the assembled bytes through
the version authority. Abort retires the capability before removing its parts.

The backend is intentionally not production storage. It does not promise crash consistency,
multi-process coordination, hostile concurrent filesystem mutation resistance, S3 minimum-part
size enforcement, multipart checksum negotiation, or lifecycle processing. Bucket names never
become raw path components and object keys never become paths; symbolic-link roots and storage
components are refused.

The remaining capabilities belong to later slices of rustfs/backlog#1741 rather than this core
reference-backend slice.
