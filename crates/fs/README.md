# `rustfs-gateway-fs`

`rustfs-gateway-fs` is the inspectable filesystem reference backend for `rustfs-gateway`. It exists
to prove that the public `Handler` and `ServiceBuilder` APIs are sufficient to assemble a real S3
service without a private adapter.

This bounded implementation supports bucket and object CRUD plus `CreateMultipartUpload`,
`UploadPart`, `ListParts`, `CompleteMultipartUpload`, and `AbortMultipartUpload`.
`FsBackend::supported_operations`, `FsBackend::register_crud`, and
`FsBackend::register_multipart` consume one crate-local operation list so the advertised set and
the production registry cannot drift independently.

Multipart state remains separate from published objects. Completion validates a strictly ordered,
duplicate-free part list, builds the result under a temporary name, retires the upload capability,
and publishes the object with one rename. Abort retires the capability before removing its parts.

The backend is intentionally not production storage. It does not promise crash consistency,
multi-process coordination, hostile concurrent filesystem mutation resistance, S3 minimum-part
size enforcement, multipart checksum negotiation, versioning, lifecycle processing, or object and
upload listing. Bucket names never become raw path components and object keys never become paths;
symbolic-link roots and storage components are refused.

The remaining capabilities belong to later slices of rustfs/backlog#1741 rather than this core
reference-backend slice.
