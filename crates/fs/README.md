# `rustfs-gateway-fs`

`rustfs-gateway-fs` is the inspectable filesystem reference backend for `rustfs-gateway`. It exists
to prove that the public `Handler` and `ServiceBuilder` APIs are sufficient to assemble a real S3
service without a private adapter.

This bounded implementation supports bucket and version-aware object CRUD plus `ListObjects` and
`ListObjectsV2`, `ListMultipartUploads`, `GetBucketLocation`,
`GetBucketVersioning`, `PutBucketVersioning`, `ListObjectVersions`, `CreateMultipartUpload`,
`UploadPart`, `ListParts`, `CompleteMultipartUpload`, `AbortMultipartUpload`, and lifecycle
configuration PUT/GET/DELETE plus object tagging GET/PUT/DELETE.
`FsBackend::supported_operations`, `FsBackend::register_crud`, and
`FsBackend::register_multipart`, `FsBackend::register_versioning`, and
`FsBackend::register_listing`, `FsBackend::register_lifecycle`, and `FsBackend::register_tagging`
consume one crate-local operation list so the advertised set and the production registry cannot
drift independently.

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

Object tags are atomically replaced beside the selected version record. Current and explicit-version
reads, idempotent deletion, and restart recovery all use that authority without minting a new version
or changing object bytes. The same validated tag pairs drive lifecycle `Tag` and `And` filters.

Multipart state remains separate from published objects. Completion validates a strictly ordered,
duplicate-free part list, retires the upload capability, and publishes the assembled bytes through
the version authority. Negotiated multipart checksums persist with the upload, require matching
composite part claims, validate completion claims, and report either a composite checksum or the
assembled full-object CRC. Abort retires the capability before removing its parts.

Lifecycle configuration is one atomically replaced bucket record encoded with the historical
persistence XML codec. Complete standard rules, the transition minimum-size header, deletion, and
restart recovery share that authority; malformed or symbolic-link records fail closed. A one-shot
expiration sweep preflights every bucket before applying enabled day/date rules to current objects.
The optional lifecycle scheduler repeats that same fail-closed sweep with a joined shutdown handle
and reports successful, failed, and object-expiration counts. The debug interval maps both one
lifecycle day and one sweep cadence to a short duration for conformance; tag-filtered rules match
the persisted object-version tags. A separate one-shot transition sweep applies enabled
day/date actions to current objects, honors the persisted minimum-size mode, and atomically records
the selected storage class without changing bytes, identity, tags, or modification time. GET, HEAD,
and both object and version listing views project that durable class after restart.

The backend serves one region, `us-east-1` unless `FsBackend::with_region` names another. That one
value is the `x-amz-bucket-region` a `HeadBucket` reports, the `LocationConstraint` a
`GetBucketLocation` answers — the empty element for `us-east-1`, whose constraint AWS defines as
null — and the only constraint a `CreateBucket` may name. A region the `LocationConstraint`
enumeration cannot name is refused by `with_region` rather than at request time.

Ranged reads resolve through the exported `evaluate_range` contract, so a suffix range, a window
that runs past the end, an unsatisfiable range, a multi-range header and `If-Range` all behave as
they do everywhere else in this workspace rather than being re-derived here.

The backend is intentionally not production storage. It does not promise crash consistency,
multi-process coordination, hostile concurrent filesystem mutation resistance, or lifecycle
transition scheduling or physical storage tiers. Bucket names never become raw path components and
object keys never become paths; symbolic-link roots and storage components are refused.

The remaining capabilities belong to later slices of rustfs/backlog#1741 rather than this core
reference-backend slice.
