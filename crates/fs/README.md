# `rustfs-gateway-fs`

`rustfs-gateway-fs` is the inspectable filesystem reference backend for `rustfs-gateway`. It exists
to prove that the public `Handler` and `ServiceBuilder` APIs are sufficient to assemble a real S3
service without a private adapter.

This bounded implementation supports bucket and version-aware object CRUD, `ListBuckets`,
`DeleteObjects`, browser `POST` Object uploads, `CopyObject`, plus `ListObjects` and
`ListObjectsV2`, `ListMultipartUploads`, `GetBucketLocation`,
`GetBucketVersioning`, `PutBucketVersioning`, `ListObjectVersions`, `CreateMultipartUpload`,
`UploadPart`, `UploadPartCopy`, `ListParts`, `CompleteMultipartUpload`, `AbortMultipartUpload`, and lifecycle
configuration PUT/GET/DELETE plus object and bucket tagging GET/PUT/DELETE, and bucket CORS PUT/GET/DELETE with a `CorsSource`
that feeds the gateway's CORS answers. Default-encryption
configuration PUT/GET/DELETE is stored and reported as RustFS answers it, and nothing is
encrypted: this backend measures the protocol surface, not key management. Object writes record
the SSE-S3 or SSE-KMS algorithm (and KMS key id) the request names, or the bucket default, and the
write, `GET` and `HEAD` report it, again without encrypting a byte.
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

User metadata is persisted in the version record itself. A record is the same eight newline-terminated
lines earlier builds wrote, and an object carrying `x-amz-meta-*` adds a named, versioned trailing
section — `meta/1 <count>` followed by one hex-encoded key/value line per entry. An object with no
optional sections is written in the exact pre-section form and stays readable by a build that
predates the section, while a record that does carry metadata is refused by that older reader rather
than silently read as an object with none. In the other direction this build reads a pre-section
record and answers it with no metadata; a section it does not recognise, one that declares more
entries than it holds, one whose entry could not be returned as a header, and one that repeats a key
are each refused with their own diagnosis instead of quietly reading as metadata-less. `GET` and
`HEAD` answer the stored map on both the current and an explicit version, and a lifecycle transition
rewrites the record without dropping it. Multipart takes the metadata from `CreateMultipartUpload`,
where S3 defines it, persists it in the upload record, and publishes it at completion; the
completion's own headers change nothing. Keys are stored in the lowercase form the codec already
produced and refused rather than normalised a second time, values are stored RFC 2047-decoded and
re-encoded on the way out, and the combined key and value size is capped at 2 KB — the figure AWS
documents for user metadata — measured against the stored form.

The standard representation headers a write carries — `Content-Type`, `Content-Encoding`,
`Content-Disposition`, `Content-Language`, `Cache-Control`, and `Expires` — are stored with the
version in a second optional trailing section, `headers/1 <count>`, and answered by `GET` and `HEAD`
on the current and on an explicit version. An object stored with no `Content-Type` answers
`binary/octet-stream`, the model's default, which is therefore not stored; an object carrying none
of the optional sections keeps the eight-line record form. Multipart takes them from
`CreateMultipartUpload`, `CopyObject` copies them under `COPY` and rebuilds them from the request
under `REPLACE`, and a browser `POST` stores the media type the form pipeline hands over.

A verified `PutObject` checksum, supplied in a header or trailer, is stored in a final optional
`checksum/1 1` section followed by `<algorithm> <base64 value>`. `GET` and `HEAD` return it when
`ChecksumMode=ENABLED` and no range was requested. A plain overwrite stores no checksum.
`CopyObject` keeps the source checksum unless its `ChecksumAlgorithm` requests a recalculation.
Earlier records remain readable without a checksum, but older builds refuse the new section;
keep a pre-upgrade data copy for rollback instead of deleting checksums from new records.
Completed multipart uploads store their checksum and explicit type in `checksum/2 1`, followed
by `<algorithm> <type> <value>`. The type and any composite suffix must agree. Checksum-enabled
whole-object reads and completion retries report both after restart. Default COPY preserves a
composite checksum's type; copying a FULL_OBJECT checksum or requesting recalculation omits the
type, as RustFS does. Readers that only understand `checksum/1` refuse these typed records, so
rollback still needs a pre-upgrade data copy.

`GetObjectAttributes` reports only the requested ETag, size, storage class and checksum groups,
using the current or explicitly selected persisted version. Last-modified and version headers
follow that same representation. A requested checksum with no stored value is an empty group;
plain objects omit ObjectParts. New multipart records report original part numbers, sizes and
individual checksums with up to 1000 parts per page. A marker selects higher original numbers,
including when the marker itself is absent. Native RustFS instead restarts such a page; this
remains an explicit difference. Older records without original identities return `NotImplemented`
for ObjectParts. Unknown groups select no fields, as native RustFS
does. The existing reader keeps its `NoSuchVersion` response for absent explicit versions, while
native RustFS rejects malformed version IDs as `InvalidArgument`. Stored multipart checksum types
are reported here as on GET/HEAD.

New multipart completions also store `parts/1 <count>` followed by each completed part's length.
The table must agree with the object size and multipart ETag. GET partNumber uses the shared core
resolver to serve that ordinal byte window and reports the multipart part count; ordinary objects
have one readable part without a multipart count. A part read omits whole-object checksums.
Older multipart records without the table remain readable whole and return `NotImplemented` for
part reads. Readers without parts/1 support reject new tables, so the rollback rule also applies
here. HEAD partNumber returns 200 with the selected length and multipart count, omitting
Content-Range; malformed numbers are 400 and an unavailable ordinal part is 416, as the core
part-table contract specifies. GET retains RustFS's 400 InvalidPart for that unavailable part.
Native RustFS currently returns the whole length without PartsCount on HEAD and 500 for an
unavailable part; these remain explicit compatibility differences.
New completions append `part-meta/1 <count>` after `parts/1`, with one row containing the original
part number, checksum algorithm and checksum value (`- -` when no checksum was negotiated).
Numbers must increase within 1..10000, counts must match the length table, and each individual
checksum must match the object's algorithm without a composite suffix. This preserves sparse
numbers and verified per-part values for the part-list reader. Version rewrites preserve the
section; ordinary PUT, POST and COPY replacements clear it. Old records remain readable without
invented identities or checksums. Old readers reject this section, so rollback needs a pre-upgrade
data copy. GET part checksums remain unavailable.

Native sparse numbering has a known discrepancy: after completing uploaded numbers 2 and 5, its
GET number 5 returns the whole object. This backend refuses that unavailable ordinal part.

A `PutObject` also stores the tag set its `x-amz-tagging` header carries, validated as the
`?tagging` subresource's document is and written into the new version's directory before the
version becomes visible, and the storage class its `x-amz-storage-class` names. `CopyObject`
records the class the request names, `STANDARD` when it names none, copies the source's tags
under the default tagging directive and takes the request's under `REPLACE`; a self copy that only
names a class is a change. A class a record cannot carry is refused as `InvalidStorageClass`
before anything is written. `CreateMultipartUpload` carries its `x-amz-tagging` tags to the completed object; it does not yet
carry its class.

`ListBuckets` answers every bucket under the single-tenant data root in byte order, with the
configured owner, a prefix filter, a region filter, and `max-buckets` pages resumed by a minted
opaque cursor. `DeleteObjects` runs every authorized key through the same single-key deletion
`DeleteObject` uses and reports each key exactly once, as deleted or as an error; quiet mode reports
only the errors. A browser `POST` Object upload is stored through the same publication as
`PutObject`, with its `x-amz-meta-*` form fields.

`CopyObject` resolves its source only through the framework's derived-resource authorization proof.
It selects current or explicit-version bytes before opening the destination, applies the shared
copy-source conditional contract before publication, inherits metadata for `COPY`, rebuilds it from
the request for `REPLACE` (including an empty map), and refuses a self copy that changes nothing.
The result reports the source and destination version identities independently.

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
It also expires eligible noncurrent versions and orphan delete markers, preserving retained history
and legacy objects. Historical removals do not change the returned current-object expiration count.
The optional lifecycle scheduler repeats that same fail-closed sweep with a joined shutdown handle
and reports successful, failed, and object-expiration counts. The debug interval maps both one
lifecycle day and one sweep cadence to a short duration for conformance; tag-filtered rules match
the persisted object-version tags. A separate one-shot transition sweep applies enabled
day/date actions to current objects, honors the persisted minimum-size mode, and atomically records
the selected storage class without changing bytes, identity, tags, or modification time. GET, HEAD,
and both object and version listing views project that durable class after restart.

`PutObject`, `HeadObject` and `GetObject` of a current version answer `x-amz-expiration` as AWS and
legacy RustFS do: the enabled rule selecting the object that is due first, its `Date`, or its `Days`
after the write rounded up to the next UTC midnight in real days whatever the debug interval, with
the rule's id. A copy or completion response, and a noncurrent version, answer none.

The backend serves one region, `us-east-1` unless `FsBackend::with_region` names another. That one
value is the `x-amz-bucket-region` a `HeadBucket` reports, the `LocationConstraint` a
`GetBucketLocation` answers — the empty element for `us-east-1`, whose constraint AWS defines as
null — and the only constraint a `CreateBucket` may name. A region the `LocationConstraint`
enumeration cannot name is refused by `with_region` rather than at request time.

The backend reports no listing owner unless `FsBackend::with_owner` configures the one owner of its
single-tenant data root. ListObjects V1 and ListObjectVersions then report that owner on every object
or version entry, including delete markers; ListObjectsV2 reports it only when `fetch-owner=true`.
The XML response encoder escapes the configured id and display name when it writes them to the wire.
ListObjectVersions resumes after a `key-marker` and, within that key, after a `version-id-marker`;
a `version-id-marker` sent without a key marker is refused with `InvalidArgument` rather than
answered with the first page.

A deployment standing this backend in for RustFS — the RustFS-profile launcher, `compat/sut` — asks
for legacy RustFS's answers by name, and each one is off by default: `FsBackend::refusing_batch_deletes_of`
answers the keys RustFS's storage refuses on their own in a batch delete, and
`FsBackend::evaluating_delete_if_match` judges `If-Match` on `DeleteObject` as legacy RustFS does —
the object's own tag or `*` deletes, anything else is `412` and deletes nothing, and a versioned
bucket's key that holds no version is marked without being judged — and `FsBackend::sorting_object_tags`
answers an object's tag set in its keys' byte order while the stored document keeps the written one,
`FsBackend::normalizing_completed_parts` keeps the last entry a completion names for each part
number, as legacy RustFS does, before the list is judged, and `FsBackend::normalizing_content_encoding`
stores a write's `Content-Encoding` without its `aws-chunked` members, as legacy RustFS stores it.

Ranged reads resolve through the exported `evaluate_range` contract, so a suffix range, a window
that runs past the end, an unsatisfiable range, a multi-range header and `If-Range` all behave as
they do everywhere else in this workspace rather than being re-derived here.

The backend is intentionally not production storage. It does not promise crash consistency,
multi-process coordination, hostile concurrent filesystem mutation resistance, or lifecycle
transition scheduling or physical storage tiers. Bucket names never become raw path components and
object keys never become paths; symbolic-link roots and storage components are refused.

The remaining capabilities belong to later slices of rustfs/backlog#1741 rather than this core
reference-backend slice.
