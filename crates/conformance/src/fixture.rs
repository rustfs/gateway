// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The backend a case runs against: the fixtures it declared, and nothing else.
//!
//! Responsible for: holding what `[setup]` established — buckets, objects, multipart uploads and
//! their parts — and answering each registered operation out of that state, so a case measures the
//! *protocol* between the wire and the handler rather than a storage engine's behaviour.
//! NOT responsible for: durability, concurrency, versioning, lifecycle, replication, encryption,
//! or any other S3 semantic a case does not assert. Every one of those is a reason this file would
//! stop being a fixture and start being an implementation.
//! Upstream: `rustfs-gateway`, `crate::md5`. Downstream: `crate::inprocess`.
//!
//! # The line this stub does not cross
//!
//! A conformance stub has exactly one job: make the *observable* half of an exchange a function of
//! the fixtures. So it does the smallest thing that makes an assertion meaningful — resolve a key,
//! apply the `Range` the codec already parsed, evaluate the conditional headers the codec already
//! parsed, assemble the parts a completion names — and refuses everything else in the open. It
//! stores no history, mints no version ids, and has no notion of time beyond the instant the case
//! pinned. When a case fails here, the failure is about the framework or about the case; it is
//! never about a storage decision this file made quietly.
//!
//! # The listing half, and what it is allowed to know
//!
//! Six operations answer with a list — `ListObjects`, `ListObjectsV2`, `ListObjectVersions`,
//! `ListBuckets`, `ListParts`, `ListMultipartUploads` — and every entry they emit is a fixture
//! the case declared. Three consequences follow, and each is a rule this file keeps:
//!
//! * **A version is a `[setup.objects]` entry, never an invention.** In a bucket the case declared
//!   `versioning = "enabled"`, each setup entry for a key becomes one version and each `absent =
//!   true` becomes one delete marker, in the order the case wrote them. In every other bucket a
//!   key has exactly one version, spelled `null`, which is what S3 calls the version of an object
//!   in a bucket that was never versioned. Nothing else mints a version.
//! * **A cursor is opaque and verifiable.** `NextContinuationToken` is the position it resumes
//!   from, hex-encoded and checksummed, so a token that was altered, truncated, extended or made
//!   up is *refused* rather than read as some other position. A verbatim marker would make four
//!   security cases (`c-list-0029` … `c-list-0032`) unable to fail, which is worse than failing.
//! * **`encoding-type` is echoed, never applied.** `spec/operations/*.toml` declares
//!   `url_encoded_fields` for every listing and the generated codec does not act on it, so
//!   percent-encoding a key here would paper over a code-generator gap with backend code that
//!   every other backend would then have to write too. The echo is honest; the encoding is not
//!   this file's to do.
//!
//! An identity is the one thing a listing needs that no fixture declares: `<Owner>` is a required
//! element of a v1 listing and of `ListAllMyBucketsResult`. [`OWNER_ID`] is that identity, fixed
//! and shared, so the value is the same in every run and every golden redacts one thing.
//!
//! # The copy half, and the parser it had to write twice
//!
//! `CopyObject` and `UploadPartCopy` name a *second* object the caller chose, so both go through
//! [`parse_copy_source`], [`confirm_source_owner`] and [`read_copy_source`] — one set of functions,
//! called from both, because the two published advisories on this family were a part copy that
//! authorized the upload it wrote to and never the object it read from.
//!
//! Those three still mirror `crates/core/src/ops/shared/copy_source.rs` rather than calling it,
//! and that is now a debt rather than a necessity: the facade *does* export `CopySource`,
//! `authorize_source` and `classify_self_copy`, so the mirror is a second copy of a rule that has
//! one owner. The copy **range** no longer is — [`resolve_copy_span`] is a call to the contract's
//! `resolve_copy_range`, and the arithmetic and the opinion this file used to hold beside it are
//! gone. The two had drifted apart in exactly the way the shared directory exists to prevent: this
//! file trimmed an overlong span and the contract's doc comment said it refused one.
//!
//! Where a mirror is still here, it is faithful **including where it and the corpus disagree**, and
//! each disagreement is recorded on the function that carries it. A stub that answered what a case
//! wanted rather than what the implementation says would report a green for a gap that is still
//! open, which is the one thing a conformance backend must never do.
//!
//! # The multipart half, and the one thing an upload id is not
//!
//! An upload id is the only handle in S3 that names *state a later request will write into*, and
//! that is what makes it the family's whole security surface. Five operations accept one, and all
//! five go through [`require_upload`], which resolves the id **against the bucket and the key of
//! the request that named it** rather than on its own. s3s#51 is the cost of the other spelling:
//! knowing an id was enough to push a part into a stranger's upload, and the owner completed it
//! without ever learning that somebody else had contributed bytes. `c-mpu-0029` and `c-mpu-0030`
//! are the two halves of that check — a genuine id from another bucket, and a genuine id from
//! another key in the same bucket — and an implementation that scoped by bucket alone would pass
//! the first and fail the second.
//!
//! Completion is the other place where accepting too much is silent. The refusals it makes, in the
//! order it makes them, and each because the alternative is an object nobody can detect is wrong:
//! a part list that is not strictly ascending is `InvalidPartOrder`; a part number that was never
//! uploaded, or one whose claimed digest is not the digest of the bytes on file, is `InvalidPart`;
//! and a non-final part under [`MIN_PART_BYTES`] is `EntityTooSmall`, because the object is the
//! concatenation and a short part in the middle leaves a hole no later read can see. The tag the
//! completion answers is not the digest of those bytes either — it is
//! `ETag::from_part_digests`, the digest of the concatenated part digests with `-N` after it, and
//! a client handed the plain MD5 instead would compare it against the composite and conclude the
//! object is corrupt.
//!
//! Completion is also the operation AWS documents most loudly as committing its head before it
//! knows the outcome, and it does that here: every refusal above is made while a status is still
//! choosable, and [`rustfs_gateway::Resp::commit`] is called only once none is left. The assembly —
//! the concatenation, the composite tag, the part checksums, the write — runs below the boundary,
//! because that is the work that outlasts a client's timeout and the reason the head goes out early.
//!
//! Nothing was moved below the boundary to make a case pass. A refusal below it has no status of its
//! own left to carry, so it would go out as the committed `200`; `c-mpu-0020` … `c-mpu-0023` and
//! `c-mpu-0026` each pin one of those refusals to a `400`, and they would report green while sending
//! the wrong status line. `c-mpu-0001` asks for the opposite answer to the same request and stays
//! red for it — see `MAP.md` finding 15, which names the three cases and what each one now needs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rustfs_gateway::dto;
use rustfs_gateway::{
    BucketName, ByteStream, ChecksumAlgorithm, ChecksumSpec, ConditionalOutcome, CopyRange, CopySourceRejection, CursorSpec,
    ETag, ErrorCode, ErrorDetail, Handler, HandlerError, HandlerResult, IfRange, ObjectKey, ObjectValidators,
    PRECONDITION_FAILED_MESSAGE, PreconditionRejection, Preconditions, RangeDecision, RangeSelectors, Req, RequestKind, Resp,
    TagScope, TaggingRejection, Timestamp, collect, evaluate, evaluate_range, parse_conditional_etag, parse_tagging_header,
    resolve_copy_range, validate_cors, validate_tag_set,
};

/// The canonical user id every listing reports as the owner.
///
/// Fixed rather than random, and shaped like the 64 hex characters AWS uses, so that a golden can
/// redact `<ID>` once and a run compares byte for byte against itself.
pub const OWNER_ID: &str = "3f6e2b1c4a8d90e7b5c31f2a6d80e4c97b1a3d5f8e206c4b7a9d1e3f5c7b9a0d";

/// The display name that accompanies [`OWNER_ID`].
pub const OWNER_DISPLAY_NAME: &str = "conformance";

/// The version id of a key in a bucket that was never versioned. S3's own spelling.
pub const UNVERSIONED: &str = "null";

/// The cursor contract every listing in this fixture reads a client-supplied position through.
///
/// [`CursorSpec::accept`] is the exported rule — the ceiling ([`rustfs_gateway::MAX_CURSOR_BYTES`])
/// and the refusal of a byte that cannot be written back into a response document — and it is a
/// call rather than a second copy for the reason `c-list-0030` exists: a ceiling written twice is a
/// ceiling two implementations can hold at two different values, and this file had it at 2304 while
/// the contract held 2048. Refusing at the ceiling rather than after decoding is the whole point of
/// the case, and the contract is where that ordering is stated.
const CONTINUATION_CURSOR: CursorSpec = CursorSpec::opaque("continuation-token");

/// The smallest a non-final part of a multipart upload may be: 5 MiB, AWS's published floor.
///
/// Checked at completion rather than at upload, which is where S3 checks it and the only place it
/// *can* be checked: whether a part is the last one is not knowable while it is arriving.
const MIN_PART_BYTES: usize = 5 * 1024 * 1024;

/// One object the fixtures established.
///
/// The representation-metadata fields are here because a write sets them and a read must give them
/// back unchanged — that round trip is what several cases assert, and a store that dropped them
/// would fail those cases for a reason that has nothing to do with the framework.
#[derive(Debug, Clone, Default)]
pub struct StoredObject {
    /// The bytes.
    pub body: Vec<u8>,
    /// The declared content type, when the writer named one.
    pub content_type: Option<String>,
    /// `Cache-Control`, as written.
    pub cache_control: Option<String>,
    /// `Content-Disposition`, as written.
    pub content_disposition: Option<String>,
    /// `Content-Encoding`, as written.
    pub content_encoding: Option<String>,
    /// `Content-Language`, as written.
    pub content_language: Option<String>,
    /// `Expires`, as written. Opaque: S3 echoes whatever it was given, valid date or not.
    pub expires: Option<String>,
    /// User metadata.
    pub metadata: BTreeMap<String, String>,
    /// The tag set, in the order the request that wrote it listed the pairs.
    ///
    /// A `Vec` rather than a map, and ordered rather than sorted, because the tag set is what the
    /// writer sent: `x-amz-tagging: a=1&b=2` and a `<Tagging>` document both carry an order, and a
    /// stub that re-sorted them would be answering from a decision of its own. Duplicate keys never
    /// reach here — [`read_tagging_header`] and [`tag_pairs`] refuse them — so the sequence is a
    /// map in everything but lookup cost, and ten pairs is the ceiling AWS documents.
    pub tags: Vec<(String, String)>,
    /// The storage class the writer named, or `STANDARD`.
    pub storage_class: String,
    /// The unquoted MD5 entity tag of `body`.
    pub etag: String,
    /// The instant the case pinned, in Unix seconds.
    pub last_modified: i64,
}

impl StoredObject {
    /// Builds an object and stamps its entity tag.
    #[must_use]
    pub fn new(body: Vec<u8>, content_type: Option<String>, last_modified: i64) -> StoredObject {
        let etag = crate::md5::hex_digest(&body);
        StoredObject {
            body,
            content_type,
            storage_class: "STANDARD".to_owned(),
            etag,
            last_modified,
            ..StoredObject::default()
        }
    }
}

/// One part of a multipart upload.
#[derive(Debug, Clone)]
pub struct StoredPart {
    /// The bytes.
    pub body: Vec<u8>,
    /// The unquoted MD5 entity tag of `body`.
    pub etag: String,
}

/// One multipart upload the fixtures established.
///
/// The `attributes` and `encryption` members are here for a reason the single-request path does not
/// have: the initiating request is the *only* one that carries the object's metadata, its content
/// type, its storage class and its encryption mode, and the object does not exist until the
/// completion arrives. An upload that does not carry them forward has nowhere else to read them
/// from, so they are lost silently and only a later `HeadObject` can tell.
#[derive(Debug, Clone)]
pub struct StoredUpload {
    /// The bucket it belongs to.
    pub bucket: String,
    /// The key it will become.
    pub key: String,
    /// Parts by part number.
    pub parts: BTreeMap<i32, StoredPart>,
    /// The representation metadata the initiating request named, minus the bytes and the tag.
    pub attributes: StoredObject,
    /// The `x-amz-server-side-encryption` the initiating request named, echoed on the completion.
    ///
    /// Stored and echoed, never acted on: this fixture encrypts nothing and says so here so that
    /// nobody reads the header as evidence it did. What the cases measure is whether a value
    /// decided at initiation can still reach a response head that is flushed at completion.
    pub encryption: Option<dto::ServerSideEncryption>,
    /// The `x-amz-checksum-algorithm` the initiating request named, and the `x-amz-checksum-type`
    /// beside it.
    ///
    /// Both are carried for the same reason as [`StoredUpload::encryption`]: the completion reports
    /// them and only the initiation could state them. The *digest* is never carried — it is
    /// recomputed from the part bytes, so nothing here can claim an integrity check that did not
    /// happen.
    pub checksum: Option<UploadChecksum>,
}

/// The checksum contract an upload was opened under.
#[derive(Debug, Clone)]
pub struct UploadChecksum {
    /// The algorithm every part is digested with.
    pub algorithm: ChecksumAlgorithm,
    /// `COMPOSITE` unless the initiation asked for `FULL_OBJECT`.
    pub kind: dto::ChecksumType,
}

impl StoredUpload {
    /// An upload with no parts and no attributes, which is what `setup.multipart_uploads` declares.
    #[must_use]
    pub fn bare(bucket: &str, key: &str) -> StoredUpload {
        StoredUpload {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            parts: BTreeMap::new(),
            attributes: StoredObject {
                storage_class: "STANDARD".to_owned(),
                ..StoredObject::default()
            },
            encryption: None,
            checksum: None,
        }
    }
}

/// One version of one key: what was put there, or the delete marker that hid it.
///
/// A bucket the case never declared versioned holds exactly one of these per key, with
/// [`UNVERSIONED`] as its id — so the versioned and unversioned paths are the same code and there
/// is no second representation to keep in step.
#[derive(Debug, Clone)]
pub struct StoredVersion {
    /// The id this fixture minted, or [`UNVERSIONED`].
    pub version_id: String,
    /// The object, or `None` when this version is a delete marker.
    pub object: Option<StoredObject>,
    /// The instant this version was recorded, in Unix seconds.
    pub last_modified: i64,
}

/// One entry of a version listing, borrowed from the fixture.
#[derive(Debug, Clone, Copy)]
pub struct VersionRef<'a> {
    /// The key it belongs to.
    pub key: &'a str,
    /// The version itself.
    pub version: &'a StoredVersion,
    /// Whether it is the newest version of that key.
    pub is_latest: bool,
}

/// What `[[setup.buckets]]` declared about one bucket, plus the state requests wrote onto it.
///
/// No longer `Copy`: the CORS document and the tag set are fixtures an exchange writes rather
/// than flags `[setup]` declares, and they are held here because they are per-bucket state
/// exactly as the versioning flag is.
#[derive(Debug, Default, Clone)]
struct BucketState {
    /// `versioning = "enabled"`.
    versioned: bool,
    /// `object_lock = true`.
    object_lock: bool,
    /// The stored CORS configuration, written by `PutBucketCors` within the case. `None` is the
    /// observable state `NoSuchCORSConfiguration` reports; there is no "empty document" state,
    /// because the decoder refuses a document with no rule.
    cors: Option<dto::CorsConfiguration>,
    /// The bucket's tag set, in the order the request that wrote it listed the pairs.
    ///
    /// `None` is "never configured, or deleted" and `Some` is "a tagging write happened" — two
    /// states a `Vec` alone cannot hold apart, and the read depends on the difference: an
    /// unconfigured bucket answers `404 NoSuchTagSet` where an object without tags answers `200`.
    /// No `[[setup.buckets]]` field feeds this; a case establishes it through `PutBucketTagging`,
    /// so what the read answers is always something a request wrote.
    tags: Option<Vec<(String, String)>>,
}

/// The state one case runs against.
#[derive(Debug, Default)]
pub struct Fixture {
    buckets: BTreeMap<String, BucketState>,
    objects: BTreeMap<(String, String), Vec<StoredVersion>>,
    uploads: BTreeMap<String, StoredUpload>,
    next_upload: u32,
    next_version: u32,
    /// The instant the case pinned, stamped onto everything this fixture mints.
    pub now: i64,
}

impl Fixture {
    /// An empty fixture whose clock reads `now`.
    #[must_use]
    pub fn at(now: i64) -> Fixture {
        Fixture {
            now,
            ..Fixture::default()
        }
    }

    /// Declares a bucket. `versioned` decides whether a later write appends a version or replaces
    /// the only one there is.
    ///
    /// Object lock is set separately by [`Fixture::set_object_lock`] so that the two declarations
    /// stay independent: `object_lock` without `versioning` is a shape a case may write, and
    /// folding them into one argument would let one silently imply the other.
    pub fn declare_bucket(&mut self, name: &str, versioned: bool) {
        self.buckets.entry(name.to_owned()).or_default().versioned = versioned;
    }

    /// Records `setup.buckets[].object_lock` for a bucket.
    pub fn set_object_lock(&mut self, name: &str, locked: bool) {
        self.buckets.entry(name.to_owned()).or_default().object_lock = locked;
    }

    /// Whether a bucket was declared with object lock on.
    #[must_use]
    pub fn has_object_lock(&self, name: &str) -> bool {
        self.buckets.get(name).is_some_and(|bucket| bucket.object_lock)
    }

    /// Installs a bucket's CORS document, replacing whatever was there. `PutBucketCors` only.
    pub fn set_cors(&mut self, name: &str, configuration: dto::CorsConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().cors = Some(configuration);
    }

    /// The stored CORS document, or `None` for a bucket that never had one.
    #[must_use]
    pub fn cors(&self, name: &str) -> Option<&dto::CorsConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.cors.as_ref())
    }

    /// Removes a bucket's CORS document. Idempotent on purpose: the delete answers `204` whether
    /// or not a document was there, so this reports nothing.
    pub fn clear_cors(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.cors = None;
        }
    }

    /// The bucket's tag set: `None` until a tagging write configures one.
    #[must_use]
    pub fn bucket_tags(&self, name: &str) -> Option<&[(String, String)]> {
        self.buckets.get(name).and_then(|bucket| bucket.tags.as_deref())
    }

    /// Replaces the bucket's tag set. `None` returns the bucket to "never configured", which is
    /// what both the delete and an empty `<TagSet/>` mean — see `Stub::put_bucket_tagging`.
    pub fn set_bucket_tags(&mut self, name: &str, tags: Option<Vec<(String, String)>>) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.tags = tags;
        }
    }

    /// Removes a bucket, for `setup.buckets[].absent`.
    pub fn remove_bucket(&mut self, name: &str) {
        self.buckets.remove(name);
        self.objects.retain(|(bucket, _), _| bucket != name);
    }

    /// Places an object, answering with the version id it was given.
    ///
    /// In a versioned bucket this appends a version and leaves the earlier ones reachable through
    /// [`Fixture::versions_in`]; everywhere else it replaces the single `null` version. Either way
    /// the newest version is what a read sees, which is why `GetObject` needed no change.
    ///
    /// The id comes back because a copy has to report it: `x-amz-version-id` names the version the
    /// copy *wrote*, and a caller that re-read the newest version to find it would be answering
    /// from state rather than from the write it just performed.
    pub fn put_object(&mut self, bucket: &str, key: &str, object: StoredObject) -> String {
        let last_modified = object.last_modified;
        let version = self.mint_version(bucket);
        let versions = self.objects.entry((bucket.to_owned(), key.to_owned())).or_default();
        if version == UNVERSIONED {
            versions.clear();
        }
        versions.push(StoredVersion {
            version_id: version.clone(),
            object: Some(object),
            last_modified,
        });
        version
    }

    /// Removes an object, for `setup.objects[].absent` and for `DeleteObject`.
    ///
    /// A versioned bucket keeps the versions and hides them behind a delete marker, which is what
    /// makes `<DeleteMarker>` and `<IsLatest>false</IsLatest>` observable at all. The id of that
    /// marker comes back so that `DeleteObject` can report it, which is the only way a case can
    /// name one afterwards. An unversioned bucket mints nothing and answers `None`.
    pub fn remove_object(&mut self, bucket: &str, key: &str) -> Option<String> {
        let identity = (bucket.to_owned(), key.to_owned());
        if !self.is_versioned(bucket) {
            self.objects.remove(&identity);
            return None;
        }
        let versions = self.objects.get(&identity)?;
        if versions.is_empty() {
            return None;
        }
        let last_modified = self.now;
        let version_id = self.mint_version(bucket);
        let versions = self.objects.get_mut(&identity)?;
        versions.push(StoredVersion {
            version_id: version_id.clone(),
            object: None,
            last_modified,
        });
        Some(version_id)
    }

    /// Whether a bucket was declared with versioning enabled.
    #[must_use]
    pub fn is_versioned(&self, name: &str) -> bool {
        self.buckets.get(name).is_some_and(|bucket| bucket.versioned)
    }

    /// The id the next version of a key in `bucket` is given.
    fn mint_version(&mut self, bucket: &str) -> String {
        if !self.is_versioned(bucket) {
            return UNVERSIONED.to_owned();
        }
        self.next_version += 1;
        format!("conformance-version-{:04}", self.next_version)
    }

    /// Creates a multipart upload and returns the id it was given.
    ///
    /// Ids are minted from a counter rather than randomly: a case that captures one and redacts it
    /// compares byte for byte, and a random id would make the same run differ from itself.
    pub fn create_upload(&mut self, bucket: &str, key: &str) -> String {
        self.begin_upload(StoredUpload::bare(bucket, key))
    }

    /// Creates a multipart upload that carries the attributes its initiating request named.
    pub fn begin_upload(&mut self, upload: StoredUpload) -> String {
        self.next_upload += 1;
        let id = format!("conformance-upload-{:04}", self.next_upload);
        self.uploads.insert(id.clone(), upload);
        id
    }

    /// The upload an id names, whichever bucket and key it belongs to.
    ///
    /// Every handler goes through [`require_upload`] instead, which is the same lookup plus the
    /// ownership check; this accessor exists for that function and for `setup`.
    #[must_use]
    pub fn upload(&self, upload_id: &str) -> Option<&StoredUpload> {
        self.uploads.get(upload_id)
    }

    /// Places a part in an upload, returning its entity tag. A part for an unknown upload is
    /// dropped, which cannot happen from `setup` and is not worth a second error path.
    pub fn put_part(&mut self, upload_id: &str, part_number: i32, body: Vec<u8>) -> String {
        let etag = crate::md5::hex_digest(&body);
        if let Some(upload) = self.uploads.get_mut(upload_id) {
            upload.parts.insert(
                part_number,
                StoredPart {
                    body,
                    etag: etag.clone(),
                },
            );
        }
        etag
    }

    /// Whether a bucket was declared.
    #[must_use]
    pub fn has_bucket(&self, name: &str) -> bool {
        self.buckets.contains_key(name)
    }

    /// An object, if the newest version of that key is one.
    #[must_use]
    pub fn object(&self, bucket: &str, key: &str) -> Option<&StoredObject> {
        self.objects
            .get(&(bucket.to_owned(), key.to_owned()))
            .and_then(|versions| versions.last())
            .and_then(|version| version.object.as_ref())
    }

    /// The same object, writable — the newest version of that key, if it is an object.
    ///
    /// The tagging operations are the only writers that change an object *in place*: every other
    /// write in this fixture goes through [`Fixture::put_object`], which appends a version. A tag
    /// set is not a representation, so relabelling an object must not mint a version for it — the
    /// version id a tagging write reports is the one the object already had.
    #[must_use]
    pub fn object_mut(&mut self, bucket: &str, key: &str) -> Option<&mut StoredObject> {
        self.objects
            .get_mut(&(bucket.to_owned(), key.to_owned()))
            .and_then(|versions| versions.last_mut())
            .and_then(|version| version.object.as_mut())
    }

    /// One named version of one key, or `None` for an id this fixture never minted.
    ///
    /// The version is answered whether or not it carries an object, because a delete marker and an
    /// id that names nothing are different facts and a copy source has to tell them apart: one is
    /// `MethodNotAllowed` and the other is `NoSuchVersion`.
    #[must_use]
    pub fn version(&self, bucket: &str, key: &str, version_id: &str) -> Option<&StoredVersion> {
        self.objects
            .get(&(bucket.to_owned(), key.to_owned()))?
            .iter()
            .find(|version| version.version_id == version_id)
    }

    /// The id of the newest version of a key, whatever it holds.
    #[must_use]
    pub fn newest_version_id(&self, bucket: &str, key: &str) -> Option<&str> {
        self.objects
            .get(&(bucket.to_owned(), key.to_owned()))?
            .last()
            .map(|version| version.version_id.as_str())
    }

    /// Every live key in a bucket, in the lexicographic order S3 lists in.
    ///
    /// A key whose newest version is a delete marker is not live: `ListObjects` does not see it,
    /// and `ListObjectVersions` does.
    #[must_use]
    pub fn keys_in(&self, bucket: &str) -> Vec<&str> {
        self.objects
            .iter()
            .filter(|((name, _), versions)| name == bucket && versions.last().is_some_and(|version| version.object.is_some()))
            .map(|((_, key), _)| key.as_str())
            .collect()
    }

    /// Every version of every key in a bucket: keys ascending, versions newest first.
    ///
    /// That is S3's own order, and it is the order a key marker plus a version marker resume in.
    #[must_use]
    pub fn versions_in(&self, bucket: &str) -> Vec<VersionRef<'_>> {
        let mut out = Vec::new();
        for ((name, key), versions) in &self.objects {
            if name != bucket {
                continue;
            }
            let newest = versions.len().saturating_sub(1);
            for (index, version) in versions.iter().enumerate().rev() {
                out.push(VersionRef {
                    key: key.as_str(),
                    version,
                    is_latest: index == newest,
                });
            }
        }
        out
    }

    /// Every bucket name, ascending.
    #[must_use]
    pub fn bucket_names(&self) -> Vec<&str> {
        self.buckets.keys().map(String::as_str).collect()
    }
}

/// The backend, over shared fixture state the runner rebuilds for every case.
#[derive(Debug, Clone)]
pub struct Stub {
    state: Arc<Mutex<Fixture>>,
}

impl Stub {
    /// Wraps fixture state.
    #[must_use]
    pub fn new(state: Arc<Mutex<Fixture>>) -> Stub {
        Stub { state }
    }

    /// The state, or an internal error if a previous handler panicked while holding it.
    fn borrow(&self) -> Result<std::sync::MutexGuard<'_, Fixture>, HandlerError> {
        self.state
            .lock()
            .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))
    }
}

/// The owner every listing reports.
fn owner() -> dto::Owner {
    dto::Owner {
        id: Some(OWNER_ID.to_owned()),
        display_name: Some(OWNER_DISPLAY_NAME.to_owned()),
    }
}

/// Mints a continuation token that resumes after `marker`.
///
/// Hex plus eight bytes of a digest over the same value. Opaque, so no client can construct one by
/// reasoning about keys; verifiable, so one that was altered is *known* to be altered rather than
/// read as a different position. Both properties are what `c-list-0029` … `c-list-0032` assert,
/// and a token that was simply the marker in the clear can satisfy neither.
fn mint_token(marker: &str) -> String {
    let digest = crate::sha256::hex_digest(marker.as_bytes());
    format!("{}-{}", encode_hex(marker.as_bytes()), digest.get(..8).unwrap_or_default())
}

/// Reads a token back, or `None` for anything this stub did not mint.
///
/// The ceiling is applied first and it is the contract's, not this file's: a cursor over
/// [`rustfs_gateway::MAX_CURSOR_BYTES`] is refused *before* the hex body is decoded, so the work the
/// ceiling exists to prevent is never done. `c-list-0030` is the case that separates the two
/// orderings, by bounding the response time.
fn read_token(token: &str) -> Option<String> {
    let token = CONTINUATION_CURSOR.accept(token).ok()?;
    let (body, checksum) = token.rsplit_once('-')?;
    let marker = String::from_utf8(decode_hex(body)?).ok()?;
    if crate::sha256::hex_digest(marker.as_bytes()).get(..8)? != checksum {
        return None;
    }
    Some(marker)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    char::from_digit(u32::from(value), 16).unwrap_or('0')
}

/// Standard base64 (RFC 4648 §4), which is the alphabet `Content-MD5` is written in.
///
/// Hand-written here for the same reason the digests are: a foreign implementation running this
/// suite inherits the corpus and nothing else, so the fixture may not reach for a workspace crate
/// the facade does not export.
fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let packed = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (index, byte)| acc | (u32::from(*byte) << (16 - 8 * index)));
        for slot in 0..4 {
            if slot <= chunk.len() {
                let index = ((packed >> (18 - 6 * slot)) & 0x3f) as usize;
                out.push(char::from(ALPHABET[index]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Refuses a body whose `Content-MD5` is not its digest.
///
/// The header is an end-to-end integrity claim, so a store that reads it and does not check it is
/// worse than one that ignores it: the client is told the round trip verified when nothing
/// compared anything. `c-mpu-0044` is the part-upload form; the object form is the same rule and
/// goes through the same function, because a fixture that checked the digest of a part and waved
/// through the digest of a whole object would be asserting a distinction S3 does not make.
///
/// What this does *not* do is separate a malformed header from a mismatched one. AWS answers
/// `InvalidDigest` for a value that is not 16 base64-encoded bytes at all, and no case in the
/// corpus draws that line — so rather than guess at a code nothing asserts, both arrive here as
/// `BadDigest`. A case that wants the distinction will find this comment.
fn require_content_md5(claimed: Option<&str>, body: &[u8]) -> Result<(), HandlerError> {
    let Some(claimed) = claimed.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(());
    };
    if claimed == encode_base64(&crate::md5::digest(body)) {
        return Ok(());
    }
    Err(HandlerError::new(
        ErrorCode::BAD_DIGEST,
        "The Content-MD5 you specified did not match what we received.",
    ))
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = char::from(*pair.first()?).to_digit(16)?;
        let low = char::from(*pair.get(1)?).to_digit(16)?;
        out.push(((high * 16) + low) as u8);
    }
    Some(out)
}

/// `InvalidArgument`, in AWS's own wording for a cursor the service did not issue.
fn bad_token() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, "The continuation token provided is incorrect")
}

/// A delimiter the request supplied, with the empty value read as "no delimiter".
///
/// `?delimiter=` arrives as `Some("")`, and folding on an empty string would put every key under
/// the same common prefix. S3 treats it as absent; `c-list-0039` is the case that says so.
fn delimiter_of(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}

/// Builds one `Contents` entry.
fn object_entry(key: &str, object: &StoredObject, with_owner: bool) -> Result<dto::Object, HandlerError> {
    Ok(dto::Object {
        key: object_key(key)?,
        last_modified: Timestamp::from_secs(object.last_modified),
        e_tag: entity_tag(&object.etag)?,
        size: object.body.len() as i64,
        storage_class: dto::StorageClass::custom(object.storage_class.clone()),
        owner: with_owner.then(owner),
        ..dto::Object::default()
    })
}

fn object_key(key: &str) -> Result<ObjectKey, HandlerError> {
    ObjectKey::new(key.to_owned()).map_err(|_| HandlerError::internal_error("a fixture key is not a valid object key"))
}

fn entity_tag(etag: &str) -> Result<ETag, HandlerError> {
    ETag::new(etag.to_owned()).map_err(|_| HandlerError::internal_error("a fixture entity tag is not a valid entity tag"))
}

/// `NoSuchBucket` unless the fixture declared it.
///
/// The message is AWS's own wording rather than a description of the fixture, because a dozen
/// cases pin the error document byte for byte: a message of this file's choosing would make every
/// one of them differ in the `<Message>` element and hide whatever else was wrong.
fn require_bucket(fixture: &Fixture, bucket: &BucketName) -> Result<(), HandlerError> {
    if fixture.has_bucket(bucket.as_str()) {
        return Ok(());
    }
    Err(HandlerError::new(ErrorCode::NO_SUCH_BUCKET, "The specified bucket does not exist"))
}

/// AWS's own wording for an upload id that names nothing this caller may act on.
///
/// One function rather than five literals: the five multipart operations have to be
/// indistinguishable here, because a caller who can tell "wrong bucket" from "no such id" apart by
/// the `<Message>` element has been told the id is genuine.
fn no_such_upload() -> HandlerError {
    HandlerError::new(
        ErrorCode::NO_SUCH_UPLOAD,
        "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
    )
}

/// Resolves an upload id **against the bucket and the key of the request that named it**.
///
/// An upload id is a bearer token in every implementation that looks it up on its own, and s3s#51
/// is what that costs: knowing an id was enough to push a part into somebody else's upload, and the
/// owner completed it without ever learning that a stranger had contributed bytes. Neither half of
/// the check is optional — `c-mpu-0029` carries a genuine id from another bucket and `c-mpu-0030`
/// carries a genuine id from another key in the *same* bucket, so an implementation that scoped by
/// bucket alone would still pass the first and fail the second.
///
/// The refusal is [`no_such_upload`] rather than an access-denied: an id the caller does not own
/// must not be confirmed to exist.
fn require_upload<'a>(
    fixture: &'a Fixture,
    upload_id: &str,
    bucket: &BucketName,
    key: &ObjectKey,
) -> Result<&'a StoredUpload, HandlerError> {
    match fixture.upload(upload_id) {
        Some(upload) if upload.bucket == bucket.as_str() && upload.key == key.as_str() => Ok(upload),
        _ => Err(no_such_upload()),
    }
}

/// The four conditional headers, read into the shape the exported contract evaluates.
///
/// This backend does not decide anything here. Every rule that used to live in this file — the
/// strong/weak split between the two entity-tag headers, the order the four are evaluated in, the
/// `If-Match` suppression of `If-Modified-Since`, the future-clock exemption — is
/// [`rustfs_gateway::evaluate`]'s, and the only job left is turning wire values into its inputs.
///
/// # Errors
///
/// A value the entity-tag grammar cannot carry is a `400` rather than a silently dropped
/// condition: a guard the server ignores is a compare-and-swap the client believes it made.
fn conditions(
    if_match: Option<&str>,
    if_unmodified_since: Option<i64>,
    if_none_match: Option<&str>,
    if_modified_since: Option<i64>,
    now: i64,
) -> Result<Preconditions, HandlerError> {
    Ok(Preconditions {
        if_match: conditional_tag(if_match)?,
        if_none_match: conditional_tag(if_none_match)?,
        if_modified_since: if_modified_since.map(Timestamp::from_secs),
        if_unmodified_since: if_unmodified_since.map(Timestamp::from_secs),
        // The instant the case pinned. Without it the contract cannot apply the rule that ignores
        // an `If-Modified-Since` the server has not itself reached, and a client with a fast clock
        // is told its cached copy is current forever.
        observed_at: Some(Timestamp::from_secs(now)),
    })
}

/// One conditional entity-tag header, read through the contract's own parser.
///
/// Accepts the quoted, weak and bare spellings, and `*`. The RFC 9110 *list* form is refused by
/// [`parse_conditional_etag`] rather than reduced to its first member, so this backend refuses it
/// too instead of answering a question the client did not ask.
fn conditional_tag(value: Option<&str>) -> Result<Option<ETag>, HandlerError> {
    let Some(value) = value else { return Ok(None) };
    parse_conditional_etag(value)
        .map(Some)
        .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "The ETag value provided is not valid."))
}

/// The facts about a representation that a condition is evaluated against.
///
/// `None` is an absent representation rather than an error, because the contract needs to see the
/// absence: `If-Match` against a key that is not there fails the *condition*, and answering `404`
/// before evaluating would report the lookup instead.
fn validators_of(object: Option<&StoredObject>) -> Result<ObjectValidators, HandlerError> {
    match object {
        None => Ok(ObjectValidators::default()),
        Some(object) => Ok(ObjectValidators {
            exists: true,
            etag: Some(entity_tag(&object.etag)?),
            last_modified: Some(Timestamp::from_secs(object.last_modified)),
        }),
    }
}

/// The one range refusal that is a fact about the request head and not about the object.
///
/// `Range` and `partNumber` together are a contradiction in the request itself: the two select
/// overlapping spans by different mechanisms, and no object needs to exist for that to be true. It
/// therefore has to be answered before the key is resolved. Answering `NoSuchKey` first — which is
/// what this fixture did while the check lived inside [`resolve_range`], below the lookup — reports
/// a storage fact to a caller whose request was never going to be served whatever storage held, and
/// tells it to go looking for the wrong bug.
///
/// The rule itself is not restated here. [`evaluate_range`] owns it, and only its refusal is read:
/// for a request carrying at most one selector the contract answers with a decision about bytes,
/// which is a decision this function is deliberately too early to make.
///
/// # Errors
///
/// The contract's own [`PreconditionRejection`], rendered by [`refused`].
fn refuse_conflicting_selectors(range: Option<&str>, part_number: Option<i32>) -> Result<(), HandlerError> {
    let selectors = RangeSelectors {
        range,
        part_number: part_number.map(|number| u32::try_from(number).unwrap_or(0)),
        if_range: None,
    };
    match evaluate_range(&selectors, &ObjectValidators::default(), 0) {
        Ok(_) => Ok(()),
        Err(rejection) => Err(refused(rejection)),
    }
}

/// A conditional request the contract refused as malformed rather than unsatisfied.
///
/// The wording is the contract's own constant. It is never built from request bytes — a message
/// assembled from the value that was rejected is a way to echo it back into a log.
fn refused(rejection: PreconditionRejection) -> HandlerError {
    HandlerError::new(rejection.code().clone(), rejection.reason())
}

/// The destination-side conditional headers, spelled as AWS spells them inside `<Condition>`.
///
/// The canonical mixed case, not the lowercase wire name [`rustfs_gateway::ConditionalHeader`]
/// carries: `<Condition>If-None-Match</Condition>` is what the error document reads, and a client
/// that switches on the element sees `if-none-match` as a value it has no branch for.
const DESTINATION_CONDITIONS: [&str; 4] = ["If-Match", "If-Unmodified-Since", "If-None-Match", "If-Modified-Since"];

/// The copy-source spellings of the same four. Lowercase, because the `x-amz-` headers are.
const COPY_SOURCE_CONDITIONS: [&str; 4] = [
    "x-amz-copy-source-if-match",
    "x-amz-copy-source-if-unmodified-since",
    "x-amz-copy-source-if-none-match",
    "x-amz-copy-source-if-modified-since",
];

/// The header a `412` names, when the request carried exactly one condition.
///
/// # Why only one, and why this is not the evaluation order
///
/// [`ConditionalOutcome::PreconditionFailed`] says *that* a condition was false and not *which*,
/// so the name has to come from somewhere else. The only thing this backend knows for certain is
/// which headers arrived: when exactly one did, it is the one that failed, and that is a fact
/// rather than a deduction. When two or more arrived, naming one means re-deriving RFC 9110
/// §13.2.2's precedence here — a second copy of a rule [`rustfs_gateway::evaluate`] already holds,
/// which is exactly the kind of mirror this file exists to avoid. So the element is omitted
/// instead, and a case that wants it for a multi-condition request stays red until the outcome
/// carries the header it was decided by.
fn sole_condition(names: &[&'static str; 4], present: [bool; 4]) -> Option<&'static str> {
    let mut only = None;
    for (name, present) in names.iter().zip(present) {
        if !present {
            continue;
        }
        if only.is_some() {
            return None;
        }
        only = Some(*name);
    }
    only
}

/// A `412`, worded as AWS words it, naming the condition when [`sole_condition`] could.
///
/// The name goes in `<Condition>` and never into `<Message>`: a message assembled per failure
/// would make the two byte-exact conditional cases differ in the element they are *not* about, and
/// one failure would look like two.
fn precondition(condition: Option<&'static str>) -> HandlerError {
    match condition {
        Some(name) => HandlerError::precondition_failed(name),
        None => HandlerError::new(ErrorCode::PRECONDITION_FAILED, PRECONDITION_FAILED_MESSAGE),
    }
}

/// Evaluates a write's conditions against the representation it would replace.
///
/// Absence is handed to the contract rather than answered first: `If-Match` against a key that is
/// not there fails the *condition*, and a backend that looks the key up before evaluating reports
/// `NoSuchKey` for a client that asked for a conditional overwrite.
fn guard_write(
    object: Option<&StoredObject>,
    if_match: Option<&str>,
    if_none_match: Option<&str>,
    now: i64,
) -> Result<(), HandlerError> {
    let named = sole_condition(&DESTINATION_CONDITIONS, [if_match.is_some(), false, if_none_match.is_some(), false]);
    settle_write(object, &conditions(if_match, None, if_none_match, None, now)?, named)
}

/// The copy-source conditions, evaluated against the source representation.
///
/// A copy is a write however much its source side looks like a read: a failed `If-None-Match` is a
/// `412` and never a `304`, which would tell the client its copy is up to date when no copy was
/// ever made. The four names are spelled the same as the destination's and name a different
/// object, which is why they are evaluated in their own call rather than merged into one — and why
/// the `<Condition>` this reports is the `x-amz-copy-source-` spelling: a client told `If-Match`
/// failed would look at the header it sent for the destination.
fn guard_copy_source(
    found: &StoredObject,
    if_match: Option<&str>,
    if_unmodified_since: Option<i64>,
    if_none_match: Option<&str>,
    if_modified_since: Option<i64>,
    now: i64,
) -> Result<(), HandlerError> {
    let conditions = conditions(if_match, if_unmodified_since, if_none_match, if_modified_since, now)?;
    let named = sole_condition(
        &COPY_SOURCE_CONDITIONS,
        [
            if_match.is_some(),
            if_unmodified_since.is_some(),
            if_none_match.is_some(),
            if_modified_since.is_some(),
        ],
    );
    settle_write(Some(found), &conditions, named)
}

/// Turns the contract's verdict on a write into this backend's answer.
fn settle_write(
    object: Option<&StoredObject>,
    conditions: &Preconditions,
    condition: Option<&'static str>,
) -> Result<(), HandlerError> {
    let validators = validators_of(object)?;
    match evaluate(conditions, &validators, RequestKind::Write).map_err(refused)? {
        ConditionalOutcome::Proceed => Ok(()),
        // A write is never answered `304`, and the contract guarantees it. The arm is spelled out
        // rather than folded into a catch-all so that an outcome added later cannot arrive here as
        // a silent success.
        ConditionalOutcome::NotModified | ConditionalOutcome::PreconditionFailed => Err(precondition(condition)),
        // Named, and unreachable from this fixture: detecting a lost race is the storage layer's
        // job, and a fixture behind one mutex never has two writers in flight to lose one.
        ConditionalOutcome::Conflict => Err(conflict()),
    }
}

/// A `409`, worded as AWS words it.
///
/// Nothing in this fixture produces one. The contract names the outcome and leaves detection to
/// storage, and a fixture that serialises every exchange behind one mutex has no race to lose — so
/// this arm is written to keep the outcome from being silently folded into the `412` it is
/// specifically not, and `c-cond-0013` stays red rather than being answered by a guess.
fn conflict() -> HandlerError {
    HandlerError::new(
        ErrorCode::CONDITIONAL_REQUEST_CONFLICT,
        "The conditional request cannot succeed due to a conflicting operation against this resource.",
    )
}

/// The contract's verdict on a read, with the two refusals already turned into errors.
///
/// Returns the outcome the caller still has to act on — [`ConditionalOutcome::Proceed`] or
/// [`ConditionalOutcome::NotModified`]. The `404` is deliberately *not* raised here: the condition
/// is evaluated against the absence first, so a missing key whose `If-Match` failed is a `412`,
/// and only an unconditional miss is a `NoSuchKey`.
fn guard_read(
    object: Option<&StoredObject>,
    if_match: Option<&str>,
    if_unmodified_since: Option<i64>,
    if_none_match: Option<&str>,
    if_modified_since: Option<i64>,
    now: i64,
) -> Result<ConditionalOutcome, HandlerError> {
    let conditions = conditions(if_match, if_unmodified_since, if_none_match, if_modified_since, now)?;
    let validators = validators_of(object)?;
    let named = sole_condition(
        &DESTINATION_CONDITIONS,
        [
            if_match.is_some(),
            if_unmodified_since.is_some(),
            if_none_match.is_some(),
            if_modified_since.is_some(),
        ],
    );
    match evaluate(&conditions, &validators, RequestKind::Read).map_err(refused)? {
        outcome @ (ConditionalOutcome::Proceed | ConditionalOutcome::NotModified) => Ok(outcome),
        ConditionalOutcome::PreconditionFailed => Err(precondition(named)),
        ConditionalOutcome::Conflict => Err(conflict()),
    }
}

/// `NoSuchKey`, raised only once every condition has been evaluated against the absence.
///
/// The document carries `<Key>`, which is the only element in it that says *which* read missed —
/// a client batching reads on one connection cannot tell two 404s apart without it. The key is the
/// one the request named, so it is an echo to a caller already authenticated and authorised, and
/// the writer escapes it: see `rustfs_gateway`'s renderer.
/// `NoSuchCORSConfiguration`, in AWS's own wording for a bucket that never had a CORS document.
fn no_such_cors_configuration() -> HandlerError {
    HandlerError::new(ErrorCode::NO_SUCH_CORS_CONFIGURATION, "The CORS configuration does not exist")
}

fn no_such_key(key: &str) -> HandlerError {
    HandlerError::new(ErrorCode::NO_SUCH_KEY, "The specified key does not exist.")
        .with_detail(ErrorDetail::Key(key.to_owned().into()))
}

/// A resolved range: the window to send, and the `Content-Range` value that describes it.
#[derive(Debug)]
struct Slice {
    start: usize,
    end_exclusive: usize,
    content_range: Option<String>,
}

impl Slice {
    /// The whole object.
    fn whole(length: usize) -> Slice {
        Slice {
            start: 0,
            end_exclusive: length,
            content_range: None,
        }
    }
}

/// The window a read serves, decided by [`rustfs_gateway::evaluate_range`] and not here.
///
/// This backend decides nothing about ranges. Which selector wins, what an `If-Range` that no
/// longer matches does to the range beside it, where a satisfied window starts and ends, and what
/// `Content-Range` says are all the exported contract's, and the only job left is turning wire
/// values into its inputs and its decision into bytes.
///
/// It could not always be called. `RangeSelectors::range` is the `Range` header *as text*, and
/// until the codec kept the header bytes beside the parse there was no text for a backend to hand
/// it; `if_range` was declared by no dto, so the value never left the wire. Both are reachable now,
/// which is what let the hand-rolled window arithmetic this function replaced be deleted rather
/// than kept beside the contract disagreeing with it.
///
/// # Errors
///
/// `Range` and `partNumber` together are the contract's own refusal, passed through. A `partNumber`
/// on its own selects a part of a completed multipart object, and this fixture has no part table
/// for one — `[setup]` in schema version 1 can only declare an upload that is still in progress —
/// so it is refused by name rather than answered as though the selector had not been sent.
fn resolve_range(
    range: Option<&str>,
    if_range: Option<&IfRange>,
    part_number: Option<i32>,
    object: &StoredObject,
) -> Result<Slice, HandlerError> {
    let length = object.body.len();
    let validators = validators_of(Some(object))?;
    let selectors = RangeSelectors {
        range,
        // The presence of the selector survives a value the contract's type cannot hold: a
        // `partNumber` this backend cannot read is still a `partNumber` the client sent, and
        // dropping it would silently un-refuse the `Range`-and-`partNumber` combination.
        part_number: part_number.map(|number| u32::try_from(number).unwrap_or(0)),
        if_range,
    };
    let decision = evaluate_range(&selectors, &validators, length as u64).map_err(refused)?;
    let content_range = decision.content_range();
    match decision {
        RangeDecision::Whole => Ok(Slice::whole(length)),
        RangeDecision::Partial {
            start, end_inclusive, ..
        } => {
            let start = usize::try_from(start).unwrap_or(length).min(length);
            let end_exclusive = usize::try_from(end_inclusive).unwrap_or(length).saturating_add(1).min(length);
            Ok(Slice {
                start,
                end_exclusive,
                content_range,
            })
        }
        RangeDecision::Part { .. } => Err(HandlerError::not_implemented(
            "this conformance fixture stores no part table for a completed multipart object, so a \
             partNumber selector cannot be resolved to the bytes it names",
        )),
        RangeDecision::Unsatisfiable {
            actual_object_size,
            range_requested,
        } => Err(HandlerError::unsatisfiable_range(range_requested, actual_object_size)),
    }
}

/// The `x-amz-checksum-crc32` a read reports, and the two reasons it reports none.
///
/// * **The client has to ask.** S3 emits the digest only for `x-amz-checksum-mode: ENABLED`, so a
///   backend that volunteered it would put a header on every read that no case asked for.
/// * **The read has to be whole.** A checksum describes the bytes it travels with. A `206`
///   carrying the *object's* digest fails verification in every SDK that checks one, and the client
///   then reports data corruption — which sends an operator to look at storage rather than at a
///   header. `c-range-0016` is both halves of this, in two exchanges on one connection.
///
/// CRC-32 because it is the one algorithm this suite can compute: the facade exports
/// [`ChecksumSpec`] but not the `Checksummer` trait behind `ChecksumAlgorithm::checksummer`, so
/// `src/crc32.rs` is this suite's own, and every other backend outside the workspace will write
/// one too. The digest is of the bytes `[setup]` declared and of nothing else.
fn read_checksum(mode: Option<&dto::ChecksumMode>, partial: bool, whole: &[u8]) -> Option<String> {
    if partial || mode != Some(&dto::ChecksumMode::ENABLED) {
        return None;
    }
    ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &crate::crc32::digest(whole))
        .ok()
        .map(|spec| spec.render_base64().to_owned())
}

/// The storage class a read reports, which S3 omits for the default class.
fn storage_class_header(object: &StoredObject) -> Option<dto::StorageClass> {
    if object.storage_class == "STANDARD" {
        return None;
    }
    Some(dto::StorageClass::custom(object.storage_class.clone()))
}

/// The tag count an object read reports, which S3 omits when it would be zero.
///
/// `None` for an untagged object rather than `Some(0)`: readers use the header's *presence* to
/// decide whether a `GetObjectTagging` round trip is worth making, so a zero would make every
/// object look labelled. The ceiling makes the cast total — a stored set is at most fifty pairs.
fn tag_count_header(object: &StoredObject) -> Option<i32> {
    i32::try_from(object.tags.len()).ok().filter(|count| *count > 0)
}

/// The checksum contract an initiating request declared, if it declared one.
///
/// An algorithm this suite cannot compute is refused rather than dropped: answering the upload
/// without the digests it asked for would look like success and produce parts no client could
/// verify.
fn upload_checksum(
    algorithm: Option<&dto::ChecksumAlgorithm>,
    kind: Option<&dto::ChecksumType>,
) -> Result<Option<UploadChecksum>, HandlerError> {
    let Some(algorithm) = algorithm else { return Ok(None) };
    let resolved = ChecksumAlgorithm::from_wire_name(algorithm.as_str()).ok_or_else(|| {
        HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "Checksum algorithm provided is unsupported. Please try again with any of the valid types: [CRC32, CRC32C, SHA1, SHA256, CRC64NVME]",
        )
    })?;
    if resolved != ChecksumAlgorithm::Crc32 {
        return Err(HandlerError::not_implemented(
            "this conformance fixture digests parts with CRC32 only; every other algorithm would have to be answered with a digest it did not compute",
        ));
    }
    Ok(Some(UploadChecksum {
        algorithm: resolved,
        kind: kind.cloned().unwrap_or(dto::ChecksumType::COMPOSITE),
    }))
}

/// The `x-amz-checksum-*` value for one run of bytes, under the algorithm the upload declared.
fn checksum_of(checksum: &UploadChecksum, bytes: &[u8]) -> Result<ChecksumSpec, HandlerError> {
    let digest = crate::crc32::digest(bytes);
    ChecksumSpec::from_digest(checksum.algorithm, &digest)
        .map_err(|_| HandlerError::internal_error("a computed digest is not a valid checksum"))
}

/// `x-amz-copy-source`, resolved to the object it names.
///
/// # Why this parser is written again here
///
/// `crates/core/src/ops/shared/copy_source.rs` is this gateway's copy-source contract — the split
/// rule, the two ARN grammars, the self-copy classification and the stricter range rule — and the
/// parser below is still a hand-written mirror of the first two. It no longer has to be: the facade
/// re-exports `CopySource`, `authorize_source` and `classify_self_copy`, so this mirror is a second
/// copy of a rule that has an owner, and a rule two implementations hold separately is a rule they
/// can hold differently. That is the shape of the two advisories the shared module was written to
/// prevent, and replacing this parser with the contract's is the outstanding half of the job the
/// range rule has already had done to it — see [`resolve_copy_span`].
///
/// The mirror is faithful, including where the shared module and the corpus disagree. Those
/// disagreements are recorded on the functions that carry them; none of them is smoothed over here,
/// because a stub that answers what a case wants rather than what the implementation says would
/// report a green for a gap that is still open.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CopySource {
    /// The source bucket, or the access point name standing in for one.
    bucket: BucketName,
    /// The source key, decoded exactly once and never normalised.
    key: ObjectKey,
    /// The version the header named, when it named one.
    version_id: Option<String>,
}

/// `InvalidArgument`, in AWS's own wording, for a copy source this fixture will not read.
///
/// The explanation is a `&'static str` chosen from a fixed set, never assembled from the rejected
/// value: this header carries a bucket name the caller may have no right to learn the existence of,
/// and echoing it into an error document turns a refusal into an oracle.
fn bad_copy_source(reason: &'static str) -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, reason)
}

/// Parses one `x-amz-copy-source` value.
///
/// The order is the point: the optional `?versionId=` suffix is split off the **raw** value at its
/// last `?`, and only then is each half percent-decoded. Decode first and `a%3Fb?versionId=v1`
/// becomes `a?b?versionId=v1`, where no split rule recovers which `?` the client sent.
fn parse_copy_source(raw: &str) -> Result<CopySource, HandlerError> {
    if raw.is_empty() {
        return Err(bad_copy_source("x-amz-copy-source must name a source object"));
    }
    let (path, version_id) = split_source_version(raw)?;
    let (bucket, key) = if path.starts_with("arn:") {
        parse_source_arn(path)?
    } else {
        parse_source_path(path)?
    };
    Ok(CopySource {
        bucket: source_bucket(&bucket)?,
        key: source_key(&key)?,
        version_id,
    })
}

/// Splits the version suffix off the raw value, before anything is decoded.
///
/// The rule is fixed rather than heuristic: the split is at the last `?`, and what follows must be
/// `versionId=<value>`. A suffix that is anything else is refused instead of folded back into the
/// key, because folding it back makes one header mean two things depending on whether the value
/// happens to parse.
fn split_source_version(raw: &str) -> Result<(&str, Option<String>), HandlerError> {
    let Some((path, query)) = raw.rsplit_once('?') else {
        return Ok((raw, None));
    };
    let Some(value) = query.strip_prefix("versionId=") else {
        return Err(bad_copy_source("the only query x-amz-copy-source accepts is versionId"));
    };
    let value = decode_source(value)?;
    if value.is_empty() {
        return Err(bad_copy_source("the versionId of x-amz-copy-source must not be empty"));
    }
    Ok((path, Some(value)))
}

/// Parses `bucket/key`, with or without the leading slash AWS also accepts.
///
/// The two halves are separated on the still-encoded value, so a key containing `%2F` keeps it
/// rather than being cut at a separator the client escaped on purpose.
fn parse_source_path(path: &str) -> Result<(String, String), HandlerError> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some((bucket, key)) = path.split_once('/') else {
        return Err(bad_copy_source("x-amz-copy-source must name a key as well as a bucket"));
    };
    Ok((decode_source(bucket)?, decode_source(key)?))
}

/// Parses the two S3 ARN spellings, and refuses every other ARN.
///
/// An unrecognised ARN is never demoted to a bucket name. `arn:aws:iam::1:user/bob` would otherwise
/// address a bucket literally called `arn:aws:iam::1:user`, and in a deployment where somebody has
/// created one, every unrecognised ARN copy is silently redirected into it.
fn parse_source_arn(path: &str) -> Result<(String, String), HandlerError> {
    // arn : partition : service : region : account : resource…, where the resource half contains
    // colons in neither form, so five splits is the whole grammar.
    let mut parts = path.splitn(6, ':');
    let (Some(_arn), Some(_partition), Some(service), Some(_region), Some(_account), Some(resource)) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(unknown_source_arn());
    };
    match service {
        // An access point is addressed by name; the bucket behind it is the control plane's to
        // resolve, so the name is what stands in for the bucket until then.
        "s3" => {
            let rest = resource.strip_prefix("accesspoint/").ok_or_else(unknown_source_arn)?;
            let (name, key) = rest.split_once("/object/").ok_or_else(unknown_source_arn)?;
            if name.is_empty() {
                return Err(unknown_source_arn());
            }
            Ok((name.to_owned(), decode_source(key)?))
        }
        "s3-outposts" => {
            let rest = resource.strip_prefix("outpost/").ok_or_else(unknown_source_arn)?;
            let (outpost, rest) = rest.split_once("/bucket/").ok_or_else(unknown_source_arn)?;
            let (bucket, key) = rest.split_once("/object/").ok_or_else(unknown_source_arn)?;
            if outpost.is_empty() {
                return Err(unknown_source_arn());
            }
            Ok((bucket.to_owned(), decode_source(key)?))
        }
        _ => Err(unknown_source_arn()),
    }
}

/// The one refusal every unrecognised ARN shares.
fn unknown_source_arn() -> HandlerError {
    bad_copy_source("x-amz-copy-source accepts an access point or Outposts ARN, or a bucket and key")
}

/// Percent-decodes one half of the copy-source header, refusing bytes that are not UTF-8.
///
/// `%XX` is one octet and everything else is itself — a `+` stays a plus sign, because this is a
/// path and not a form. Percent encoding carries octets rather than characters, so a client can
/// spell a source whose decoded bytes are not text; that is a refusal and never a panic.
fn decode_source(value: &str) -> Result<String, HandlerError> {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        let pair = (
            bytes.get(index + 1).and_then(|digit| char::from(*digit).to_digit(16)),
            bytes.get(index + 2).and_then(|digit| char::from(*digit).to_digit(16)),
        );
        if byte == b'%'
            && let (Some(high), Some(low)) = pair
        {
            out.push((((high * 16) + low) & 0xff) as u8);
            index += 3;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8(out).map_err(|_| bad_copy_source("x-amz-copy-source is not valid UTF-8 once decoded"))
}

/// Validates the bucket half of a copy source.
fn source_bucket(name: &str) -> Result<BucketName, HandlerError> {
    BucketName::new(name.to_owned())
        .map_err(|_| bad_copy_source("the bucket named by x-amz-copy-source is not a valid bucket name"))
}

/// Validates the key half. Never normalised: `../` is three ordinary bytes of a key.
fn source_key(key: &str) -> Result<ObjectKey, HandlerError> {
    ObjectKey::new(key.to_owned()).map_err(|_| bad_copy_source("the key named by x-amz-copy-source is not a valid object key"))
}

/// The source-side ownership gate, answered from what `[setup]` declared and nothing else.
///
/// A fixture declares buckets, objects and uploads; it declares no account. So an
/// `x-amz-source-expected-bucket-owner` assertion is one this backend cannot confirm, and an
/// assertion that cannot be confirmed is refused rather than assumed to hold. Letting it pass by
/// default would be the cheaper answer and it is the wrong one: this is the stage GHSA-mx42 and
/// GHSA-wfxj were missing, and a stub that skipped it would answer the two cases written for it
/// with a success and report nothing.
///
/// The destination-side `x-amz-expected-bucket-owner` is deliberately *not* gated the same way. It
/// is carried by half the write operations in the corpus and refusing it here would make this one
/// backend disagree with itself about the same header depending on which operation carried it.
fn confirm_source_owner(expected: Option<&str>) -> Result<(), HandlerError> {
    if expected.is_some() {
        // Names no bucket and no key: a refusal that reports *which* source was denied is an
        // existence oracle over every bucket in the deployment.
        return Err(HandlerError::new(ErrorCode::ACCESS_DENIED, "Access Denied"));
    }
    Ok(())
}

/// Where a copy's metadata — or its tag set — comes from.
///
/// One type for both directives because they are one rule over two field groups. `REPLACE` rebuilds
/// from the request; `COPY`, which is also the answer when the header is absent, takes the source's
/// and discards every `x-amz-meta-*` the request carried. There is no third answer: a merge would
/// produce objects whose metadata no single request asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataFrom {
    /// The source object's.
    Source,
    /// The request's, rebuilt from scratch.
    Request,
}

/// Reads a directive header. An unrecognised spelling is refused rather than read as the default.
fn directive_of(value: Option<&str>, reason: &'static str) -> Result<MetadataFrom, HandlerError> {
    match value {
        None | Some("COPY") => Ok(MetadataFrom::Source),
        Some("REPLACE") => Ok(MetadataFrom::Request),
        Some(_) => Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, reason)),
    }
}

/// Reads the inline `x-amz-tagging` header through the exported tagging contract.
///
/// This is the header `PutObject` and `CopyObject` carry, and it is **not** the `?tagging`
/// subresource: the two travel together in `c-copy-0008`, where the copy writes the tag set through
/// this header and the read-back comes back through `GetObjectTagging`. The parsing and the
/// object-scope validation are both calls into [`rustfs_gateway::parse_tagging_header`] and
/// [`rustfs_gateway::validate_tag_set`] rather than a second copy, for the reason the copy-range
/// mirror was retired: a rule written twice is a rule two implementations hold differently, and
/// this file's copy had already grown its own opinion about which code a duplicate key carries.
///
/// # Errors
///
/// Whatever the contract refuses: `InvalidArgument` in AWS's one sentence for every malformed
/// spelling of the header, `InvalidTag` for an empty key, a ceiling violation, or an illegal
/// character.
fn read_tagging_header(header: Option<&str>) -> Result<Vec<(String, String)>, HandlerError> {
    let pairs = parse_tagging_header(header).map_err(refused_tagging)?;
    validate_tag_set(&pairs, TagScope::Object).map_err(refused_tagging)?;
    Ok(pairs)
}

/// The tagging contract's own refusal, rendered.
///
/// The wording is the contract's constant, never assembled from the header: a tag key is
/// caller-chosen text and has no business inside an error body.
fn refused_tagging(rejection: TaggingRejection) -> HandlerError {
    HandlerError::new(rejection.code().clone(), rejection.reason())
}

/// A tag key, as the type the model gives it.
///
/// The pinned model types `Tag.Key` as `ObjectKey`, so an empty key — which is what `x-amz-tagging:
/// =1` decodes to — has no representation at all. Refusing it on the way in is what keeps the read
/// path total: every pair in a [`StoredObject`] came through here, so rendering one back can only
/// fail on a value this fixture never stored.
///
/// # Errors
///
/// `InvalidTag`, in AWS's own wording, for a key the type will not hold.
fn require_tag_key(key: &str) -> Result<ObjectKey, HandlerError> {
    ObjectKey::new(key).map_err(|_| HandlerError::new(ErrorCode::INVALID_TAG, "The TagKey you have provided is invalid"))
}

/// The stored pairs, rendered as the `<TagSet>` a tagging read answers with.
///
/// # Errors
///
/// `InvalidTag` for a key the model's type cannot hold. Unreachable for anything this fixture
/// stored — both writers go through [`require_tag_key`] — and propagated rather than unwrapped
/// because "unreachable" is a claim about two other functions, not about this one.
fn tag_elements(tags: &[(String, String)]) -> Result<Vec<dto::Tag>, HandlerError> {
    tags.iter()
        .map(|(key, value)| {
            Ok(dto::Tag {
                key: require_tag_key(key)?,
                value: value.clone(),
            })
        })
        .collect()
}

/// The `<Tagging>` document of a tagging write, read into ordered pairs.
///
/// The twin of [`read_tagging_header`] over the XML spelling, and deliberately the same validator:
/// count ceiling, length ceilings, character set and the duplicate-key refusal are all
/// [`rustfs_gateway::validate_tag_set`] under the scope the caller names, so the two channels
/// cannot drift apart on any of them.
///
/// # Errors
///
/// `InvalidTag` for every semantic violation. Everything structural — a wrong root, a missing
/// `<Key>` — was already refused by the generated decoder before this ran.
fn tag_pairs(document: &dto::Tagging, scope: TagScope) -> Result<Vec<(String, String)>, HandlerError> {
    let pairs: Vec<(String, String)> = document
        .tag_set
        .iter()
        .map(|tag| (tag.key.as_str().to_owned(), tag.value.clone()))
        .collect();
    validate_tag_set(&pairs, scope).map_err(refused_tagging)?;
    Ok(pairs)
}

/// Refuses `?versionId` on a tagging request rather than answering the current version's tag set.
///
/// This fixture keeps one tag set per key, on its newest version, because no case declares a tag
/// set per version — `[setup.objects]` has no field for one, and inventing per-version labels is
/// exactly the kind of state a conformance stub must not hold. So the honest answer to a request
/// that names a version is that this backend does not serve it. Silently ignoring the parameter
/// would report the *current* labels as the named version's, and a case asserting on that would go
/// green against a wrong answer.
///
/// # Errors
///
/// `NotImplemented` whenever the parameter is present, with a value or without. The message is
/// AWS's own constant for the code — it says "header" where this one is a query key, and it is
/// still the sentence AWS sends, so it is reproduced rather than improved on.
fn refuse_versioned_tagging(version_id: Option<&str>) -> Result<(), HandlerError> {
    if version_id.is_none() {
        return Ok(());
    }
    Err(HandlerError::new(
        ErrorCode::NOT_IMPLEMENTED,
        "A header you provided implies functionality that is not implemented",
    ))
}

/// The source object a copy will read, and the version id to report for it.
///
/// Every refusal here is the *source's*: a copy that reports on the destination answers a missing
/// source with a success. The three not-found answers are kept apart on purpose — a client branches
/// on them to decide whether to create a bucket, and a delete marker is a version that exists and
/// has no representation rather than a version that is unknown.
fn read_copy_source(fixture: &Fixture, source: &CopySource) -> Result<(StoredObject, Option<String>), HandlerError> {
    let (bucket, key) = (source.bucket.as_str(), source.key.as_str());
    if !fixture.has_bucket(bucket) {
        return Err(HandlerError::new(ErrorCode::NO_SUCH_BUCKET, "The specified bucket does not exist"));
    }
    let Some(requested) = source.version_id.as_deref() else {
        // The key named is the *source's*, which is the whole reason the element is worth carrying
        // here: a copy that reported the destination key would send a client looking at the object
        // it was writing rather than the one that was missing.
        let object = fixture.object(bucket, key).ok_or_else(|| no_such_key(key))?.clone();
        // Reported only for a versioned bucket: `null` is the version of an object in a bucket that
        // was never versioned, and a header carrying it tells a client its unversioned copy has a
        // version to come back for.
        let reported = fixture
            .is_versioned(bucket)
            .then(|| fixture.newest_version_id(bucket, key).map(ToOwned::to_owned))
            .flatten();
        return Ok((object, reported));
    };
    let version = fixture
        .version(bucket, key, requested)
        .ok_or_else(|| HandlerError::new(ErrorCode::NO_SUCH_VERSION, "The specified version does not exist."))?;
    let object = version.object.as_ref().ok_or_else(|| {
        HandlerError::new(
            ErrorCode::METHOD_NOT_ALLOWED,
            "The specified method is not allowed against this resource.",
        )
    })?;
    Ok((object.clone(), Some(requested.to_owned())))
}

/// Resolves `x-amz-copy-source-range` against the source's length, through the exported contract.
///
/// This used to be a hand-written mirror of `resolve_copy_range`, complete with its own arithmetic
/// and its own opinion about what an overlong span means — and the mirror and the contract had
/// drifted apart on both counts. It is a call now: [`rustfs_gateway::resolve_copy_range`] is
/// re-exported by the facade, so the rule a copy range is held to is the same rule for this backend
/// and for every backend outside the workspace, and a change to it cannot reach one of them without
/// the other.
///
/// What is left here is the two conversions the contract deliberately does not do: `usize` to `u64`
/// on the way in, and a rejection to a [`HandlerError`] on the way out.
///
/// # Errors
///
/// Whatever the contract refuses: a multi-range value, a value the byte-range grammar does not
/// admit, and any span the source cannot satisfy in full — all of them `InvalidArgument`.
fn resolve_copy_span(header: Option<&str>, source_len: usize) -> Result<Option<CopyRange>, HandlerError> {
    resolve_copy_range(header, source_len as u64).map_err(refused_copy_source)
}

/// The contract's own refusal, rendered.
///
/// The wording is the contract's constant, never assembled from the header: this one carries a
/// bucket name the caller may have no right to learn the existence of.
fn refused_copy_source(rejection: CopySourceRejection) -> HandlerError {
    HandlerError::new(rejection.code().clone(), rejection.reason())
}

impl Handler<dto::GetObject> for Stub {
    fn call(&self, request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let outcome = self.get_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::HeadObject> for Stub {
    fn call(&self, request: Req<dto::HeadObject>) -> impl core::future::Future<Output = HandlerResult<dto::HeadObject>> + Send {
        let outcome = self.head_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CopyObject> for Stub {
    fn call(&self, request: Req<dto::CopyObject>) -> impl core::future::Future<Output = HandlerResult<dto::CopyObject>> + Send {
        let outcome = self.copy_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::UploadPartCopy> for Stub {
    fn call(
        &self,
        request: Req<dto::UploadPartCopy>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::UploadPartCopy>> + Send {
        let outcome = self.upload_part_copy(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteObject> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObject>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObject>> + Send {
        let outcome = self.delete_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetObjectTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectTagging>> + Send {
        let outcome = self.get_object_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObjectTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::PutObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectTagging>> + Send {
        let outcome = self.put_object_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteObjectTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObjectTagging>> + Send {
        let outcome = self.delete_object_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketTagging>> + Send {
        let outcome = self.get_bucket_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketTagging>> + Send {
        let outcome = self.put_bucket_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketTagging>> + Send {
        let outcome = self.delete_bucket_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteObjects> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObjects>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObjects>> + Send {
        let outcome = self.delete_objects(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketLocation> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketLocation>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLocation>> + Send {
        let outcome = self.get_bucket_location(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketCors> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketCors>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketCors>> + Send {
        let outcome = self.get_bucket_cors(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketCors> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketCors>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketCors>> + Send {
        let outcome = self.put_bucket_cors(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketCors> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketCors>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketCors>> + Send {
        let outcome = self.delete_bucket_cors(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CreateMultipartUpload> for Stub {
    fn call(
        &self,
        request: Req<dto::CreateMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CreateMultipartUpload>> + Send {
        let outcome = self.create_multipart_upload(request.input());
        async move { outcome }
    }
}

impl Handler<dto::AbortMultipartUpload> for Stub {
    fn call(
        &self,
        request: Req<dto::AbortMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::AbortMultipartUpload>> + Send {
        let outcome = self.abort_multipart_upload(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CompleteMultipartUpload> for Stub {
    fn call(
        &self,
        request: Req<dto::CompleteMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CompleteMultipartUpload>> + Send {
        let outcome = self.complete_multipart_upload(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListMultipartUploads> for Stub {
    fn call(
        &self,
        request: Req<dto::ListMultipartUploads>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListMultipartUploads>> + Send {
        let outcome = self.list_multipart_uploads(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListParts> for Stub {
    fn call(&self, request: Req<dto::ListParts>) -> impl core::future::Future<Output = HandlerResult<dto::ListParts>> + Send {
        let outcome = self.list_parts(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListBuckets> for Stub {
    fn call(&self, request: Req<dto::ListBuckets>) -> impl core::future::Future<Output = HandlerResult<dto::ListBuckets>> + Send {
        let outcome = self.list_buckets(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListObjects> for Stub {
    fn call(&self, request: Req<dto::ListObjects>) -> impl core::future::Future<Output = HandlerResult<dto::ListObjects>> + Send {
        let outcome = self.list_objects(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListObjectsV2> for Stub {
    fn call(
        &self,
        request: Req<dto::ListObjectsV2>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjectsV2>> + Send {
        let outcome = self.list_objects_v2(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListObjectVersions> for Stub {
    fn call(
        &self,
        request: Req<dto::ListObjectVersions>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjectVersions>> + Send {
        let outcome = self.list_object_versions(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObject> for Stub {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { put_object(&state, input).await }
    }
}

impl Handler<dto::UploadPart> for Stub {
    fn call(&self, request: Req<dto::UploadPart>) -> impl core::future::Future<Output = HandlerResult<dto::UploadPart>> + Send {
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { upload_part(&state, input).await }
    }
}

/// Drains a request body into bytes using nothing but the facade.
///
/// `ByteStream` is opaque outside the workspace — `PayloadStream` is not exported — but
/// `ByteStream::into_body` and [`rustfs_gateway::collect`] both are, and together they are a
/// complete reader. A body that will not drain is an internal error here rather than a client
/// error: the acceptance layer has already committed to a framing by this point.
async fn drain(body: Option<ByteStream>) -> Result<Vec<u8>, HandlerError> {
    let Some(stream) = body else { return Ok(Vec::new()) };
    let response = http::Response::new(stream.into_body());
    let collected = collect(response)
        .await
        .map_err(|_| HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed"))?;
    Ok(collected.body().to_vec())
}

async fn put_object(state: &Arc<Mutex<Fixture>>, input: dto::PutObjectInput) -> HandlerResult<dto::PutObject> {
    let bytes = drain(input.body).await?;
    let mut fixture = state
        .lock()
        .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
    require_bucket(&fixture, &input.bucket)?;
    require_content_md5(input.content_md5.as_deref(), &bytes)?;
    let now = fixture.now;
    let existing = fixture.object(input.bucket.as_str(), input.key.as_str()).cloned();
    guard_write(existing.as_ref(), input.if_match.as_deref(), input.if_none_match.as_deref(), now)?;
    let mut object = StoredObject::new(bytes, input.content_type.clone(), now);
    object.cache_control = input.cache_control.clone();
    object.content_disposition = input.content_disposition.clone();
    object.content_encoding = input.content_encoding.clone();
    object.content_language = input.content_language.clone();
    object.expires = input.expires.as_ref().map(|value| value.as_str().to_owned());
    object.metadata = input.metadata.clone();
    // The inline tag set, which is a different thing from the `?tagging` subresource: this header
    // is how a single-request write labels the object it is writing. Parsed before the write so a
    // malformed header is a refusal rather than an object stored with no tags and a 200.
    object.tags = read_tagging_header(input.tagging.as_deref())?;
    if let Some(class) = input.storage_class.as_ref() {
        object.storage_class = class.to_string();
    }
    let size = object.body.len() as i64;
    let etag = object.etag.clone();
    let written = fixture.put_object(input.bucket.as_str(), input.key.as_str(), object);
    Ok(Resp::new(dto::PutObjectOutput {
        size: Some(size),
        // `ETag` is a *required* member of this output, so leaving it at its default did not omit
        // the header — it emitted an empty one, which is worse than omitting it: a client that
        // stores the value it was handed records `""` as the digest of the object it just wrote.
        e_tag: entity_tag(&etag)?,
        version_id: (written != UNVERSIONED).then_some(written),
        ..dto::PutObjectOutput::default()
    }))
}

async fn upload_part(state: &Arc<Mutex<Fixture>>, input: dto::UploadPartInput) -> HandlerResult<dto::UploadPart> {
    let bytes = drain(input.body).await?;
    let mut fixture = state
        .lock()
        .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
    require_bucket(&fixture, &input.bucket)?;
    let upload = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
    // Before a single byte is recorded: a part that failed its own integrity claim must not be
    // reachable by the completion that follows.
    require_content_md5(input.content_md5.as_deref(), &bytes)?;
    // The digest of the bytes that just arrived, under the algorithm the *initiation* named. A part
    // request carries no algorithm of its own, so an upload opened without one gets no checksum
    // header rather than a default one nobody asked for.
    let checksum_spec = match upload.checksum.clone() {
        None => None,
        Some(checksum) => Some(checksum_of(&checksum, &bytes)?),
    };
    let etag = fixture.put_part(&input.upload_id, input.part_number, bytes);
    Ok(Resp::new(dto::UploadPartOutput {
        checksum_spec,
        // Required, like `PutObject`'s. Nine multipart cases capture this header and quote it back
        // in the completion document, so an empty one did not merely lose a header — it made the
        // completion body they built unparseable.
        e_tag: entity_tag(&etag)?,
        ..dto::UploadPartOutput::default()
    }))
}

impl Stub {
    fn get_object(&self, input: &dto::GetObjectInput) -> HandlerResult<dto::GetObject> {
        // Before the bucket, before the key, before anything is borrowed: a request that names two
        // ways of selecting bytes is refused on its own terms.
        refuse_conflicting_selectors(input.range.as_ref().map(|range| range.as_str()), input.part_number)?;
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let found = fixture.object(input.bucket.as_str(), input.key.as_str());
        let condition = guard_read(
            found,
            input.if_match.as_deref(),
            input.if_unmodified_since.as_ref().map(|stamp| stamp.secs()),
            input.if_none_match.as_deref(),
            input.if_modified_since.as_ref().map(|stamp| stamp.secs()),
            fixture.now,
        )?;
        let Some(object) = found else { return Err(no_such_key(input.key.as_str())) };
        if condition == ConditionalOutcome::NotModified {
            return Ok(Resp::with_status(
                dto::GetObjectOutput {
                    e_tag: Some(entity_tag(&object.etag)?),
                    last_modified: Some(Timestamp::from_secs(object.last_modified)),
                    cache_control: object.cache_control.clone(),
                    expires: object.expires.clone().map(Into::into),
                    ..dto::GetObjectOutput::default()
                },
                304,
            ));
        }
        // `If-Range` is read through the contract's own total parse, never through an `Option`: a
        // fallible read would turn a validator this server cannot confirm into "no `If-Range` was
        // sent", which honours the range against a representation nobody checked — the spliced
        // download the header exists to prevent.
        let if_range = input.if_range.as_deref().map(IfRange::parse);
        let slice = resolve_range(
            input.range.as_ref().map(|range| range.as_str()),
            if_range.as_ref(),
            input.part_number,
            object,
        )?;
        let body = object.body.get(slice.start..slice.end_exclusive).unwrap_or_default().to_vec();
        let status = if slice.content_range.is_some() { 206 } else { 200 };
        Ok(Resp::with_status(
            dto::GetObjectOutput {
                content_length: Some(body.len() as i64),
                content_type: object.content_type.clone(),
                content_range: slice.content_range,
                accept_ranges: Some("bytes".to_owned()),
                // The two validators. They describe the *representation*, never the window served,
                // so a 206 reports the entity tag and the modification time of the whole object —
                // which is what makes a resumed download able to notice the object changed under it.
                e_tag: Some(entity_tag(&object.etag)?),
                last_modified: Some(Timestamp::from_secs(object.last_modified)),
                checksum_crc32: read_checksum(input.checksum_mode.as_ref(), status == 206, &object.body),
                cache_control: object.cache_control.clone(),
                content_disposition: object.content_disposition.clone(),
                content_encoding: object.content_encoding.clone(),
                content_language: object.content_language.clone(),
                expires: object.expires.clone().map(Into::into),
                metadata: object.metadata.clone(),
                storage_class: storage_class_header(object),
                tag_count: tag_count_header(object),
                body: Some(ByteStream::from_bytes(bytes::Bytes::from(body))),
                ..dto::GetObjectOutput::default()
            },
            status,
        ))
    }

    fn head_object(&self, input: &dto::HeadObjectInput) -> HandlerResult<dto::HeadObject> {
        // The same order as `get_object`'s, and for the same reason. A `HEAD` that disagreed with a
        // `GET` about which refusal comes first would be the harder half of the bug to find.
        refuse_conflicting_selectors(input.range.as_ref().map(|range| range.as_str()), input.part_number)?;
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let found = fixture.object(input.bucket.as_str(), input.key.as_str());
        let condition = guard_read(
            found,
            input.if_match.as_deref(),
            input.if_unmodified_since.as_ref().map(|stamp| stamp.secs()),
            input.if_none_match.as_deref(),
            input.if_modified_since.as_ref().map(|stamp| stamp.secs()),
            fixture.now,
        )?;
        let Some(object) = found else { return Err(no_such_key(input.key.as_str())) };
        if condition == ConditionalOutcome::NotModified {
            return Ok(Resp::with_status(
                dto::HeadObjectOutput {
                    e_tag: Some(entity_tag(&object.etag)?),
                    last_modified: Some(Timestamp::from_secs(object.last_modified)),
                    cache_control: object.cache_control.clone(),
                    expires: object.expires.clone().map(Into::into),
                    ..dto::HeadObjectOutput::default()
                },
                304,
            ));
        }
        // No `if_range` argument, and that is a fact about the model rather than a simplification:
        // `HeadObject` declares no `If-Range` binding, so the header never leaves the wire for this
        // operation and there is nothing honest to pass. A `GET` and a `HEAD` of the same object
        // therefore disagree about a stale validator; the disagreement is the model's.
        let slice = resolve_range(input.range.as_ref().map(|range| range.as_str()), None, input.part_number, object)?;
        let served = slice.end_exclusive.saturating_sub(slice.start);
        let status = if slice.content_range.is_some() { 206 } else { 200 };
        Ok(Resp::with_status(
            dto::HeadObjectOutput {
                content_length: Some(served as i64),
                content_type: object.content_type.clone(),
                content_range: slice.content_range,
                accept_ranges: Some("bytes".to_owned()),
                e_tag: Some(entity_tag(&object.etag)?),
                last_modified: Some(Timestamp::from_secs(object.last_modified)),
                // The same rule as `GetObject`'s, for the same reason: a `HEAD` carries the head a
                // `GET` would, so the two would otherwise disagree about the object's integrity.
                checksum_crc32: read_checksum(input.checksum_mode.as_ref(), status == 206, &object.body),
                cache_control: object.cache_control.clone(),
                content_disposition: object.content_disposition.clone(),
                content_encoding: object.content_encoding.clone(),
                content_language: object.content_language.clone(),
                expires: object.expires.clone().map(Into::into),
                metadata: object.metadata.clone(),
                storage_class: storage_class_header(object),
                tag_count: tag_count_header(object),
                ..dto::HeadObjectOutput::default()
            },
            status,
        ))
    }

    /// A server-side copy: read the source, then write the destination. In that order.
    ///
    /// The order is the whole of this handler. Every refusal below happens before a single byte of
    /// the destination is touched, because the two published failures on this path are not wrong
    /// answers — they are correct answers delivered after the destination was already gone. A self
    /// copy that opens the target for writing before reading the source truncates the object it was
    /// asked to rewrite, and an authorization stage that runs after the write refuses the caller
    /// and destroys the object anyway.
    ///
    /// Reading the source into an owned [`StoredObject`] before anything else is what makes that
    /// impossible here rather than merely unlikely: the bytes the copy will write are already in
    /// hand when the destination is opened, so `source == dest` is not a special case to remember.
    ///
    /// # Where the head is committed, and why the source is not below it
    ///
    /// AWS documents a copy as flushing `200` before it knows the outcome, and the boundary it
    /// documents alongside is the one used here: *"if the error occurs before the copy action
    /// starts, you receive a standard Amazon S3 error"*. Naming the source, resolving it, gating it
    /// and evaluating both sets of conditions all happen before the copy action starts, so all of
    /// them keep their own status — which is what `c-copy-0026` and `c-copy-0034` assert, each a
    /// `404` for a source that is not there. What the commit covers is the copy itself.
    fn copy_object(&self, input: &dto::CopyObjectInput) -> HandlerResult<dto::CopyObject> {
        let source = parse_copy_source(&input.copy_source)?;
        let metadata_from = directive_of(
            input.metadata_directive.as_ref().map(dto::MetadataDirective::as_str),
            "Unknown metadata directive.",
        )?;
        let tagging_from = directive_of(
            input.tagging_directive.as_ref().map(dto::TaggingDirective::as_str),
            "Unknown tagging directive.",
        )?;
        confirm_source_owner(input.expected_source_bucket_owner.as_deref())?;

        let fixture = self.borrow()?;
        let (found, source_version) = read_copy_source(&fixture, &source)?;
        guard_copy_source(
            &found,
            input.copy_source_if_match.as_deref(),
            input.copy_source_if_unmodified_since.as_ref().map(Timestamp::secs),
            input.copy_source_if_none_match.as_deref(),
            input.copy_source_if_modified_since.as_ref().map(Timestamp::secs),
            fixture.now,
        )?;
        require_bucket(&fixture, &input.bucket)?;

        // A version suffix makes the source a different representation, so a copy of an old version
        // onto the current key is not a self copy even though the key matches.
        let onto_itself = source.version_id.is_none()
            && source.bucket.as_str() == input.bucket.as_str()
            && source.key.as_str() == input.key.as_str();
        let changes_something =
            metadata_from == MetadataFrom::Request || tagging_from == MetadataFrom::Request || input.storage_class.is_some();
        if onto_itself && !changes_something {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "This copy request is illegal because it is trying to copy an object to itself \
                 without changing the object's metadata, storage class, website redirect location \
                 or encryption attributes.",
            ));
        }

        // The destination's own conditions, evaluated against the destination. The four names are
        // spelled the same as the source's and name a different representation; one evaluator over
        // both would overwrite an object the client guarded.
        let now = fixture.now;
        let existing = fixture.object(input.bucket.as_str(), input.key.as_str()).cloned();
        guard_write(existing.as_ref(), input.if_match.as_deref(), input.if_none_match.as_deref(), now)?;

        // Taken before `found` is consumed below, and applied after: the two directives are
        // independent, so a copy may replace the metadata and inherit the tags, or the reverse.
        // Folding them into one branch is the defect `c-copy-0008` exists to catch — the tagging
        // half is the one most often left out, and when it is the destination silently inherits the
        // source's labels, which is a lifecycle and access-policy decision rather than a cosmetic
        // one.
        let source_tags = found.tags.clone();
        let mut object = match metadata_from {
            // COPY is not a merge: every `x-amz-meta-*` and object attribute on the request is
            // discarded rather than layered over the source's.
            MetadataFrom::Source => StoredObject {
                last_modified: now,
                ..found
            },
            MetadataFrom::Request => {
                let mut rebuilt = StoredObject::new(found.body, input.content_type.clone(), now);
                rebuilt.cache_control = input.cache_control.clone();
                rebuilt.content_disposition = input.content_disposition.clone();
                rebuilt.content_encoding = input.content_encoding.clone();
                rebuilt.content_language = input.content_language.clone();
                rebuilt.expires = input.expires.as_ref().map(|value| value.as_str().to_owned());
                rebuilt.metadata = input.metadata.clone();
                rebuilt
            }
        };
        object.tags = match tagging_from {
            MetadataFrom::Source => source_tags,
            MetadataFrom::Request => read_tagging_header(input.tagging.as_deref())?,
        };
        if let Some(class) = input.storage_class.as_ref() {
            object.storage_class = class.to_string();
        }
        // The guard is released before the head goes out: the continuation is `'static` and takes
        // the state back on its own, so nothing holds the fixture across the commit.
        drop(fixture);

        let state = Arc::clone(&self.state);
        let bucket = input.bucket.clone();
        let key = input.key.clone();

        // The head is committed here. Nothing below chooses a status, and nothing below can refuse:
        // every rule this operation has was applied above.
        Ok(Resp::commit(Box::pin(async move {
            let etag = object.etag.clone();
            let mut fixture = state
                .lock()
                .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
            let written = fixture.put_object(bucket.as_str(), key.as_str(), object);
            drop(fixture);
            let destination_version = (written != UNVERSIONED).then_some(written);

            Ok(dto::CopyObjectOutput {
                e_tag: entity_tag(&etag)?,
                last_modified: Some(Timestamp::from_secs(now)),
                // Two headers, never one value written into both: one names the version the copy
                // read and the other the version it created, and a client told they are the same
                // records the source as its new object.
                copy_source_version_id: source_version,
                version_id: destination_version,
                ..dto::CopyObjectOutput::default()
            })
        })))
    }

    /// One part of a multipart upload, copied out of an object rather than sent.
    ///
    /// Shares [`parse_copy_source`] and [`confirm_source_owner`] with [`Stub::copy_object`], and
    /// that sharing is the point: both advisories on this family were a part copy that authorized
    /// the upload it was writing to and never the object it read from, so "both operations gate the
    /// source the same way" has to be a fact about which function is called and not a claim in a
    /// comment.
    fn upload_part_copy(&self, input: &dto::UploadPartCopyInput) -> HandlerResult<dto::UploadPartCopy> {
        let source = parse_copy_source(&input.copy_source)?;
        confirm_source_owner(input.expected_source_bucket_owner.as_deref())?;

        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
        let (found, source_version) = read_copy_source(&fixture, &source)?;
        guard_copy_source(
            &found,
            input.copy_source_if_match.as_deref(),
            input.copy_source_if_unmodified_since.as_ref().map(Timestamp::secs),
            input.copy_source_if_none_match.as_deref(),
            input.copy_source_if_modified_since.as_ref().map(Timestamp::secs),
            fixture.now,
        )?;

        // A zero-byte source has no span and is not an arithmetic edge: the copy of nothing is a
        // legal copy, and upstream aborted the process on it.
        let bytes = match resolve_copy_span(input.copy_source_range.as_deref(), found.body.len())? {
            None => found.body.clone(),
            Some(span) => {
                let start = usize::try_from(span.start).unwrap_or(usize::MAX);
                let len = usize::try_from(span.len()).unwrap_or(usize::MAX);
                found.body.get(start..start.saturating_add(len)).unwrap_or_default().to_vec()
            }
        };
        let now = fixture.now;
        let etag = fixture.put_part(&input.upload_id, input.part_number, bytes);

        Ok(Resp::new(dto::UploadPartCopyOutput {
            e_tag: entity_tag(&etag)?,
            last_modified: Some(Timestamp::from_secs(now)),
            copy_source_version_id: source_version,
            ..dto::UploadPartCopyOutput::default()
        }))
    }

    fn delete_object(&self, input: &dto::DeleteObjectInput) -> HandlerResult<dto::DeleteObject> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // A versioned delete records a marker and reports it; an unversioned one removes the object
        // and reports nothing, because there is no version for a client to come back for. Without
        // the two headers a case cannot name the marker it just created, and a delete marker that
        // cannot be named cannot be asserted about.
        let marker = fixture.remove_object(input.bucket.as_str(), input.key.as_str());
        Ok(Resp::new(dto::DeleteObjectOutput {
            delete_marker: marker.is_some().then_some(true),
            version_id: marker,
            ..dto::DeleteObjectOutput::default()
        }))
    }

    /// The tag set of one object, out of what the writer sent — never invented.
    ///
    /// An object with no tags answers `200` with an empty `<TagSet/>`, which is not the same shape
    /// as the bucket-level read: `NoSuchTagSet` has no object-level twin, and answering `404` here
    /// would make "this object has no labels" indistinguishable from "this key is not there".
    ///
    /// `versionId` is refused rather than ignored. This fixture stores the tag set on the newest
    /// version of a key, so answering a request that named an older one would report the current
    /// labels as that version's — a wrong answer, where a refusal is merely a gap.
    fn get_object_tagging(&self, input: &dto::GetObjectTaggingInput) -> HandlerResult<dto::GetObjectTagging> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        refuse_versioned_tagging(input.version_id.as_deref())?;
        let object = fixture
            .object(input.bucket.as_str(), input.key.as_str())
            .ok_or_else(|| no_such_key(input.key.as_str()))?;
        Ok(Resp::new(dto::GetObjectTaggingOutput {
            tag_set: tag_elements(&object.tags)?,
            ..dto::GetObjectTaggingOutput::default()
        }))
    }

    /// The whole tag set, replaced. There is no partial update, so an empty document clears it.
    ///
    /// The write is in place: relabelling an object is not a new representation of it, so no version
    /// is minted and the bytes, the entity tag and `Last-Modified` are all left exactly as they
    /// were. A stub that went through [`Fixture::put_object`] here would have appended a version on
    /// a versioned bucket and changed the object's modification time on every bucket, and a case
    /// asserting either afterwards would be measuring this file rather than the protocol.
    fn put_object_tagging(&self, input: &dto::PutObjectTaggingInput) -> HandlerResult<dto::PutObjectTagging> {
        let pairs = tag_pairs(&input.tagging, TagScope::Object)?;
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        refuse_versioned_tagging(input.version_id.as_deref())?;
        let object = fixture
            .object_mut(input.bucket.as_str(), input.key.as_str())
            .ok_or_else(|| no_such_key(input.key.as_str()))?;
        object.tags = pairs;
        Ok(Resp::new(dto::PutObjectTaggingOutput::default()))
    }

    /// The tag set removed, the object left where it is.
    ///
    /// The `204` is unconditional in the same sense `DeleteObject`'s is: clearing the tags of an
    /// object that carries none is a success. The key, however, still has to exist — the request
    /// names an object, and answering a success for one that is not there would tell a caller its
    /// untag landed on something.
    fn delete_object_tagging(&self, input: &dto::DeleteObjectTaggingInput) -> HandlerResult<dto::DeleteObjectTagging> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        refuse_versioned_tagging(input.version_id.as_deref())?;
        let object = fixture
            .object_mut(input.bucket.as_str(), input.key.as_str())
            .ok_or_else(|| no_such_key(input.key.as_str()))?;
        object.tags.clear();
        Ok(Resp::new(dto::DeleteObjectTaggingOutput::default()))
    }

    /// The tag set of one bucket, or the read's own 404.
    ///
    /// The unconfigured answer is the *opposite* of the object read's: a bucket that never had a
    /// tag set — or whose set was deleted, or cleared by an empty document — answers
    /// `404 NoSuchTagSet`, the code `GetBucketTagging`'s spec declares as its
    /// `not_configured_error`. Answering a `200` with an empty set here would make "unlabelled"
    /// and "labelled with nothing" indistinguishable, which is precisely the distinction the two
    /// scopes draw differently.
    fn get_bucket_tagging(&self, input: &dto::GetBucketTaggingInput) -> HandlerResult<dto::GetBucketTagging> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let tags = fixture
            .bucket_tags(input.bucket.as_str())
            .ok_or_else(|| HandlerError::new(ErrorCode::NO_SUCH_TAG_SET, "The TagSet does not exist"))?;
        Ok(Resp::new(dto::GetBucketTaggingOutput {
            tag_set: tag_elements(tags)?,
        }))
    }

    /// The whole bucket tag set, replaced — under the bucket scope's ceilings.
    ///
    /// The same shared validator the object write goes through, with `TagScope::Bucket` naming
    /// the one rule that differs: fifty tags rather than ten. An empty `<TagSet/>` never reaches
    /// here — `TagSet` is a required member, so the generated decoder answers it with
    /// `MalformedXML` (`c-tagging-0005`); the delete is the clearing path. The empty-to-`None`
    /// collapse below is therefore a defensive spelling of "a configured set is never empty",
    /// not a wire behaviour.
    fn put_bucket_tagging(&self, input: &dto::PutBucketTaggingInput) -> HandlerResult<dto::PutBucketTagging> {
        let pairs = tag_pairs(&input.tagging, TagScope::Bucket)?;
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.set_bucket_tags(input.bucket.as_str(), (!pairs.is_empty()).then_some(pairs));
        Ok(Resp::new(dto::PutBucketTaggingOutput::default()))
    }

    /// The bucket's tag set removed, unconditionally.
    ///
    /// The `204` does not depend on a set being there — untagging an unlabelled bucket is a
    /// success — but the bucket itself still has to exist: the request names one, and a success
    /// for a missing bucket would tell the caller its delete landed somewhere.
    fn delete_bucket_tagging(&self, input: &dto::DeleteBucketTaggingInput) -> HandlerResult<dto::DeleteBucketTagging> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.set_bucket_tags(input.bucket.as_str(), None);
        Ok(Resp::new(dto::DeleteBucketTaggingOutput::default()))
    }

    fn delete_objects(&self, input: &dto::DeleteObjectsInput) -> HandlerResult<dto::DeleteObjects> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let quiet = input.delete.quiet.unwrap_or(false);
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        let locked = fixture.has_object_lock(input.bucket.as_str());
        for identifier in &input.delete.objects {
            // Deleting a *version* is where `setup.buckets[].object_lock` becomes observable. On a
            // lock-enabled bucket removing a version needs `s3:BypassGovernanceRetention`, and the
            // refusal is an authorisation decision taken before the version is looked up — so the
            // answer is `AccessDenied` and it does not disclose whether the version exists. Without
            // object lock the fixture keeps no version history, so the same request is a per-key
            // `NoSuchVersion`. Reporting either per key rather than failing the whole request is
            // the shape this operation is being measured for.
            if let Some(version) = identifier.version_id.as_ref() {
                let (code, message) = if locked {
                    ("AccessDenied", "Access Denied")
                } else {
                    ("NoSuchVersion", "The specified version does not exist.")
                };
                errors.push(dto::Error {
                    key: Some(identifier.key.clone()),
                    version_id: Some(version.clone()),
                    code: Some(code.to_owned()),
                    message: Some(message.to_owned()),
                });
                continue;
            }
            fixture.remove_object(input.bucket.as_str(), identifier.key.as_str());
            if !quiet {
                deleted.push(dto::DeletedObject {
                    key: Some(identifier.key.clone()),
                    ..dto::DeletedObject::default()
                });
            }
        }
        Ok(Resp::new(dto::DeleteObjectsOutput {
            deleted,
            errors,
            ..dto::DeleteObjectsOutput::default()
        }))
    }

    fn get_bucket_location(&self, input: &dto::GetBucketLocationInput) -> HandlerResult<dto::GetBucketLocation> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        Ok(Resp::new(dto::GetBucketLocationOutput::default()))
    }

    /// The stored CORS document, or the family's defining 404.
    ///
    /// The bucket is resolved first, so a missing bucket is `NoSuchBucket` and only a bucket that
    /// exists without a document is `NoSuchCORSConfiguration` — two different facts a client
    /// tearing down configuration branches on. There is no empty-document answer: the decoder
    /// refuses a document with no rule on the way in, so "configured but empty" is unrepresentable.
    fn get_bucket_cors(&self, input: &dto::GetBucketCorsInput) -> HandlerResult<dto::GetBucketCors> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = fixture.cors(input.bucket.as_str()).ok_or_else(no_such_cors_configuration)?;
        Ok(Resp::new(dto::GetBucketCorsOutput {
            cors_rules: configuration.cors_rules.clone(),
        }))
    }

    /// The whole document, replaced — after the one validation pass every backend shares.
    ///
    /// The rules are `rustfs_gateway::validate_cors`'s, not this file's: the closed method set,
    /// the wildcard budget and the hundred-rule cap live once in the shared contract, and this
    /// fixture calls it rather than mirroring it — the copy-source mirror is the cautionary tale.
    /// What is stored is exactly what was sent, in the order it was sent: the read-back is a
    /// byte-level golden, and a stub that re-sorted rules would be answering from a decision of
    /// its own.
    fn put_bucket_cors(&self, input: &dto::PutBucketCorsInput) -> HandlerResult<dto::PutBucketCors> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        validate_cors(&input.cors_configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_cors(input.bucket.as_str(), input.cors_configuration.clone());
        Ok(Resp::new(dto::PutBucketCorsOutput::default()))
    }

    /// The document removed, the bucket left alone.
    ///
    /// The `204` is unconditional in the same sense `DeleteObject`'s is: removing the CORS
    /// configuration of a bucket that has none is a success, not a `404`. The bucket itself still
    /// has to exist — the request names one, and a success for a bucket that is not there would
    /// tell a caller its teardown landed on something.
    fn delete_bucket_cors(&self, input: &dto::DeleteBucketCorsInput) -> HandlerResult<dto::DeleteBucketCors> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.clear_cors(input.bucket.as_str());
        Ok(Resp::new(dto::DeleteBucketCorsOutput::default()))
    }

    /// Opens a multipart upload, and records the attributes only this request can state.
    ///
    /// Nothing here is invented: every value stored is one the initiating request carried, and the
    /// two that come back out as headers come back out unchanged. What the fixture must not do is
    /// *drop* them, because the object they describe does not exist yet and there is no second
    /// request that could restate them.
    fn create_multipart_upload(&self, input: &dto::CreateMultipartUploadInput) -> HandlerResult<dto::CreateMultipartUpload> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let mut upload = StoredUpload::bare(input.bucket.as_str(), input.key.as_str());
        upload.attributes.content_type = input.content_type.clone();
        upload.attributes.cache_control = input.cache_control.clone();
        upload.attributes.content_disposition = input.content_disposition.clone();
        upload.attributes.content_encoding = input.content_encoding.clone();
        upload.attributes.content_language = input.content_language.clone();
        upload.attributes.expires = input.expires.as_ref().map(|value| value.as_str().to_owned());
        upload.attributes.metadata = input.metadata.clone();
        if let Some(class) = input.storage_class.as_ref() {
            upload.attributes.storage_class = class.to_string();
        }
        upload.encryption = input.server_side_encryption.clone();
        upload.checksum = upload_checksum(input.checksum_algorithm.as_ref(), input.checksum_type.as_ref())?;
        let server_side_encryption = input.server_side_encryption.clone();
        let checksum_algorithm = input.checksum_algorithm.clone();
        let checksum_type = upload.checksum.as_ref().map(|checksum| checksum.kind.clone());
        let upload_id = fixture.begin_upload(upload);
        Ok(Resp::new(dto::CreateMultipartUploadOutput {
            bucket: input.bucket.clone(),
            key: input.key.clone(),
            upload_id,
            server_side_encryption,
            checksum_algorithm,
            checksum_type,
            ..dto::CreateMultipartUploadOutput::default()
        }))
    }

    fn abort_multipart_upload(&self, input: &dto::AbortMultipartUploadInput) -> HandlerResult<dto::AbortMultipartUpload> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // Resolved before it is removed: an abort that dropped an upload it did not own would let a
        // stranger destroy work in progress, and the caller would see the same 204 either way.
        require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
        fixture.uploads.remove(&input.upload_id);
        Ok(Resp::new(dto::AbortMultipartUploadOutput::default()))
    }

    /// Completes an upload, committing the head once nothing can still choose a status.
    ///
    /// The function reads as two halves, and the boundary is the whole point. Above the commit is
    /// every refusal that carries a status of its own — the bucket, the upload's ownership of its
    /// bucket and key, the part list's arity and order, the write's own conditional headers, and
    /// then each named part resolved, size-checked and digest-checked. Below it is the assembly:
    /// concatenating the bytes, deriving the composite entity tag and the part checksums, and
    /// writing the object. That is the work AWS documents as outlasting a client's timeout, which is
    /// why the head goes out before it starts.
    ///
    /// The split is not a stylistic one. After [`Resp::commit`] the continuation's error type is a
    /// `HandlerError` with no status, so a refusal that moved below the boundary would silently
    /// become a `200` — `c-mpu-0020` … `c-mpu-0023` and `c-mpu-0026` are the cases that would go
    /// green while reporting the wrong status line. Every check that can still name a status is
    /// therefore above it, and what is left below can only fail the way an internal error fails.
    fn complete_multipart_upload(
        &self,
        input: &dto::CompleteMultipartUploadInput,
    ) -> HandlerResult<dto::CompleteMultipartUpload> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let upload = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?.clone();
        let named = &input.multipart_upload.parts;
        if named.is_empty() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_PART,
                "One or more of the specified parts could not be found.",
            ));
        }
        let mut previous = 0;
        for part in named {
            if part.part_number <= previous {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_PART_ORDER,
                    "The list of parts was not in ascending order. Parts must be ordered by part number.",
                ));
            }
            previous = part.part_number;
        }
        // A completion is a write, and it carries the same two conditional headers a write does.
        let existing = fixture.object(upload.bucket.as_str(), upload.key.as_str()).cloned();
        guard_write(existing.as_ref(), input.if_match.as_deref(), input.if_none_match.as_deref(), fixture.now)?;
        // Resolved, size-checked and digest-checked *before* the head is committed, and collected
        // in the order the request named them. Each of these three refusals carries its own status,
        // so each has to happen while a status is still choosable.
        let mut ordered_parts: Vec<StoredPart> = Vec::with_capacity(named.len());
        let final_part = named.len().saturating_sub(1);
        for (index, part) in named.iter().enumerate() {
            let stored = upload.parts.get(&part.part_number).ok_or_else(|| {
                HandlerError::new(ErrorCode::INVALID_PART, "One or more of the specified parts could not be found.")
            })?;
            // The size floor, and the one exemption that makes it usable: every part but the last
            // must reach [`MIN_PART_BYTES`], because the object is the concatenation and a short
            // part in the middle is a hole no later read can detect. Applying the floor to the final
            // part too would make every upload whose total is not a multiple of the floor
            // uncompletable, so the exemption is the rule rather than a leniency.
            if index != final_part && stored.body.len() < MIN_PART_BYTES {
                return Err(HandlerError::new(
                    ErrorCode::ENTITY_TOO_SMALL,
                    "Your proposed upload is smaller than the minimum allowed size",
                ));
            }
            // An empty claim is accepted rather than refused: a case that echoes back a header some
            // *other* implementation did not send is asserting about that implementation, and a
            // digest mismatch reported here would name a mismatch that never happened.
            if let Some(claimed) = part.e_tag.as_ref() {
                let claimed = claimed.opaque_tag();
                if !claimed.is_empty() && claimed != stored.etag {
                    return Err(HandlerError::new(
                        ErrorCode::INVALID_PART,
                        "One or more of the specified parts could not be found.",
                    ));
                }
            }
            ordered_parts.push(stored.clone());
        }
        // The guard is released before the head goes out: the continuation is `'static` and takes
        // the state back on its own, so nothing holds the fixture across the commit.
        drop(fixture);

        let state = Arc::clone(&self.state);
        let upload_id = input.upload_id.clone();
        let bucket = input.bucket.clone();
        let key = input.key.clone();
        let location = format!("/{}/{}", input.bucket.as_str(), input.key.as_str());

        // The head is committed here. Everything below runs with the status line already on the
        // wire, and the only thing it can still report is a failure with no status of its own.
        Ok(Resp::commit(Box::pin(async move {
            let mut assembled = Vec::new();
            let mut digests = Vec::new();
            let mut part_checksums = Vec::new();
            for stored in &ordered_parts {
                digests.push(crate::md5::digest(&stored.body));
                if let Some(checksum) = upload.checksum.as_ref() {
                    part_checksums.push((checksum_of(checksum, &stored.body)?, stored.body.len() as u64));
                }
                assembled.extend_from_slice(&stored.body);
            }
            // The two ways S3 rolls part checksums into one, and they are not interchangeable: a
            // composite is a digest *of the digests* and carries `-N`, while a full-object checksum
            // is the digest the whole object would have had if it had arrived in one request.
            // Emitting one where the upload asked for the other gives a client a value that never
            // verifies.
            let checksum_spec = match upload.checksum.as_ref() {
                None => None,
                Some(checksum) if checksum.kind == dto::ChecksumType::FULL_OBJECT => Some(
                    ChecksumSpec::combine_full_object(&part_checksums)
                        .map_err(|_| HandlerError::internal_error("the part checksums do not combine"))?,
                ),
                Some(_) => {
                    let parts: Vec<ChecksumSpec> = part_checksums.iter().map(|(spec, _)| *spec).collect();
                    Some(
                        ChecksumSpec::composite_of(&parts)
                            .map_err(|_| HandlerError::internal_error("the part checksums have no composite"))?,
                    )
                }
            };
            let checksum_type = upload.checksum.as_ref().map(|checksum| checksum.kind.clone());
            // The entity tag of a multipart object is not the digest of its bytes. It is the digest
            // of the concatenated part digests with the part count after a hyphen, and a client that
            // reads the plain MD5 back would compare it against the composite and conclude the
            // object is corrupt. `ETag::from_part_digests` is the framework's own derivation of that
            // rule, so the two spellings cannot drift.
            let composite = ETag::from_part_digests(&digests)
                .map_err(|_| HandlerError::internal_error("a part digest set has no entity tag"))?;
            let mut fixture = state
                .lock()
                .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
            let now = fixture.now;
            let object = StoredObject {
                body: assembled,
                etag: composite.opaque_tag().to_owned(),
                last_modified: now,
                ..upload.attributes.clone()
            };
            let written = fixture.put_object(&upload.bucket, &upload.key, object);
            fixture.uploads.remove(&upload_id);
            drop(fixture);
            Ok(dto::CompleteMultipartUploadOutput {
                bucket: Some(bucket),
                key: Some(key),
                location: Some(location),
                e_tag: Some(composite),
                version_id: (written != UNVERSIONED).then_some(written),
                // The body binds one element per algorithm rather than the packed spec a header
                // binds, so the rendering is explicit here. CRC32 is the only algorithm this fixture
                // computes, and `upload_checksum` refuses the rest outright rather than letting one
                // fall through to an empty element.
                checksum_crc32: checksum_spec.as_ref().map(|spec| spec.render_base64().to_owned()),
                checksum_type,
                // Decided at initiation, reported here. That gap is the whole of what these cases
                // measure: the completion's head is flushed before the body is assembled, so a value
                // that is only looked up afterwards can never become a header.
                server_side_encryption: upload.encryption.clone(),
                ..dto::CompleteMultipartUploadOutput::default()
            })
        })))
    }

    fn list_multipart_uploads(&self, input: &dto::ListMultipartUploadsInput) -> HandlerResult<dto::ListMultipartUploads> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // An upload-id marker is not a free-form string: it names an id this service minted, so
        // one shaped like a path is refused before it is compared against anything.
        let upload_marker = match input.upload_id_marker.as_deref().filter(|text| !text.is_empty()) {
            None => None,
            Some(text) if is_minted_upload_id(text) => Some(text),
            Some(_) => {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_ARGUMENT,
                    "Invalid upload-id-marker: it does not name an upload id this service issued",
                ));
            }
        };
        let prefix = input.prefix.clone().unwrap_or_default();
        let delimiter = delimiter_of(input.delimiter.as_deref());
        let key_marker = input.key_marker.as_deref().unwrap_or("");

        let mut ordered: Vec<(&str, &str)> = fixture
            .uploads
            .iter()
            .filter(|(_, upload)| upload.bucket == input.bucket.as_str() && upload.key.starts_with(&prefix))
            .map(|(id, upload)| (upload.key.as_str(), id.as_str()))
            .collect();
        ordered.sort_unstable();

        let mut entries: Vec<UploadEntry<'_>> = Vec::new();
        for (key, id) in ordered {
            if !after_upload_marker(key, id, key_marker, upload_marker) {
                continue;
            }
            match fold(key, &prefix, delimiter) {
                Some(folded) => {
                    if !entries.iter().any(|entry| entry.folded_prefix() == Some(folded.as_str())) {
                        entries.push(UploadEntry::Folded(folded));
                    }
                }
                None => entries.push(UploadEntry::Upload { key, id }),
            }
        }

        let max_uploads = input.max_uploads.unwrap_or(1000);
        let truncated = truncate_to(&mut entries, max_uploads);
        let (mut next_key, mut next_upload) = (None, None);
        if truncated {
            match entries.last() {
                Some(UploadEntry::Upload { key, id }) => {
                    next_key = Some((*key).to_owned());
                    next_upload = Some((*id).to_owned());
                }
                Some(UploadEntry::Folded(prefix)) => next_key = Some(prefix.clone()),
                None => {}
            }
        }

        let mut uploads = Vec::new();
        let mut common_prefixes = Vec::new();
        for entry in &entries {
            match entry {
                UploadEntry::Upload { key, id } => uploads.push(dto::MultipartUpload {
                    upload_id: Some((*id).to_owned()),
                    key: Some(object_key(key)?),
                    initiated: Some(Timestamp::from_secs(fixture.now)),
                    storage_class: Some(dto::StorageClass::STANDARD),
                    ..dto::MultipartUpload::default()
                }),
                UploadEntry::Folded(prefix) => common_prefixes.push(dto::CommonPrefix { prefix: prefix.clone() }),
            }
        }

        Ok(Resp::new(dto::ListMultipartUploadsOutput {
            bucket: input.bucket.clone(),
            prefix: input.prefix.clone(),
            delimiter: input.delimiter.clone(),
            encoding_type: input.encoding_type.clone(),
            key_marker: input.key_marker.clone(),
            upload_id_marker: input.upload_id_marker.clone(),
            next_key_marker: next_key,
            next_upload_id_marker: next_upload,
            max_uploads,
            is_truncated: truncated,
            uploads,
            common_prefixes,
            ..dto::ListMultipartUploadsOutput::default()
        }))
    }

    fn list_parts(&self, input: &dto::ListPartsInput) -> HandlerResult<dto::ListParts> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // The part-number marker is bound as a string by the model, so nothing before this point
        // has checked that it is a number. `c-mpu-0046` is the case that noticed.
        let marker: i32 = match input.part_number_marker.as_deref().filter(|text| !text.is_empty()) {
            None => 0,
            Some(text) => text.parse().ok().filter(|value| *value >= 0).ok_or_else(|| {
                HandlerError::new(
                    ErrorCode::INVALID_ARGUMENT,
                    "Argument part-number-marker must be an integer between 0 and 2147483647",
                )
            })?,
        };
        let upload = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;

        // `BTreeMap` already holds the parts in ascending part-number order, which is the order
        // `ListParts` answers in and the order a marker resumes.
        let mut numbers: Vec<i32> = upload.parts.keys().copied().filter(|number| *number > marker).collect();
        let max_parts = input.max_parts.unwrap_or(1000);
        let truncated = truncate_to(&mut numbers, max_parts);
        let next_marker = truncated.then(|| numbers.last().map(i32::to_string)).flatten();

        let mut parts = Vec::new();
        for number in numbers {
            let Some(stored) = upload.parts.get(&number) else { continue };
            parts.push(dto::Part {
                part_number: number,
                size: stored.body.len() as i64,
                e_tag: entity_tag(&stored.etag)?,
                last_modified: Some(Timestamp::from_secs(fixture.now)),
                ..dto::Part::default()
            });
        }

        Ok(Resp::new(dto::ListPartsOutput {
            bucket: input.bucket.clone(),
            key: input.key.clone(),
            upload_id: input.upload_id.clone(),
            part_number_marker: input.part_number_marker.clone(),
            next_part_number_marker: next_marker,
            max_parts,
            is_truncated: truncated,
            parts,
            storage_class: Some(dto::StorageClass::STANDARD),
            ..dto::ListPartsOutput::default()
        }))
    }

    fn list_buckets(&self, input: &dto::ListBucketsInput) -> HandlerResult<dto::ListBuckets> {
        let fixture = self.borrow()?;
        let after = match input.continuation_token.as_ref() {
            None => None,
            Some(token) => Some(read_token(token.as_str()).ok_or_else(bad_token)?),
        };
        let prefix = input.prefix.clone().unwrap_or_default();
        // `bucket-region` is accepted and not applied: this fixture models one deployment and no
        // region at all, so filtering on it would be a decision made out of nothing. A filter that
        // is ignored can only over-return, which no case can mistake for a correct answer it asked
        // for — unlike a filter answered from an invented region, which could.
        let mut names: Vec<&str> = fixture
            .bucket_names()
            .into_iter()
            .filter(|name| name.starts_with(&prefix))
            .filter(|name| after.as_deref().is_none_or(|marker| *name > marker))
            .collect();
        let max_buckets = input.max_buckets.unwrap_or(10_000);
        let truncated = truncate_to(&mut names, max_buckets);
        let next = truncated.then(|| names.last().map(|name| mint_token(name))).flatten();

        let mut buckets = Vec::new();
        for name in names {
            buckets.push(dto::Bucket {
                name: BucketName::new(name.to_owned())
                    .map_err(|_| HandlerError::internal_error("a fixture bucket name is not a valid bucket name"))?,
                creation_date: Timestamp::from_secs(fixture.now),
                ..dto::Bucket::default()
            });
        }

        Ok(Resp::new(dto::ListBucketsOutput {
            buckets,
            owner: owner(),
            continuation_token: next.map(Into::into),
            prefix: input.prefix.clone(),
        }))
    }

    fn list_objects(&self, input: &dto::ListObjectsInput) -> HandlerResult<dto::ListObjects> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let max_keys = input.max_keys.unwrap_or(1000);
        let page = paginate(
            &fixture,
            input.bucket.as_str(),
            input.prefix.as_deref().unwrap_or(""),
            delimiter_of(input.delimiter.as_deref()),
            input.marker.as_deref(),
            max_keys,
        );
        // The first listing version writes an owner for every entry with nothing having asked for
        // one; the second writes one only for `fetch-owner=true`. That asymmetry is the whole of
        // `c-list-0010` and `c-list-0024`.
        let contents = page.contents(&fixture, input.bucket.as_str(), true)?;
        Ok(Resp::new(dto::ListObjectsOutput {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            marker: input.marker.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            encoding_type: input.encoding_type.clone(),
            max_keys,
            is_truncated: page.truncated,
            // A v1 next marker is the last entry in the clear, because that is what the client
            // sends back as `?marker=` and what AWS documents it to be.
            next_marker: page.next.clone(),
            contents,
            common_prefixes: page.common_prefixes(),
            ..dto::ListObjectsOutput::default()
        }))
    }

    fn list_objects_v2(&self, input: &dto::ListObjectsV2Input) -> HandlerResult<dto::ListObjectsV2> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // A continuation token decides the page on its own; `start-after` is read only when there
        // is no token to read. Both arriving together is `c-list-0007`.
        let start = match input.continuation_token.as_ref() {
            Some(token) => Some(read_token(token.as_str()).ok_or_else(bad_token)?),
            None => input.start_after.clone(),
        };
        let max_keys = input.max_keys.unwrap_or(1000);
        let page = paginate(
            &fixture,
            input.bucket.as_str(),
            input.prefix.as_deref().unwrap_or(""),
            delimiter_of(input.delimiter.as_deref()),
            start.as_deref(),
            max_keys,
        );
        let contents = page.contents(&fixture, input.bucket.as_str(), input.fetch_owner.unwrap_or(false))?;
        Ok(Resp::new(dto::ListObjectsV2Output {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            encoding_type: input.encoding_type.clone(),
            max_keys,
            key_count: page.count(),
            is_truncated: page.truncated,
            next_continuation_token: page.next.as_deref().map(|marker| mint_token(marker).into()),
            contents,
            common_prefixes: page.common_prefixes(),
            continuation_token: input.continuation_token.clone(),
            start_after: input.start_after.clone(),
            ..dto::ListObjectsV2Output::default()
        }))
    }

    fn list_object_versions(&self, input: &dto::ListObjectVersionsInput) -> HandlerResult<dto::ListObjectVersions> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // A version marker names a position *within* a key, so without a key marker there is no
        // position for it to name. AWS refuses the pair rather than guessing one.
        if input.version_id_marker.is_some() && input.key_marker.is_none() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_ARGUMENT,
                "A version-id marker cannot be specified without a key marker.",
            ));
        }
        let key_marker = input.key_marker.as_deref().unwrap_or("");
        let version_marker = input
            .version_id_marker
            .as_ref()
            .map(|marker| marker.as_str())
            .filter(|marker| !marker.is_empty());
        let prefix = input.prefix.clone().unwrap_or_default();
        let delimiter = delimiter_of(input.delimiter.as_deref());

        let all = fixture.versions_in(input.bucket.as_str());
        let mut resumed = version_marker.is_none();
        let mut entries: Vec<VersionEntry<'_>> = Vec::new();
        for entry in &all {
            if !entry.key.starts_with(&prefix) {
                continue;
            }
            if !resumed {
                // A version marker resumes *after* the entry it names. A marker that names no
                // entry of this key leaves the key skipped entirely, which is the same answer as
                // a key marker one character short of it.
                if entry.key == key_marker && entry.version.version_id == version_marker.unwrap_or_default() {
                    resumed = true;
                }
                continue;
            }
            if version_marker.is_none() && entry.key <= key_marker {
                continue;
            }
            match fold(entry.key, &prefix, delimiter) {
                Some(folded) => {
                    if !entries.iter().any(|held| held.folded_prefix() == Some(folded.as_str())) {
                        entries.push(VersionEntry::Folded(folded));
                    }
                }
                None => entries.push(VersionEntry::Version(*entry)),
            }
        }

        let max_keys = input.max_keys.unwrap_or(1000);
        let truncated = truncate_to(&mut entries, max_keys);
        let (mut next_key, mut next_version) = (None, None);
        if truncated {
            match entries.last() {
                Some(VersionEntry::Version(entry)) => {
                    next_key = Some(entry.key.to_owned());
                    next_version = Some(entry.version.version_id.clone());
                }
                Some(VersionEntry::Folded(prefix)) => next_key = Some(prefix.clone()),
                None => {}
            }
        }

        let mut versions = Vec::new();
        let mut delete_markers = Vec::new();
        let mut common_prefixes = Vec::new();
        for entry in &entries {
            match entry {
                VersionEntry::Folded(prefix) => common_prefixes.push(dto::CommonPrefix { prefix: prefix.clone() }),
                VersionEntry::Version(held) => match held.version.object.as_ref() {
                    Some(object) => versions.push(dto::ObjectVersion {
                        key: object_key(held.key)?,
                        version_id: held.version.version_id.clone().into(),
                        is_latest: held.is_latest,
                        last_modified: Timestamp::from_secs(held.version.last_modified),
                        e_tag: entity_tag(&object.etag)?,
                        size: object.body.len() as i64,
                        storage_class: dto::StorageClass::custom(object.storage_class.clone()),
                        owner: Some(owner()),
                        ..dto::ObjectVersion::default()
                    }),
                    None => delete_markers.push(dto::DeleteMarkerEntry {
                        key: object_key(held.key)?,
                        version_id: held.version.version_id.clone().into(),
                        is_latest: held.is_latest,
                        last_modified: Timestamp::from_secs(held.version.last_modified),
                        owner: Some(owner()),
                    }),
                },
            }
        }

        Ok(Resp::new(dto::ListObjectVersionsOutput {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            encoding_type: input.encoding_type.clone(),
            key_marker: input.key_marker.clone().unwrap_or_default(),
            version_id_marker: input.version_id_marker.clone().unwrap_or_default(),
            next_key_marker: next_key,
            next_version_id_marker: next_version.map(Into::into),
            max_keys,
            is_truncated: truncated,
            versions,
            delete_markers,
            common_prefixes,
            ..dto::ListObjectVersionsOutput::default()
        }))
    }
}

/// One entry of an upload listing: an upload, or the prefix a delimiter folded it into.
enum UploadEntry<'a> {
    /// An upload, by key and id.
    Upload {
        /// The key it will become.
        key: &'a str,
        /// The id it was minted with.
        id: &'a str,
    },
    /// A folded common prefix.
    Folded(String),
}

impl UploadEntry<'_> {
    fn folded_prefix(&self) -> Option<&str> {
        match self {
            UploadEntry::Folded(prefix) => Some(prefix.as_str()),
            UploadEntry::Upload { .. } => None,
        }
    }
}

/// One entry of a version listing: a version, or the prefix a delimiter folded it into.
enum VersionEntry<'a> {
    /// One version or delete marker.
    Version(VersionRef<'a>),
    /// A folded common prefix.
    Folded(String),
}

impl VersionEntry<'_> {
    fn folded_prefix(&self) -> Option<&str> {
        match self {
            VersionEntry::Folded(prefix) => Some(prefix.as_str()),
            VersionEntry::Version(_) => None,
        }
    }
}

/// Whether an upload sits after the `(key, upload id)` position the markers name.
fn after_upload_marker(key: &str, id: &str, key_marker: &str, upload_marker: Option<&str>) -> bool {
    match upload_marker {
        None => key > key_marker,
        Some(marker) => key > key_marker || (key == key_marker && id > marker),
    }
}

/// Whether a value has the shape of an upload id this fixture mints.
fn is_minted_upload_id(value: &str) -> bool {
    value
        .strip_prefix("conformance-upload-")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit()))
}

/// The common prefix `key` folds into under `delimiter`, if it folds at all.
fn fold(key: &str, prefix: &str, delimiter: Option<&str>) -> Option<String> {
    let delimiter = delimiter?;
    let rest = key.get(prefix.len()..)?;
    let at = rest.find(delimiter)?;
    key.get(..prefix.len() + at + delimiter.len()).map(ToOwned::to_owned)
}

/// Cuts `entries` down to `max`, answering whether anything was left behind.
///
/// `max = 0` is not a truncation: S3 answers a zero page size with an empty listing and
/// `IsTruncated` false, because a client that saw `true` would ask for the next page of nothing
/// forever. `c-list-0027` is the case that pins it.
fn truncate_to<T>(entries: &mut Vec<T>, max: i32) -> bool {
    let limit = usize::try_from(max.max(0)).unwrap_or(usize::MAX);
    let truncated = limit > 0 && entries.len() > limit;
    entries.truncate(limit);
    truncated
}

/// One page of a listing: the keys that survived the delimiter, and the folded prefixes.
struct Page {
    keys: Vec<String>,
    common_prefixes: Vec<String>,
    truncated: bool,
    /// The last entry emitted — a key or a folded prefix — which is what the next page resumes
    /// after. `None` when the page was not truncated.
    next: Option<String>,
}

impl Page {
    fn common_prefixes(&self) -> Vec<dto::CommonPrefix> {
        self.common_prefixes
            .iter()
            .map(|prefix| dto::CommonPrefix { prefix: prefix.clone() })
            .collect()
    }

    /// Entries on the page: keys plus folded prefixes. This is `KeyCount`, and the fact that it
    /// counts both is what several list cases exist to pin.
    fn count(&self) -> i32 {
        i32::try_from(self.keys.len() + self.common_prefixes.len()).unwrap_or(i32::MAX)
    }

    /// The `Contents` entries for the keys on this page.
    fn contents(&self, fixture: &Fixture, bucket: &str, with_owner: bool) -> Result<Vec<dto::Object>, HandlerError> {
        let mut out = Vec::with_capacity(self.keys.len());
        for key in &self.keys {
            let object = fixture
                .object(bucket, key)
                .ok_or_else(|| HandlerError::internal_error("a key this listing selected is no longer in the fixture"))?;
            out.push(object_entry(key, object, with_owner)?);
        }
        Ok(out)
    }
}

/// Applies prefix, delimiter, start position and page size, in that order.
///
/// Entries are paged in one lexicographic sequence over keys *and* folded prefixes, because that
/// is the sequence a continuation token has to resume: paging the two lists independently makes a
/// resumed listing skip or repeat entries, which is invisible to any single-response assertion.
fn paginate(fixture: &Fixture, bucket: &str, prefix: &str, delimiter: Option<&str>, after: Option<&str>, max: i32) -> Page {
    let mut entries: Vec<(String, bool)> = Vec::new();
    for key in fixture.keys_in(bucket) {
        if !key.starts_with(prefix) {
            continue;
        }
        // The marker is compared against the *entry*, not against the key: with a delimiter in
        // play, the last thing page one emitted may have been a folded prefix, and resuming after
        // `b/` has to drop every key underneath it rather than only the one that spelled it.
        let entry = match fold(key, prefix, delimiter) {
            Some(folded) => (folded, true),
            None => (key.to_owned(), false),
        };
        if after.is_some_and(|marker| entry.0.as_str() <= marker) {
            continue;
        }
        if entry.1 && entries.iter().any(|(value, is_prefix)| *is_prefix && *value == entry.0) {
            continue;
        }
        entries.push(entry);
    }
    entries.sort();
    let truncated = truncate_to(&mut entries, max);
    let next = truncated.then(|| entries.last().map(|(value, _)| value.clone())).flatten();
    Page {
        keys: entries
            .iter()
            .filter(|(_, is_prefix)| !is_prefix)
            .map(|(value, _)| value.clone())
            .collect(),
        common_prefixes: entries
            .iter()
            .filter(|(_, is_prefix)| *is_prefix)
            .map(|(value, _)| value.clone())
            .collect(),
        truncated,
        next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The elements of a refusal, in the order the document will write them.
    fn elements(error: &HandlerError) -> Vec<(&'static str, String)> {
        error
            .details()
            .iter()
            .map(|detail| (detail.element(), detail.text().into_owned()))
            .collect()
    }

    /// The headers a refusal adds to its own head, rendered.
    fn head(error: &HandlerError) -> Vec<(String, String)> {
        error
            .headers()
            .iter()
            .map(|header| (header.name().as_str().to_owned(), header.value()))
            .collect()
    }

    fn name(text: &str) -> BucketName {
        BucketName::new(text).expect("a bucket name")
    }

    fn object_key(text: &str) -> ObjectKey {
        ObjectKey::new(text).expect("an object key")
    }

    /// A stub holding one bucket, one two-part upload, and one object to copy from.
    ///
    /// The parts are `MIN_PART_BYTES` and one byte, so the size floor is satisfied by a completion
    /// that names them in order and violated by one that names them the other way round.
    fn stub_with_an_upload() -> (Stub, String, String, String) {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("conf-bucket", false);
        fixture.put_object("conf-bucket", "src", StoredObject::new(b"source bytes".to_vec(), None, 0));
        let upload = fixture.create_upload("conf-bucket", "k");
        let first = fixture.put_part(&upload, 1, vec![0_u8; MIN_PART_BYTES]);
        let second = fixture.put_part(&upload, 2, vec![1_u8]);
        (Stub::new(Arc::new(Mutex::new(fixture))), upload, first, second)
    }

    fn completion(upload_id: &str, parts: Vec<(i32, Option<&str>)>) -> dto::CompleteMultipartUploadInput {
        dto::CompleteMultipartUploadInput {
            bucket: name("conf-bucket"),
            key: object_key("k"),
            upload_id: upload_id.to_owned(),
            multipart_upload: dto::CompletedMultipartUpload {
                parts: parts
                    .into_iter()
                    .map(|(number, tag)| dto::CompletedPart {
                        part_number: number,
                        e_tag: tag.map(|tag| ETag::new(format!("\"{tag}\"")).expect("an entity tag")),
                        ..dto::CompletedPart::default()
                    })
                    .collect(),
            },
            ..dto::CompleteMultipartUploadInput::default()
        }
    }

    fn copy(source: &str, destination: &str) -> dto::CopyObjectInput {
        dto::CopyObjectInput {
            bucket: name("conf-bucket"),
            key: object_key(destination),
            copy_source: source.to_owned(),
            ..dto::CopyObjectInput::default()
        }
    }

    /// Negative — **every** refusal a completion has happens while a status is still choosable.
    ///
    /// This is the test the `Resp::commit` boundary exists for. A check that slipped below the
    /// commit would not fail loudly: the refusal's own status is gone by then, so the response would
    /// go out as the `200` the head already carried and the `<Error>` inside it would be the only
    /// sign. `c-mpu-0020` … `c-mpu-0023` and `c-mpu-0026` would all report green while putting the
    /// wrong status line on the wire, which is precisely the failure this corpus exists to catch —
    /// so the boundary is asserted here rather than trusted to the order of the lines above.
    #[test]
    fn every_completion_refusal_happens_before_the_head_is_committed() {
        let (stub, upload, first, _second) = stub_with_an_upload();
        let refusals = [
            // A part list naming nothing.
            (completion(&upload, vec![]), ErrorCode::INVALID_PART),
            // Descending part numbers.
            (completion(&upload, vec![(2, None), (1, None)]), ErrorCode::INVALID_PART_ORDER),
            // A part number that was never uploaded.
            (completion(&upload, vec![(7, None)]), ErrorCode::INVALID_PART),
            // A digest that is not the digest of the bytes on file.
            (
                completion(&upload, vec![(1, Some("ffffffffffffffffffffffffffffffff"))]),
                ErrorCode::INVALID_PART,
            ),
            // The one-byte part in a non-final position, which is under the floor. The floor is
            // checked before part 3 is looked for, so this is the size refusal and not the
            // missing-part one.
            (completion(&upload, vec![(2, None), (3, None)]), ErrorCode::ENTITY_TOO_SMALL),
        ];
        for (input, code) in refusals {
            let error = stub.complete_multipart_upload(&input).expect_err("a refusal");
            assert_eq!(*error.code(), code);
        }
        // An upload id that names another key is refused too, and before anything else.
        let mut foreign = completion(&upload, vec![(1, Some(&first))]);
        foreign.key = object_key("someone-else");
        assert!(stub.complete_multipart_upload(&foreign).is_err());
    }

    /// Negative — the size floor refuses a short part in the middle and exempts the last one, and
    /// both answers are given before the head is committed.
    ///
    /// The exemption is not a leniency: the object is the concatenation, so every upload whose total
    /// is not a multiple of the floor ends in a short part and applying the floor to it would make
    /// them all uncompletable. The two halves are asserted together because a floor without the
    /// exemption and an exemption without the floor look identical from either one alone.
    #[test]
    fn the_size_floor_refuses_a_short_middle_part_and_exempts_the_last_one() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("conf-bucket", false);
        let upload = fixture.create_upload("conf-bucket", "k");
        fixture.put_part(&upload, 1, vec![0_u8; 8]);
        fixture.put_part(&upload, 2, vec![1_u8; 8]);
        let stub = Stub::new(Arc::new(Mutex::new(fixture)));
        let error = stub
            .complete_multipart_upload(&completion(&upload, vec![(1, None), (2, None)]))
            .expect_err("a refusal");
        assert_eq!(*error.code(), ErrorCode::ENTITY_TOO_SMALL);
        // The same eight-byte part, named alone, is the final part and passes.
        let answer = stub
            .complete_multipart_upload(&completion(&upload, vec![(1, None)]))
            .expect("a committed answer");
        assert!(answer.is_committed());
    }

    /// Positive — a completion with nothing left to refuse commits its head before it assembles.
    ///
    /// The status is the operation's declared one and the output does not exist yet, which is the
    /// whole shape: `Resp::output` answers `None` for a committed answer because there is nothing to
    /// answer with until the work runs.
    #[test]
    fn a_completion_with_nothing_left_to_refuse_commits_its_head() {
        let (stub, upload, first, second) = stub_with_an_upload();
        let answer = stub
            .complete_multipart_upload(&completion(&upload, vec![(1, Some(&first)), (2, Some(&second))]))
            .expect("a committed answer");
        assert!(answer.is_committed());
        assert_eq!(answer.status(), 200);
        assert!(answer.output().is_none());
    }

    /// Negative — every refusal a copy has also happens before its head is committed.
    ///
    /// The source side is the half that matters. AWS draws the line at "before the copy action
    /// starts", and a source that cannot be resolved is discovered before it starts — so a missing
    /// key stays a `404` rather than becoming a `200` whose body says `NoSuchKey`. `c-copy-0026` and
    /// `c-copy-0034` are the cases that would silently change status if this moved.
    #[test]
    fn every_copy_refusal_happens_before_the_head_is_committed() {
        let (stub, _upload, _first, _second) = stub_with_an_upload();
        for source in [
            // A key that is not there.
            "/conf-bucket/missing",
            // A bucket that is not there.
            "/conf-absent/src",
            // A source that names no bucket and key at all.
            "not-a-copy-source",
        ] {
            assert!(stub.copy_object(&copy(source, "dst")).is_err(), "{source}");
        }
        // A copy onto itself that changes nothing is refused as well.
        assert!(stub.copy_object(&copy("/conf-bucket/src", "src")).is_err());
    }

    /// Positive — a copy with nothing left to refuse commits its head before it writes.
    #[test]
    fn a_copy_with_nothing_left_to_refuse_commits_its_head() {
        let (stub, _upload, _first, _second) = stub_with_an_upload();
        let answer = stub
            .copy_object(&copy("/conf-bucket/src", "dst"))
            .expect("a committed answer");
        assert!(answer.is_committed());
        assert_eq!(answer.status(), 200);
        assert!(answer.output().is_none());
    }

    /// Negative — a copy's two condition sets are evaluated against their own object, and neither
    /// tag satisfies the other side's guard.
    ///
    /// This is the rule `c-cond-0027` is about and the rule that case cannot reach: its first
    /// exchange copies the source onto the destination, and from then on the two objects carry the
    /// *same* entity tag, so the tag it goes on to call "the source tag" is by then also the
    /// destination's and satisfies the destination guard honestly. The rule is asserted here
    /// instead, against two objects that stay different, one side varied at a time.
    ///
    /// The failure it guards against is one shared evaluator reading the wrong object's validators.
    /// Both directions matter: the wrong one lets a copy through that the client guarded against,
    /// and the other refuses one the client's guard permitted.
    #[test]
    fn each_side_of_a_copy_is_judged_against_its_own_object() {
        // md5("hello") and md5("original") — two objects that do not share an entity tag.
        const SOURCE_TAG: &str = "\"5d41402abc4b2a76b9719d911017c592\"";
        const TARGET_TAG: &str = "\"919c8b643b7133116b02fc0d9bb7df3f\"";

        let stub = || {
            let mut fixture = Fixture::at(0);
            fixture.declare_bucket("conf-bucket", false);
            fixture.put_object("conf-bucket", "source", StoredObject::new(b"hello".to_vec(), None, 0));
            fixture.put_object("conf-bucket", "target", StoredObject::new(b"original".to_vec(), None, 0));
            Stub::new(Arc::new(Mutex::new(fixture)))
        };
        let request = |source_if_match: &str, if_match: &str| dto::CopyObjectInput {
            copy_source_if_match: Some(source_if_match.to_owned()),
            if_match: Some(if_match.to_owned()),
            ..copy("/conf-bucket/source", "target")
        };

        // Each condition against its own object: both hold, so the copy proceeds.
        assert!(stub().copy_object(&request(SOURCE_TAG, TARGET_TAG)).is_ok());

        // The source's tag offered to the destination guard. The destination is still `original`,
        // so the guard is false and the copy is refused before anything is written.
        let error = stub()
            .copy_object(&request(SOURCE_TAG, SOURCE_TAG))
            .expect_err("the destination condition is false");
        assert_eq!(*error.code(), ErrorCode::PRECONDITION_FAILED);

        // The destination's tag offered to the source guard, which is the direction that reads
        // another object's validators to satisfy a condition on the one being copied.
        let error = stub()
            .copy_object(&request(TARGET_TAG, TARGET_TAG))
            .expect_err("the source condition is false");
        assert_eq!(*error.code(), ErrorCode::PRECONDITION_FAILED);
        assert_eq!(
            elements(&error),
            vec![("Condition", "x-amz-copy-source-if-match".to_owned())],
            "the refusal names the header that carried the failed condition, not its destination twin"
        );
    }

    /// Positive — one conditional header arrived, so the `412` can say which one failed.
    ///
    /// Both spellings are asserted: the destination set is the canonical mixed case a client reads
    /// out of `<Condition>`, and the copy-source set names the `x-amz-` header that actually
    /// carried the condition rather than the destination header of the same shape.
    #[test]
    fn a_single_condition_is_named_by_the_header_that_carried_it() {
        assert_eq!(
            sole_condition(&DESTINATION_CONDITIONS, [false, false, true, false]),
            Some("If-None-Match")
        );
        assert_eq!(sole_condition(&DESTINATION_CONDITIONS, [true, false, false, false]), Some("If-Match"));
        assert_eq!(
            sole_condition(&COPY_SOURCE_CONDITIONS, [true, false, false, false]),
            Some("x-amz-copy-source-if-match")
        );
    }

    /// Negative — a request that carried two conditions, or none, is not attributed to one.
    ///
    /// Picking one of two would mean re-deriving RFC 9110 §13.2.2's precedence in this file, and a
    /// backend that guesses tells the client to fix a header that was holding fine. The element is
    /// dropped instead, which leaves any case that wants it red rather than wrong.
    #[test]
    fn no_condition_is_named_when_the_request_carried_more_than_one() {
        assert_eq!(sole_condition(&DESTINATION_CONDITIONS, [true, false, true, false]), None);
        assert_eq!(sole_condition(&DESTINATION_CONDITIONS, [true, true, true, true]), None);
        assert_eq!(sole_condition(&DESTINATION_CONDITIONS, [false, false, false, false]), None);
    }

    /// Negative — an unnameable condition produces a `412` with no `<Condition>` at all, and above
    /// all with the same `<Message>`. Folding the name into the message would make the two
    /// byte-exact conditional cases differ in the element they are not about.
    #[test]
    fn an_unnamed_precondition_failure_adds_no_element_and_changes_no_message() {
        let anonymous = precondition(None);
        assert!(elements(&anonymous).is_empty());
        assert!(head(&anonymous).is_empty());
        assert_eq!(anonymous.message(), precondition(Some("If-Match")).message());
        assert_eq!(elements(&precondition(Some("If-Match"))), [("Condition", "If-Match".to_owned())]);
    }

    /// A ten-byte object whose entity tag is the one `c-range-0018` sends as its `If-Range`.
    fn ten() -> StoredObject {
        StoredObject::new(b"0123456789".to_vec(), Some("text/plain".to_owned()), 0)
    }

    /// Positive — a `416` carries the length in the head, the same length in the document, and the
    /// range the client asked for, in the order AWS's document writes them.
    ///
    /// The header is never spelled here: `ErrorHeader::UnsatisfiedRange` holds the number and the
    /// framework renders it, which is what makes the header name unwritable by a backend.
    #[test]
    fn an_unsatisfiable_range_reports_the_length_and_the_range_that_was_refused() {
        let error = resolve_range(Some("bytes=20-30"), None, None, &ten()).expect_err("20-30 of ten bytes");
        assert_eq!(head(&error), [("content-range".to_owned(), "bytes */10".to_owned())]);
        assert_eq!(
            elements(&error),
            [
                ("RangeRequested", "bytes=20-30".to_owned()),
                ("ActualObjectSize", "10".to_owned())
            ]
        );
    }

    /// Negative — `<RangeRequested>` is the header's own bytes and never a re-spelling of the
    /// parse.
    ///
    /// This test replaces `an_unsatisfiable_range_invents_no_requested_range`, whose premise no
    /// longer holds: the element used to be omitted because the text did not reach a handler, and
    /// the codec now keeps the header bytes beside the parse. What survives is the rule that test
    /// was really protecting — the value is *echoed*, not reconstructed. Padded and unpadded forms
    /// parse identically and only one of them is what the client wrote, so a document that reports
    /// the tidy form is reporting the server's own reading back as though it were the request.
    #[test]
    fn an_unsatisfiable_range_echoes_the_header_rather_than_re_spelling_the_parse() {
        for raw in ["bytes=20-30", "  bytes=20-30  ", "bytes=20-"] {
            let error = resolve_range(Some(raw), None, None, &ten()).expect_err("out of range");
            assert!(
                elements(&error).contains(&("RangeRequested", raw.to_owned())),
                "{raw:?} was not echoed verbatim"
            );
        }
    }

    /// Positive — an `If-Range` whose validator still matches leaves the range in force.
    #[test]
    fn a_matching_if_range_keeps_the_window_the_client_asked_for() {
        let object = ten();
        let if_range = IfRange::parse(&format!("\"{}\"", object.etag));
        let slice = resolve_range(Some("bytes=0-4"), Some(&if_range), None, &object).expect("a satisfied range");
        assert_eq!((slice.start, slice.end_exclusive), (0, 5));
        assert_eq!(slice.content_range.as_deref(), Some("bytes 0-4/10"));
    }

    /// Negative — a stale or unreadable `If-Range` drops the range and serves the whole object.
    ///
    /// Not a `412`: the header is a switch, and a client told its resumed download failed a
    /// precondition gives up where it should have started again. The unreadable value is here for
    /// the sharper reason — `IfRange::parse` is total precisely so that a validator this server
    /// cannot confirm cannot decay into "no `If-Range` was sent", which would honour the range
    /// against a representation nobody checked and splice two versions of the object together.
    #[test]
    fn a_stale_or_unreadable_if_range_drops_the_range_instead_of_refusing() {
        let object = ten();
        for value in ["\"0000000000000000000000000000dead\"", "*", "not-a-validator"] {
            let if_range = IfRange::parse(value);
            let slice = resolve_range(Some("bytes=0-4"), Some(&if_range), None, &object).expect("the whole object");
            assert_eq!((slice.start, slice.end_exclusive), (0, 10), "{value}");
            assert_eq!(slice.content_range, None, "{value}");
        }
    }

    /// Negative — `Range` and `partNumber` together are refused, and a `partNumber` alone is
    /// refused by name rather than answered as though it had not been sent.
    ///
    /// The second half is the one that matters here: `[setup]` in schema version 1 declares uploads
    /// that are still in progress, so this fixture has no part table for a completed object.
    /// Serving the whole object instead would answer a selector it cannot resolve with a `200` that
    /// looks right.
    #[test]
    fn the_two_byte_selectors_are_refused_together_and_a_part_selector_is_refused_by_name() {
        let object = ten();
        let both = resolve_range(Some("bytes=0-4"), None, Some(2), &object).expect_err("two selectors");
        assert_eq!(*both.code(), ErrorCode::INVALID_REQUEST);
        let part = resolve_range(None, None, Some(2), &object).expect_err("no part table");
        assert_eq!(*part.code(), ErrorCode::NOT_IMPLEMENTED);
    }

    /// Negative — a `404` names the key that missed and nothing else. `<BucketName>` is not added:
    /// the bucket was found, so naming it would report a fact that is not the failure.
    #[test]
    fn a_missing_key_is_reported_by_key_alone() {
        assert_eq!(elements(&no_such_key("missing/key")), [("Key", "missing/key".to_owned())]);
        assert!(head(&no_such_key("missing/key")).is_empty());
    }

    /// Negative — no checksum travels with bytes it does not cover, and none travels unasked.
    ///
    /// The partial case is the one that produces a corruption report from a correct client; the
    /// unasked case is the one that would put a header on every read in the corpus.
    #[test]
    fn a_read_reports_no_checksum_unless_it_was_asked_and_whole() {
        assert_eq!(read_checksum(Some(&dto::ChecksumMode::ENABLED), true, b"123456789"), None);
        assert_eq!(read_checksum(None, false, b"123456789"), None);
        assert_eq!(read_checksum(None, true, b"123456789"), None);
        // A value this build has no constant for is not `ENABLED` by resemblance.
        assert_eq!(read_checksum(Some(&dto::ChecksumMode::custom("enabled")), false, b"123456789"), None);
    }

    /// Positive — a whole read that asked reports the CRC-32 of the bytes it sends, base64 as the
    /// header carries it. Pinned against `crate::crc32`'s published check vector.
    #[test]
    fn a_whole_read_that_asked_reports_the_crc32_of_its_bytes() {
        assert_eq!(
            read_checksum(Some(&dto::ChecksumMode::ENABLED), false, b"123456789").as_deref(),
            Some("y/Q5Jg==")
        );
        assert_eq!(read_checksum(Some(&dto::ChecksumMode::ENABLED), false, b"").as_deref(), Some("AAAAAA=="));
    }

    /// Every spelling the exported parser accepts arrives as a tag rather than as a 400.
    ///
    /// This backend no longer decides what a conditional entity tag is: the assertions below are
    /// about the wiring into [`parse_conditional_etag`], not about the grammar, which
    /// `crates/core` owns and tests.
    #[test]
    fn a_conditional_tag_accepts_every_spelling_the_contract_accepts() {
        assert!(matches!(conditional_tag(Some("\"abc\"")), Ok(Some(_))));
        assert!(matches!(conditional_tag(Some("W/\"abc\"")), Ok(Some(_))));
        assert!(matches!(conditional_tag(Some("abc")), Ok(Some(_))));
        assert!(matches!(conditional_tag(Some("*")), Ok(Some(_))));
        assert!(matches!(conditional_tag(None), Ok(None)));
    }

    /// The list form is refused rather than reduced to its first member.
    ///
    /// The hand-written mirror this file used to carry accepted a list and answered on whichever
    /// member happened to match — an answer to a question the client did not ask. The contract
    /// refuses it, and this backend refuses it with the contract.
    #[test]
    fn a_conditional_tag_refuses_the_list_form() {
        assert!(conditional_tag(Some("\"zzz\", \"abc\"")).is_err());
    }

    #[test]
    fn a_fixture_stamps_the_entity_tag_the_corpus_writes_by_hand() {
        let object = StoredObject::new(b"hello".to_vec(), None, 0);
        assert_eq!(object.etag, "5d41402abc4b2a76b9719d911017c592");
    }

    /// Positive — the window and the header it is described by come from the same decision.
    ///
    /// They used to come from two: the contract rendered `Content-Range` and this file read the
    /// offsets back out of that string, because the outcome's variants could not be named through
    /// the facade. `RangeDecision` can be, so the string is no longer parsed to recover what it was
    /// built from — the last place in this file where a rendering was also an input.
    #[test]
    fn a_window_and_its_content_range_come_from_one_decision() {
        let object = ten();
        let first = resolve_range(Some("bytes=0-4"), None, None, &object).expect("a window");
        assert_eq!((first.start, first.end_exclusive), (0, 5));
        assert_eq!(first.content_range.as_deref(), Some("bytes 0-4/10"));
        let last = resolve_range(Some("bytes=5-9"), None, None, &object).expect("a window");
        assert_eq!((last.start, last.end_exclusive), (5, 10));
        assert_eq!(last.content_range.as_deref(), Some("bytes 5-9/10"));
        // An overlong end is clamped to the object rather than refused, and the header reports the
        // window that was actually served.
        let clamped = resolve_range(Some("bytes=5-99"), None, None, &object).expect("a clamped window");
        assert_eq!((clamped.start, clamped.end_exclusive), (5, 10));
        assert_eq!(clamped.content_range.as_deref(), Some("bytes 5-9/10"));
    }

    #[test]
    fn upload_ids_are_minted_deterministically() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("b", false);
        assert_eq!(fixture.create_upload("b", "k"), "conformance-upload-0001");
        assert_eq!(fixture.create_upload("b", "k"), "conformance-upload-0002");
    }

    /// The s3s#51 check, in the two shapes the corpus separates: a genuine id from another bucket
    /// and a genuine id from another key in the same bucket. Both are `NoSuchUpload`, and a
    /// resolver that only compared the bucket would let the second through.
    #[test]
    fn an_upload_id_resolves_only_against_the_bucket_and_key_that_own_it() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("mine", false);
        fixture.declare_bucket("theirs", false);
        let id = fixture.create_upload("theirs", "someone-elses-object");

        let bucket = |name: &str| BucketName::new(name.to_owned()).expect("a fixture bucket name is valid");
        let key = |name: &str| ObjectKey::new(name.to_owned()).expect("a fixture key is valid");

        assert!(require_upload(&fixture, &id, &bucket("theirs"), &key("someone-elses-object")).is_ok());
        // Same key, wrong bucket.
        let foreign = require_upload(&fixture, &id, &bucket("mine"), &key("someone-elses-object"));
        assert_eq!(foreign.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));
        // Right bucket, wrong key.
        let crossed = require_upload(&fixture, &id, &bucket("theirs"), &key("another-object"));
        assert_eq!(crossed.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));
        // An id nothing minted.
        let invented = require_upload(&fixture, "conformance-upload-9999", &bucket("theirs"), &key("someone-elses-object"));
        assert_eq!(invented.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));
    }

    /// The alphabet and the padding, against values whose encodings are fixed by RFC 4648 §10.
    #[test]
    fn base64_encodes_every_padding_length() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
        // The high bits of the alphabet, which a table with a typo in `+` or `/` would miss.
        assert_eq!(encode_base64(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    #[test]
    fn a_content_md5_that_is_not_the_digest_is_refused() {
        // The digest of the empty body, which is the one value a caller could send by accident.
        assert!(require_content_md5(Some("1B2M2Y8AsgTpgAmY7PhCfg=="), b"").is_ok());
        assert!(require_content_md5(Some("XUFAKrxLKna5cZ2REBfFkg=="), b"hello").is_ok());
        // Absent and empty are the same fact: no claim was made, so there is nothing to refuse.
        assert!(require_content_md5(None, b"hello").is_ok());
        assert!(require_content_md5(Some("   "), b"hello").is_ok());
        let refused = require_content_md5(Some("AAAAAAAAAAAAAAAAAAAAAA=="), b"hello");
        assert_eq!(refused.err().map(|error| error.code().clone()), Some(ErrorCode::BAD_DIGEST));
    }

    #[test]
    fn a_delimiter_folds_a_key_into_a_common_prefix() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("b", false);
        fixture.put_object("b", "a/1", StoredObject::new(b"1".to_vec(), None, 0));
        fixture.put_object("b", "top", StoredObject::new(b"t".to_vec(), None, 0));
        let page = paginate(&fixture, "b", "", Some("/"), None, 1000);
        assert_eq!(page.common_prefixes, ["a/"]);
        assert_eq!(page.keys, ["top"]);
    }

    /// A marker that names a folded prefix drops *every* key underneath it, not just the one whose
    /// spelling produced it. Resuming on the key alone repeats `b/1.txt` on the second page, and
    /// no single-response assertion can see that.
    #[test]
    fn a_marker_naming_a_common_prefix_resumes_past_every_key_under_it() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("b", false);
        for key in ["a/1.txt", "b/1.txt", "top.txt"] {
            fixture.put_object("b", key, StoredObject::new(b"x".to_vec(), None, 0));
        }
        let first = paginate(&fixture, "b", "", Some("/"), None, 2);
        assert!(first.truncated);
        assert_eq!(first.next.as_deref(), Some("b/"));
        let second = paginate(&fixture, "b", "", Some("/"), Some("b/"), 2);
        assert_eq!(second.keys, ["top.txt"]);
        assert!(second.common_prefixes.is_empty());
        assert_eq!(second.count(), 1);
    }

    /// `max-keys=0` is an empty page, not a truncated one: a client told `true` asks for the next
    /// page of nothing for ever.
    #[test]
    fn a_zero_page_size_is_not_a_truncation() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("b", false);
        fixture.put_object("b", "k", StoredObject::new(b"x".to_vec(), None, 0));
        let page = paginate(&fixture, "b", "", None, None, 0);
        assert_eq!(page.count(), 0);
        assert!(!page.truncated);
        assert_eq!(page.next, None);
    }

    /// The cursor round-trips, and every spelling this stub did not mint is refused rather than
    /// read as some other position.
    #[test]
    fn a_continuation_token_round_trips_and_refuses_everything_else() {
        let token = mint_token("a/2.txt");
        assert_ne!(token, "a/2.txt", "a cursor a client can read is a cursor a client can forge");
        assert_eq!(read_token(&token).as_deref(), Some("a/2.txt"));
        assert_eq!(read_token(&format!("{token}X")), None);
        assert_eq!(read_token("../../etc/passwd"), None);
        assert_eq!(read_token("\u{ff}\u{fe}\u{0}\u{1}"), None);
        // The ceiling is the contract's, and one byte over it is refused before anything decodes.
        assert_eq!(read_token(&"A".repeat(rustfs_gateway::MAX_CURSOR_BYTES + 1)), None);
        // The first page of an empty prefix resumes from the empty marker, which must survive too.
        assert_eq!(read_token(&mint_token("")).as_deref(), Some(""));
    }

    /// A versioned bucket keeps what `[setup]` declared, in the order it declared it; an
    /// unversioned one keeps one `null` version and no history at all.
    #[test]
    fn versions_are_the_setup_entries_and_nothing_more() {
        let mut fixture = Fixture::at(7);
        fixture.declare_bucket("v", true);
        fixture.declare_bucket("u", false);
        fixture.put_object("v", "doc", StoredObject::new(b"1".to_vec(), None, 7));
        fixture.put_object("v", "doc", StoredObject::new(b"2".to_vec(), None, 7));
        fixture.put_object("v", "gone", StoredObject::new(b"g".to_vec(), None, 7));
        fixture.remove_object("v", "gone");
        fixture.put_object("u", "doc", StoredObject::new(b"1".to_vec(), None, 7));
        fixture.put_object("u", "doc", StoredObject::new(b"2".to_vec(), None, 7));

        let versioned = fixture.versions_in("v");
        // Two versions of `doc`, then the delete marker over `gone` and the version it hides.
        assert_eq!(versioned.len(), 4);
        assert_eq!(versioned.first().map(|entry| entry.key), Some("doc"));
        assert!(versioned.first().is_some_and(|entry| entry.is_latest));
        assert!(versioned.get(1).is_some_and(|entry| !entry.is_latest));
        assert!(versioned.get(2).is_some_and(|entry| entry.key == "gone" && entry.is_latest));
        assert!(versioned.get(2).is_some_and(|entry| entry.version.object.is_none()));
        assert!(versioned.get(3).is_some_and(|entry| entry.version.object.is_some()));
        // The delete marker hides the key from a plain listing and from a read, and only from those.
        assert_eq!(fixture.keys_in("v"), ["doc"]);
        assert!(fixture.object("v", "gone").is_none());

        let unversioned = fixture.versions_in("u");
        assert_eq!(unversioned.len(), 1);
        assert_eq!(unversioned.first().map(|entry| entry.version.version_id.as_str()), Some(UNVERSIONED));
    }

    /// Negative — an upload-id marker that is not an id this service issued is refused by shape,
    /// before it is compared against anything.
    #[test]
    fn an_upload_id_marker_is_recognised_by_shape() {
        assert!(is_minted_upload_id("conformance-upload-0001"));
        assert!(!is_minted_upload_id("conformance-upload-"));
        assert!(!is_minted_upload_id("../../../etc/passwd"));
        assert!(!is_minted_upload_id("conformance-upload-00x1"));
    }

    /// The version suffix is split off the raw value, so a key whose own bytes spell the separator
    /// survives. Decoding first makes the two indistinguishable and copies a different object.
    #[test]
    fn a_copy_source_splits_its_version_before_it_decodes_anything() {
        let source = parse_copy_source("bucket/a%3Fb?versionId=v1").expect("parses");
        assert_eq!(source.key.as_str(), "a?b");
        assert_eq!(source.version_id.as_deref(), Some("v1"));
        // The same bytes with no raw `?` are one key and no version at all.
        let literal = parse_copy_source("bucket/a%3FversionId%3Dv1").expect("parses");
        assert_eq!(literal.key.as_str(), "a?versionId=v1");
        assert_eq!(literal.version_id, None);
    }

    /// A key decodes exactly once, and a plus sign is a plus sign: this is a path, not a form.
    #[test]
    fn a_copy_source_key_decodes_once_and_keeps_its_plus() {
        let source = parse_copy_source("/bucket/na%C3%AFve%20%E2%82%AC%26a%2Bb.txt").expect("parses");
        assert_eq!(source.key.as_str(), "naïve €&a+b.txt");
        assert_eq!(source.bucket.as_str(), "bucket");
        // A traversal spelling is ordinary key bytes, never a path.
        assert_eq!(
            parse_copy_source("/bucket/../../etc/passwd").expect("parses").key.as_str(),
            "../../etc/passwd"
        );
    }

    /// Both S3 ARN spellings resolve, and every other ARN is refused rather than demoted to a
    /// bucket name — a demotion turns into a redirect the moment somebody creates that bucket.
    #[test]
    fn the_two_s3_arns_parse_and_every_other_arn_is_refused() {
        let access_point = parse_copy_source("arn:aws:s3:us-east-1:1:accesspoint/my-ap/object/dir/key.txt").expect("parses");
        assert_eq!((access_point.bucket.as_str(), access_point.key.as_str()), ("my-ap", "dir/key.txt"));
        let outposts =
            parse_copy_source("arn:aws:s3-outposts:us-east-1:1:outpost/op-1/bucket/src-bucket/object/k").expect("parses");
        assert_eq!((outposts.bucket.as_str(), outposts.key.as_str()), ("src-bucket", "k"));
        assert!(parse_copy_source("arn:aws:iam::1:user/bob").is_err());
    }

    /// Negative — every spelling that names no object is refused, and a non-UTF-8 decode is a
    /// refusal rather than a panic.
    #[test]
    fn a_copy_source_that_names_no_object_is_refused_without_faulting() {
        for raw in [
            "",
            "bucket",
            "bucket/",
            "/bucket",
            "bucket/a?b",
            "bucket/a?versionId=",
            "bucket/%FF%FE%FD",
        ] {
            assert!(parse_copy_source(raw).is_err(), "{raw}");
        }
    }

    /// A span carries `end - start + 1` bytes, and the two implicit-endpoint forms mean what they
    /// mean for a read.
    #[test]
    fn a_copied_span_is_end_minus_start_plus_one() {
        assert_eq!(resolve_copy_span(Some("bytes=0-9"), 10).expect("resolves").map(|s| s.len()), Some(10));
        assert_eq!(resolve_copy_span(Some("bytes=-5"), 10).expect("resolves").map(|s| s.len()), Some(5));
        assert_eq!(resolve_copy_span(Some("bytes=3-"), 10).expect("resolves").map(|s| s.len()), Some(7));
        // No header copies the whole source, and a zero-byte source is not an arithmetic edge.
        assert_eq!(resolve_copy_span(None, 0).expect("resolves"), None);
    }

    /// Negative — the rule a copy range keeps and a read range does not, now asserted through the
    /// exported contract rather than beside it.
    ///
    /// Every one of these is `InvalidArgument`: the header names a length the client committed the
    /// part to, so a span the source cannot satisfy is a bad argument and not a window that could
    /// not be served. The overlong end is the one this backend used to clamp — a part ninety-one
    /// bytes short with a `200` attached, which is the failure `c-copy-0036` exists for.
    #[test]
    fn a_span_the_source_cannot_satisfy_in_full_is_refused_rather_than_trimmed() {
        for (header, source_len) in [
            ("bytes=100-200", 10),
            ("bytes=0-100", 10),
            ("bytes=-100", 10),
            ("bytes=0-1,5-6", 10),
            ("bytes=0-0", 0),
            ("bytes=nonsense", 10),
        ] {
            let error = resolve_copy_span(Some(header), source_len).expect_err("refused");
            assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT, "{header}");
        }
    }

    /// An ownership assertion the fixtures never declared is refused, not assumed to hold. This is
    /// the stage both published advisories on this family were missing.
    #[test]
    fn a_source_ownership_assertion_is_refused_rather_than_assumed() {
        assert!(confirm_source_owner(None).is_ok());
        assert!(confirm_source_owner(Some("000000000000")).is_err());
    }

    /// An unrecognised directive is not silently the default: a client with a typo would otherwise
    /// get the source's metadata while believing it asked for the request's.
    #[test]
    fn a_directive_is_read_exactly_or_refused() {
        assert_eq!(directive_of(None, "x").ok(), Some(MetadataFrom::Source));
        assert_eq!(directive_of(Some("COPY"), "x").ok(), Some(MetadataFrom::Source));
        assert_eq!(directive_of(Some("REPLACE"), "x").ok(), Some(MetadataFrom::Request));
        for value in ["replace", "Replace", "REPLACE ", "", "COPY_ALL"] {
            assert!(directive_of(Some(value), "x").is_err(), "{value}");
        }
    }

    /// A delete in a versioned bucket names the marker it recorded; an unversioned one names
    /// nothing, because there is no version for a client to come back for.
    #[test]
    fn a_versioned_delete_names_the_marker_it_recorded() {
        let mut fixture = Fixture::at(7);
        fixture.declare_bucket("v", true);
        fixture.declare_bucket("u", false);
        fixture.put_object("v", "doc", StoredObject::new(b"1".to_vec(), None, 7));
        fixture.put_object("u", "doc", StoredObject::new(b"1".to_vec(), None, 7));
        let marker = fixture.remove_object("v", "doc").expect("a marker");
        assert!(
            fixture
                .version("v", "doc", &marker)
                .is_some_and(|version| version.object.is_none())
        );
        assert_eq!(fixture.remove_object("u", "doc"), None);
    }

    /// An empty delimiter is no delimiter: folding on it would put every key under one prefix.
    #[test]
    fn an_empty_delimiter_folds_nothing() {
        assert_eq!(delimiter_of(Some("")), None);
        assert_eq!(delimiter_of(Some("/")), Some("/"));
        assert_eq!(fold("xxABtail", "", Some("AB")).as_deref(), Some("xxAB"));
        assert_eq!(fold("xxAother", "", Some("AB")), None);
    }
}
