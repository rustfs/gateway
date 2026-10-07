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
//! NOT responsible for: production durability or scheduling, lifecycle, replication, encryption,
//! or any other S3 semantic a case does not assert. Its test-only conditional-write rendezvous
//! makes an optimistic storage race deterministic; it does not model a production scheduler.
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
//! * **A cursor is authenticated, not merely checksummed.** `NextContinuationToken` is the
//!   position it resumes from, carried under an HMAC over that position *and over the listing it
//!   belongs to* — see [`crate::token`]. A token that was altered, truncated, extended, replayed
//!   against another bucket or prefix, or composed by a client from scratch is *refused* rather
//!   than read as some other position. The unkeyed checksum this replaced could not do the last of
//!   those: every input to it was public, so recomputing it was the forgery.
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
//! # The copy half and its consumed authorization proof
//!
//! `CopyObject` and `UploadPartCopy` name a second object. Their live handler path reads the
//! framework's `CopySourceResources` and resolves it with the `AuthorizedRead` proof carried by
//! the same `Req`; it never parses the header again. `parse_copy_source` remains only for focused
//! fixture unit tests that exercise legacy edge cases directly. The copy range likewise delegates
//! to the shared [`resolve_copy_range`] contract.
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
//! five go through `require_upload`, which resolves the id **against the bucket and the key of
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
//! and a non-final part under `MIN_PART_BYTES` is `EntityTooSmall`, because the object is the
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
use std::ops::Bound;
use std::sync::{Arc, Mutex};

use rustfs_gateway::dto;
use rustfs_gateway::{
    AclHeaders, AclInput, AclRejection, AclTarget, BucketName, ByteStream, ChecksumAlgorithm, ChecksumSpec,
    ChecksumType as PackedChecksumType, ConditionalOutcome, CopyRange, CopySourceRejection, ETag, ErrorCode, FailedCondition,
    GranteeType, Handler, HandlerError, HandlerErrorContext, HandlerResult, IfRange, MissingObject, ObjectKey, ObjectValidators,
    Operation, PRECONDITION_FAILED_MESSAGE, PreconditionRejection, Preconditions, REGION_MATCH_POLICY, RangeDecision,
    RangeSelectors, RecordedUpload, RegionLabel, RegionSet, Req, RequestKind, ResolvedUploadId, ResourceVisibility, Resp,
    RestoreState, RestoreStatus, SseEnforced, TagScope, TaggingRejection, Timestamp, UploadIdClaim, canonicalize_grantee,
    collect, completion_failure_retains_upload, conditional_write_guards_before_mutation, copy_source_guards_before_target_write,
    copy_source_if_match_miss_proceeds, copy_target_uses_source_validators, encryption_delete_absent_succeeds, evaluate,
    evaluate_range, format_optional_restore_status, object_lock_requires_enabled_bucket, parse_conditional_etag,
    parse_tagging_header, permanent_redirect_for, refuse_blocked_encryption_type, resolve_copy_range,
    resolve_input as resolve_acl_input, resolve_location_constraint, resolve_part, resolve_upload, select_scan_bytes,
    select_uses_event_stream, validate_accelerate, validate_cors, validate_encryption, validate_legal_hold, validate_lifecycle,
    validate_lock_configuration, validate_logging, validate_notification, validate_object_write_lock, validate_policy,
    validate_public_access_block, validate_replication, validate_request_payment, validate_restore, validate_retention,
    validate_select, validate_tag_set, validate_versioning, validate_website,
};

mod committed;
mod conditional_write;
mod copy_checksum;
#[cfg(test)]
mod crc32c_tests;
mod handlers_bucket;
mod handlers_object;
#[cfg(test)]
mod pagination_properties;
mod select_answer;

use committed::{ArmedFault, COMPLETE_MULTIPART_UPLOAD, COPY_OBJECT, CommittedFault, head as committed_head};
pub use committed::{COMMITTED_OPERATIONS, UnreportableFault};
use conditional_write::{ConditionalRaceCoordinator, put_object};

/// The canonical user id every listing reports as the owner.
///
/// Fixed rather than random, and shaped like the 64 hex characters AWS uses, so that a golden can
/// redact `<ID>` once and a run compares byte for byte against itself.
pub const OWNER_ID: &str = "3f6e2b1c4a8d90e7b5c31f2a6d80e4c97b1a3d5f8e206c4b7a9d1e3f5c7b9a0d";

/// The display name that accompanies [`OWNER_ID`].
pub const OWNER_DISPLAY_NAME: &str = "conformance";
use crate::token::TokenScope;

/// The version id of a key in a bucket that was never versioned. S3's own spelling.
pub const UNVERSIONED: &str = "null";

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
    /// The access control policy a `PutObjectAcl` stored, canonicalised: every grantee already
    /// carries the `xsi:type` a read will write back as an attribute.
    ///
    /// `None` is not an observable state — every object has an ACL from the moment it exists —
    /// so the read answers the owner's `FULL_CONTROL` for it rather than a `404`, which is what
    /// makes this family the only object subresource with no unconfigured error. Held on the
    /// object beside the tag set, and for the same reason: `[setup.objects]` declares no
    /// per-version ACL, so what a read answers is always either the default or something a
    /// request wrote.
    pub acl: Option<dto::AccessControlPolicy>,
    /// The tag set, in the order the request that wrote it listed the pairs.
    ///
    /// A `Vec` rather than a map, and ordered rather than sorted, because the tag set is what the
    /// writer sent: `x-amz-tagging: a=1&b=2` and a `<Tagging>` document both carry an order, and a
    /// stub that re-sorted them would be answering from a decision of its own. Duplicate keys never
    /// reach here — `read_tagging_header` and `tag_pairs` refuse them — so the sequence is a
    /// map in everything but lookup cost, and ten pairs is the ceiling AWS documents.
    ///
    /// It sits on the *version* rather than beside the key, which is what lets `?tagging&versionId`
    /// answer and write the version the request named: relabelling one version leaves every other
    /// version's set exactly where it was.
    pub tags: Vec<(String, String)>,
    /// The retention document a retention write stored, exactly as validated — never invented,
    /// and never *evaluated*: whether this fixture's deletes and overwrites honour it is
    /// enforcement, which is deliberately not this fixture's. `None` is the observable state the
    /// object-level `404 NoSuchObjectLockConfiguration` reports. Held on the object, and so on the
    /// [`StoredVersion`] that owns it: a write naming `versionId` lands on that version
    /// (`lock_state_of_mut`), an object write carrying the `x-amz-object-lock-*` headers sets it on
    /// the version it creates, and `[setup.objects]` declares none, so every value here was
    /// written by a request.
    pub retention: Option<dto::ObjectLockRetention>,
    /// The legal-hold document a hold write stored. `None` is "never set", which answers the
    /// same object-level 404 as an unset retention — not a `200` carrying `OFF`, which a
    /// compliance audit would read as a hold that exists. Per version, like the retention.
    pub legal_hold: Option<dto::ObjectLockLegalHold>,
    /// The state of an archive retrieval on this copy, or `None` when none was ever asked for.
    ///
    /// `None` is what makes `x-amz-restore` absent, which is a fact a client reads: an object
    /// with no header was never retrieved, and one carrying `ongoing-request="false"` is back.
    /// Held on the object, so on the version that owns it: a retrieval that names a version changes
    /// that version's state and no other one's.
    pub restore: Option<RestoreStatus>,
    /// The storage class the writer named, or `STANDARD`.
    pub storage_class: String,
    /// The unquoted MD5 entity tag of `body`.
    pub etag: String,
    /// The full-object checksum a write supplied, including its algorithm.
    ///
    /// [`StoredObject::new`] stamps CRC32 for objects established directly by `[setup]`, preserving
    /// the fixture's existing checksum-bearing setup contract. A request that supplies another
    /// algorithm replaces it only after the ingest pipeline has verified the body.
    pub checksum: Option<ChecksumSpec>,
    /// Whether a write named [`Self::checksum`]; only such a one is reported by a copy (`c-copy-0044`).
    pub checksum_supplied: bool,
    /// The instant the case pinned, in Unix seconds.
    pub last_modified: i64,
    /// The length of each part the object was completed from, in part order, or empty for an
    /// object that never went through a multipart upload.
    ///
    /// Empty is not "one part": a `partNumber` read against an object written by a single `PUT`
    /// is refused here rather than answered with the whole object, because this fixture has no
    /// evidence about what S3 does with a part selector on an object that has no parts, and
    /// inventing one would be a claim a case could go green against.
    ///
    /// It lives on the version rather than beside the key for the same reason the tag set does:
    /// an overwrite replaces it, so a multipart object replaced by a single `PUT` stops having
    /// parts at exactly the moment the `PUT` lands.
    pub part_lengths: Vec<u64>,
}

impl StoredObject {
    /// Builds an object and stamps its entity tag.
    #[must_use]
    pub fn new(body: Vec<u8>, content_type: Option<String>, last_modified: i64) -> StoredObject {
        let etag = crate::md5::hex_digest(&body);
        let checksum = ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &crate::crc32::digest(&body)).ok();
        StoredObject {
            body,
            content_type,
            storage_class: "STANDARD".to_owned(),
            etag,
            checksum,
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
/// exactly as the versioning flag is. A bucket deletion removes the whole entry, so the
/// configuration documents die with the bucket rather than haunting a name that is later reused.
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
    /// `region = "..."` when the case placed the bucket somewhere other than the fixture's home
    /// region. `None` means the home region, so the common case declares nothing.
    region: Option<String>,
    /// The bucket exists but belongs to somebody else. Not expressible in `[setup]` — the schema
    /// declares no account — so only the integration tests set it, through
    /// [`Fixture::declare_bucket_owned_by_other`].
    owned_by_other: bool,
    /// The stored lifecycle configuration, written by `PutBucketLifecycleConfiguration` within
    /// the case, together with the transition-minimum-object-size choice the write carried.
    /// `None` is the observable state `NoSuchLifecycleConfiguration` reports; there is no "empty
    /// document" state, because the decoder refuses a document with no rule. It lives in
    /// `BucketState` so that deleting the bucket deletes the document with it.
    lifecycle: Option<StoredLifecycle>,
    /// The stored default-encryption configuration, written by `PutBucketEncryption` within the
    /// case. `None` is the observable state `ServerSideEncryptionConfigurationNotFoundError`
    /// reports; there is no "empty document" state, because the decoder refuses a document with
    /// no rule. It lives in `BucketState` so that deleting the bucket deletes the document with
    /// it — a recreated bucket inheriting the previous owner's KMS key would encrypt the new
    /// owner's data to somebody else's key.
    encryption: Option<dto::ServerSideEncryptionConfiguration>,
    /// The stored replication configuration, written by `PutBucketReplication` within the case.
    /// `None` is the observable state `ReplicationConfigurationNotFoundError` reports; there is
    /// no "empty document" state, because the decoder refuses a document with no rule. It lives
    /// in `BucketState` so that deleting the bucket deletes the document with it — a recreated
    /// bucket inheriting the previous owner's replication rules would ship the new owner's data
    /// to somebody else's destination bucket under somebody else's IAM role.
    replication: Option<dto::ReplicationConfiguration>,
    /// The stored object-lock configuration, written by `PutObjectLockConfiguration` within the
    /// case. `None` with `object_lock` false is the observable state
    /// `ObjectLockConfigurationNotFoundError` reports; `None` with `object_lock` true answers
    /// the Enabled-only document a creation-time declaration implies. It lives in `BucketState`
    /// so that deleting the bucket deletes the document with it — a recreated bucket inheriting
    /// the previous owner's WORM configuration would lock the new owner's data to somebody
    /// else's compliance rules.
    lock_configuration: Option<dto::ObjectLockConfiguration>,
    /// The stored access control policy, written by `PutBucketAcl` within the case and already
    /// canonicalised.
    ///
    /// `None` is **not** an observable state here, unlike every other document in this
    /// structure: a bucket always has an ACL, so `None` reads back as the owner's
    /// `FULL_CONTROL` rather than as a `404`. It still lives in `BucketState` so that deleting
    /// the bucket deletes the policy with it — a recreated bucket inheriting the previous
    /// owner's grants would hand the new owner's data to whoever the last one shared it with,
    /// and unlike an inherited lifecycle or encryption document that one is silent.
    acl: Option<dto::AccessControlPolicy>,
    /// The stored versioning document, written by `PutBucketVersioning` within the case.
    ///
    /// `None` is the never-versioned state, and the read answers it with an empty
    /// `<VersioningConfiguration/>` and a `200` — **not** a `404` and not
    /// `<Status>Suspended</Status>`, which is a bucket that was versioned and stopped. It lives
    /// in `BucketState` so that deleting the bucket deletes the state with it: a recreated bucket
    /// that inherited `Suspended` would report a version history the new owner never had.
    versioning: Option<dto::VersioningConfiguration>,
    /// The stored acceleration document. `None` reads back as an empty
    /// `<AccelerateConfiguration/>` with a `200`.
    accelerate: Option<dto::AccelerateConfiguration>,
    /// The stored request-payment document. `None` reads back as `<Payer>BucketOwner</Payer>` —
    /// the *default*, not an empty document, because every bucket has a payer. Inheriting
    /// `Requester` across a recreation would bill the new owner's readers.
    request_payment: Option<dto::RequestPaymentConfiguration>,
    /// The stored logging document. `None` reads back as an empty `<BucketLoggingStatus/>`. A
    /// recreated bucket that inherited one would keep writing the new owner's access log to the
    /// previous owner's target bucket, which is a disclosure and not merely a stale setting.
    logging: Option<dto::BucketLoggingStatus>,
    /// The stored notification document. `None` reads back as an empty
    /// `<NotificationConfiguration/>`; inheriting one across a recreation would publish the new
    /// owner's object events to the previous owner's topic.
    notification: Option<dto::NotificationConfiguration>,
    /// The stored website document. `None` is the observable state
    /// `NoSuchWebsiteConfiguration` reports — one of the three reads in this band that answer a
    /// `404`, each with its own literal.
    website: Option<dto::WebsiteConfiguration>,
    /// The stored bucket policy, byte for byte as the write sent it. `None` is the observable
    /// state `NoSuchBucketPolicy` reports, for both the policy read and the policy-status read.
    /// It is stored as the original text rather than as a parse, because the read is documented
    /// to answer the document that was written and a re-serialisation is a different document.
    /// A recreated bucket inheriting one would grant the previous owner's principals access to
    /// the new owner's data, which is the sharpest inheritance in the whole band.
    policy: Option<String>,
    /// Whether the stored policy makes the bucket public, as `GetBucketPolicyStatus` reports it.
    ///
    /// Set by the case through [`Fixture::set_policy`], never computed: this workspace contains
    /// no policy evaluator and inventing one in a test fixture would be a second implementation
    /// of the thing the family's fence says does not exist here.
    policy_is_public: bool,
    /// The stored public-access block. `None` is the observable state
    /// `NoSuchPublicAccessBlockConfiguration` reports — the third distinct `404` literal, and the
    /// one whose inheritance would silently *unblock* public access on a recreated bucket.
    public_access_block: Option<dto::PublicAccessBlockConfiguration>,
}

/// A bucket's lifecycle document exactly as one write stored it.
#[derive(Debug, Clone)]
struct StoredLifecycle {
    /// The document, rule order preserved: the read-back is a byte-level golden.
    configuration: dto::BucketLifecycleConfiguration,
    /// The `x-amz-transition-default-minimum-object-size` the write carried, echoed by the read.
    /// `None` when the write did not name one: the fixture invents no default, because a value
    /// the client never sent cannot be asserted byte for byte.
    minimum_object_size: Option<dto::TransitionDefaultMinimumObjectSize>,
}

/// The region the in-process deployment serves, which is also the one every case signs for.
pub const HOME_REGION: &str = "us-east-1";

/// The state one case runs against.
#[derive(Debug, Default)]
pub struct Fixture {
    buckets: BTreeMap<String, BucketState>,
    objects: BTreeMap<(String, String), Vec<StoredVersion>>,
    /// Monotonic per-key storage generations used by conditional-write compare-and-swap.
    object_generations: BTreeMap<(String, String), u64>,
    /// Test-only rendezvous shared by the socket transport and object handlers.
    conditional_races: Arc<ConditionalRaceCoordinator>,
    uploads: BTreeMap<String, StoredUpload>,
    next_upload: u32,
    next_version: u32,
    /// The instant the case pinned, stamped onto everything this fixture mints.
    pub now: i64,
    /// The deployment's own region: where an unconstrained creation lands, what a `HeadBucket`
    /// success reports, and the yardstick a bucket's own `region` is measured against for the
    /// 301. Defaults to [`HOME_REGION`]; the integration tests move it to exercise the non-us-east-1
    /// half of the status matrix.
    pub home_region: String,
    /// The failure `[setup.fault]` armed, if the case armed one.
    committed_fault: Option<CommittedFault>,
    /// The key this instance's continuation tokens are authenticated under.
    ///
    /// Per fixture, and per process. A token minted by one run of the suite is not a token for the
    /// next one and not a token for the fixture beside it, which is the only version of "a value
    /// this service issued" that means anything: the alternative is a value anybody who has read
    /// this file can issue too. See [`crate::token`].
    token_secret: crate::token::TokenSecret,
}

impl Fixture {
    /// An empty fixture whose clock reads `now`.
    #[must_use]
    pub fn at(now: i64) -> Fixture {
        Fixture {
            now,
            home_region: HOME_REGION.to_owned(),
            ..Fixture::default()
        }
    }

    /// When a copy retrieved *now* would lapse, as the RFC 1123 string `x-amz-restore` carries.
    ///
    /// One day past the case's own clock rather than a hard-coded date, so the value a case
    /// asserts byte for byte is a function of the instant that case pinned. `Days` from the
    /// request is deliberately not consulted: the request asks for a lifetime and this stub does
    /// not model one, and reading the number without honouring it would be the more misleading of
    /// the two. The fallback is the clock itself, reachable only from an instant `Timestamp`
    /// refuses to render, which no case's `[clock]` can produce.
    #[must_use]
    pub fn restore_expiry(&self) -> String {
        const ONE_DAY_SECONDS: i64 = 24 * 60 * 60;
        Timestamp::from_secs(self.now.saturating_add(ONE_DAY_SECONDS))
            .render(rustfs_gateway::TimestampFormat::HttpDate)
            .unwrap_or_else(|_| String::new())
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

    /// Records `setup.buckets[].region` for a bucket that lives outside the home region.
    ///
    /// A request addressed to this deployment for such a bucket is the 301 case: the bucket
    /// exists, but not here.
    pub fn set_bucket_region(&mut self, name: &str, region: &str) {
        self.buckets.entry(name.to_owned()).or_default().region = Some(region.to_owned());
    }

    /// The region a bucket was explicitly placed in, when it is not the home region's default.
    #[must_use]
    pub fn bucket_region(&self, name: &str) -> Option<&str> {
        self.buckets.get(name).and_then(|bucket| bucket.region.as_deref())
    }

    /// Declares a bucket that exists under somebody else's account.
    ///
    /// `[setup]` cannot say this — the schema declares no account — so only the integration tests
    /// reach it. It is what makes `BucketAlreadyExists` distinguishable from
    /// `BucketAlreadyOwnedByYou` against this fixture.
    pub fn declare_bucket_owned_by_other(&mut self, name: &str) {
        self.buckets.entry(name.to_owned()).or_default().owned_by_other = true;
    }

    /// Whether a bucket belongs to somebody else.
    #[must_use]
    pub fn is_owned_by_other(&self, name: &str) -> bool {
        self.buckets.get(name).is_some_and(|bucket| bucket.owned_by_other)
    }

    /// Whether a bucket holds nothing a deletion would destroy.
    ///
    /// Versions count even when a delete marker hides them — S3 refuses to delete a bucket whose
    /// version history is non-empty. An in-progress multipart upload does not: it is not an
    /// object, and a general purpose bucket holding only uploads is deleted with them
    /// (`q-bkt-0008`, `c-bkt-0034`, rustfs/gateway#806).
    #[must_use]
    pub fn bucket_is_empty(&self, name: &str) -> bool {
        !self
            .objects
            .iter()
            .any(|((bucket, _), versions)| bucket == name && !versions.is_empty())
    }

    /// Whether a bucket has object lock on, however it got there.
    ///
    /// Two roads reach the same state: `setup.buckets[].object_lock` declares it at creation, and
    /// `PutObjectLockConfiguration` turns it on afterwards — which is what AWS documents that
    /// write as doing. A reader that consulted only the declaration would report a bucket the
    /// case just locked as unlocked, so both are folded here rather than at each call site.
    #[must_use]
    pub fn has_object_lock(&self, name: &str) -> bool {
        self.buckets
            .get(name)
            .is_some_and(|bucket| bucket.object_lock || bucket.lock_configuration.is_some())
    }

    /// Installs a bucket's object-lock document, replacing whatever was there.
    /// `PutObjectLockConfiguration` only.
    pub fn set_lock_configuration(&mut self, name: &str, configuration: dto::ObjectLockConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().lock_configuration = Some(configuration);
    }

    /// The document the lock read answers, or `None` for a bucket that never enabled object lock.
    ///
    /// A bucket declared `object_lock = true` at creation but never written to answers the
    /// `Enabled`-only document, because that is exactly what its state is: locking on, no default
    /// retention. Synthesising it here rather than at creation keeps `[setup]` a declaration of
    /// state instead of a hidden `PutObjectLockConfiguration` nobody sent.
    #[must_use]
    fn lock_configuration(&self, name: &str) -> Option<dto::ObjectLockConfiguration> {
        let bucket = self.buckets.get(name)?;
        if let Some(stored) = bucket.lock_configuration.as_ref() {
            return Some(stored.clone());
        }
        bucket.object_lock.then_some(dto::ObjectLockConfiguration {
            object_lock_enabled: Some(dto::ObjectLockEnabled::ENABLED),
            rule: None,
        })
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

    /// Installs a bucket's lifecycle document, replacing whatever was there.
    /// `PutBucketLifecycleConfiguration` only.
    pub fn set_lifecycle(
        &mut self,
        name: &str,
        configuration: dto::BucketLifecycleConfiguration,
        minimum_object_size: Option<dto::TransitionDefaultMinimumObjectSize>,
    ) {
        self.buckets.entry(name.to_owned()).or_default().lifecycle = Some(StoredLifecycle {
            configuration,
            minimum_object_size,
        });
    }

    /// The stored lifecycle document with its transition-minimum choice, or `None` for a bucket
    /// that never had one.
    #[must_use]
    fn lifecycle(&self, name: &str) -> Option<&StoredLifecycle> {
        self.buckets.get(name).and_then(|bucket| bucket.lifecycle.as_ref())
    }

    /// Removes a bucket's lifecycle document. Idempotent on purpose: the delete answers `204`
    /// whether or not a document was there, so this reports nothing.
    pub fn clear_lifecycle(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.lifecycle = None;
        }
    }

    /// Installs a bucket's default-encryption document, replacing whatever was there.
    /// `PutBucketEncryption` only.
    pub fn set_encryption(&mut self, name: &str, configuration: dto::ServerSideEncryptionConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().encryption = Some(configuration);
    }

    /// The stored default-encryption document, or `None` for a bucket that never had one.
    #[must_use]
    fn encryption(&self, name: &str) -> Option<&dto::ServerSideEncryptionConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.encryption.as_ref())
    }

    /// Removes a bucket's default-encryption document. Idempotent on purpose: the delete answers
    /// `204` whether or not a document was there, so this reports nothing.
    pub fn clear_encryption(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.encryption = None;
        }
    }

    /// Installs a bucket's replication document, replacing whatever was there.
    /// `PutBucketReplication` only.
    pub fn set_replication(&mut self, name: &str, configuration: dto::ReplicationConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().replication = Some(configuration);
    }

    /// The stored replication document, or `None` for a bucket that never had one.
    #[must_use]
    fn replication(&self, name: &str) -> Option<&dto::ReplicationConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.replication.as_ref())
    }

    /// Removes a bucket's replication document. Idempotent on purpose: the delete answers `204`
    /// whether or not a document was there, so this reports nothing.
    pub fn clear_replication(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.replication = None;
        }
    }

    /// Installs a bucket's access control policy, replacing whatever was there.
    /// `PutBucketAcl` only.
    pub fn set_bucket_acl(&mut self, name: &str, policy: dto::AccessControlPolicy) {
        self.buckets.entry(name.to_owned()).or_default().acl = Some(policy);
    }

    /// The stored bucket policy, or `None` for a bucket nobody ever wrote one to.
    ///
    /// `None` is answered as the default owner grant by the read rather than as a `404`: an ACL
    /// is the one bucket subresource that always exists.
    #[must_use]
    fn bucket_acl(&self, name: &str) -> Option<&dto::AccessControlPolicy> {
        self.buckets.get(name).and_then(|bucket| bucket.acl.as_ref())
    }

    /// Installs a bucket's versioning document. `PutBucketVersioning` only.
    pub fn set_versioning(&mut self, name: &str, configuration: dto::VersioningConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().versioning = Some(configuration);
    }

    /// The stored versioning document, or `None` for a bucket that was never versioned. The
    /// distinction is the family's most consequential: `None` is not `Suspended`.
    #[must_use]
    fn versioning(&self, name: &str) -> Option<&dto::VersioningConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.versioning.as_ref())
    }

    /// Installs a bucket's acceleration document. `PutBucketAccelerateConfiguration` only.
    pub fn set_accelerate(&mut self, name: &str, configuration: dto::AccelerateConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().accelerate = Some(configuration);
    }

    /// The stored acceleration document, or `None` for a bucket that never had one.
    #[must_use]
    fn accelerate(&self, name: &str) -> Option<&dto::AccelerateConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.accelerate.as_ref())
    }

    /// Installs a bucket's request-payment document. `PutBucketRequestPayment` only.
    pub fn set_request_payment(&mut self, name: &str, configuration: dto::RequestPaymentConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().request_payment = Some(configuration);
    }

    /// The stored request-payment document, or `None` for a bucket that was never switched. The
    /// read turns `None` into the documented default rather than into an empty document.
    #[must_use]
    fn request_payment(&self, name: &str) -> Option<&dto::RequestPaymentConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.request_payment.as_ref())
    }

    /// Installs a bucket's logging document. `PutBucketLogging` only.
    pub fn set_logging(&mut self, name: &str, configuration: dto::BucketLoggingStatus) {
        self.buckets.entry(name.to_owned()).or_default().logging = Some(configuration);
    }

    /// The stored logging document, or `None` for a bucket that is not logging.
    #[must_use]
    fn logging(&self, name: &str) -> Option<&dto::BucketLoggingStatus> {
        self.buckets.get(name).and_then(|bucket| bucket.logging.as_ref())
    }

    /// Installs a bucket's notification document. `PutBucketNotificationConfiguration` only.
    pub fn set_notification(&mut self, name: &str, configuration: dto::NotificationConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().notification = Some(configuration);
    }

    /// The stored notification document, or `None` for a bucket that delivers no events.
    #[must_use]
    fn notification(&self, name: &str) -> Option<&dto::NotificationConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.notification.as_ref())
    }

    /// Installs a bucket's website document. `PutBucketWebsite` only.
    pub fn set_website(&mut self, name: &str, configuration: dto::WebsiteConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().website = Some(configuration);
    }

    /// The stored website document, or `None` for a bucket that answers the family's `404`.
    #[must_use]
    fn website(&self, name: &str) -> Option<&dto::WebsiteConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.website.as_ref())
    }

    /// Removes a bucket's website document. Idempotent: the delete answers `204` whether or not a
    /// document was there, even though the read of the same bucket answers `404`.
    pub fn clear_website(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.website = None;
        }
    }

    /// Installs a bucket's policy, byte for byte, together with the public verdict the case
    /// declares for it.
    ///
    /// The verdict is a parameter and not a computation on purpose: `GetBucketPolicyStatus`
    /// transports a boolean a policy evaluator produced, and this workspace has no evaluator. A
    /// fixture that guessed one would be asserting its own guess.
    pub fn set_policy(&mut self, name: &str, document: String, is_public: bool) {
        let bucket = self.buckets.entry(name.to_owned()).or_default();
        bucket.policy = Some(document);
        bucket.policy_is_public = is_public;
    }

    /// The stored policy document, or `None` for a bucket that answers `NoSuchBucketPolicy`.
    #[must_use]
    fn policy(&self, name: &str) -> Option<&str> {
        self.buckets.get(name).and_then(|bucket| bucket.policy.as_deref())
    }

    /// The public verdict the case declared beside the policy.
    #[must_use]
    fn policy_is_public(&self, name: &str) -> bool {
        self.buckets.get(name).is_some_and(|bucket| bucket.policy_is_public)
    }

    /// Removes a bucket's policy. Idempotent: the delete answers `204` whether or not one was
    /// there. The verdict goes with it, because a verdict about a policy that is gone is not an
    /// answer about anything.
    pub fn clear_policy(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.policy = None;
            bucket.policy_is_public = false;
        }
    }

    /// Installs a bucket's public-access block. `PutPublicAccessBlock` only.
    pub fn set_public_access_block(&mut self, name: &str, configuration: dto::PublicAccessBlockConfiguration) {
        self.buckets.entry(name.to_owned()).or_default().public_access_block = Some(configuration);
    }

    /// The stored public-access block, or `None` for a bucket that answers
    /// `NoSuchPublicAccessBlockConfiguration`.
    #[must_use]
    fn public_access_block(&self, name: &str) -> Option<&dto::PublicAccessBlockConfiguration> {
        self.buckets.get(name).and_then(|bucket| bucket.public_access_block.as_ref())
    }

    /// Removes a bucket's public-access block. Idempotent, like the other two deletes in the band.
    pub fn clear_public_access_block(&mut self, name: &str) {
        if let Some(bucket) = self.buckets.get_mut(name) {
            bucket.public_access_block = None;
        }
    }

    /// Removes a bucket, for `setup.buckets[].absent` and for `DeleteBucket`.
    ///
    /// The whole `BucketState` entry goes, and the CORS document and tag set go with it because
    /// they live inside it — the lifecycle, encryption, replication, object-lock and access
    /// control documents too: a bucket's configuration is a property of the bucket, not of the
    /// name, so a later creation under the same name starts unconfigured rather than inheriting a
    /// document nobody wrote to it. `Fixture::bucket_lifecycle` tests pin this, and two of them
    /// carry the sharpest stakes in the family: a recreated bucket that inherited a COMPLIANCE
    /// default would apply the previous owner's WORM rules to the new owner's data with no way to
    /// lift them, and one that inherited an ACL would keep handing the new owner's data to
    /// whoever the previous owner had shared it with — silently, because an inherited grant looks
    /// exactly like an intended one.
    pub fn remove_bucket(&mut self, name: &str) {
        self.buckets.remove(name);
        self.objects.retain(|(bucket, _), _| bucket != name);
        // Pending uploads go with the bucket: one that survived would reappear in a recreated
        // bucket of the same name and accept parts for an object nobody can complete there.
        self.uploads.retain(|_, upload| upload.bucket != name);
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
        let version = self.mint_version(bucket);
        self.put_object_with_version(bucket, key, object, version.clone());
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
            if self.objects.remove(&identity).is_some() {
                *self.object_generations.entry(identity).or_default() += 1;
            }
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
        *self.object_generations.entry(identity).or_default() += 1;
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
    /// Every handler goes through `require_upload` instead, which is the same lookup plus the
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

    /// One named version of one key, writable.
    ///
    /// The twin of [`Fixture::version`] for the one family that writes into a version the caller
    /// named rather than into the newest one: `PutObjectAcl` takes a `versionId`, and an ACL
    /// written onto the wrong version is a permission change nobody asked for on an object
    /// nobody named.
    #[must_use]
    pub fn version_mut(&mut self, bucket: &str, key: &str, version_id: &str) -> Option<&mut StoredVersion> {
        self.objects
            .get_mut(&(bucket.to_owned(), key.to_owned()))?
            .iter_mut()
            .find(|version| version.version_id == version_id)
    }

    /// The newest version of a key, whatever it holds.
    ///
    /// The twin of [`Fixture::object`] for a reader that has to tell "nothing was ever here" from
    /// "a deletion was recorded here": [`Fixture::object`] answers `None` for both, and those are
    /// two different responses on the wire.
    #[must_use]
    pub fn newest_version(&self, bucket: &str, key: &str) -> Option<&StoredVersion> {
        self.objects
            .get(&(bucket.to_owned(), key.to_owned()))
            .and_then(|versions| versions.last())
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

    /// The live keys of a bucket that a page could start with, lazily and in order.
    ///
    /// The one difference from [`Fixture::keys_in`] that matters is that this borrows the map's
    /// own ordering instead of building a list: it starts the walk at the first key that could
    /// belong on the page and stops at the first one past the prefix, so a caller that takes a
    /// hundred keys touches a hundred keys and allocates nothing per key it did not take.
    /// `tests/list_allocations.rs` is what holds that property; before it the listing enumerated
    /// and sorted the whole bucket, and one page out of a 64,000-key bucket cost 64,661 heap
    /// blocks against a 1,000-key bucket's 1,649.
    ///
    /// `after` is the position the previous page ended on. Starting the walk past it is sound
    /// rather than an optimisation: an entry is either a key or a prefix *of* that key, so an
    /// entry greater than `after` can only come from a key greater than `after`, and no key that
    /// belongs on this page is skipped by starting there.
    fn live_keys_from<'a>(&'a self, bucket: &'a str, prefix: &'a str, after: Option<&str>) -> impl Iterator<Item = &'a str> {
        let start = match after {
            Some(marker) if marker >= prefix => Bound::Excluded((bucket.to_owned(), marker.to_owned())),
            _ => Bound::Included((bucket.to_owned(), prefix.to_owned())),
        };
        self.objects
            .range((start, Bound::Unbounded))
            .take_while(move |((name, key), _)| name == bucket && key.starts_with(prefix))
            .filter(|(_, versions)| versions.last().is_some_and(|version| version.object.is_some()))
            .map(|((_, key), _)| key.as_str())
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

/// Standard base64 (RFC 4648 §4), which is the alphabet `Content-MD5` is written in.
///
/// Hand-written here for the same reason the digests are: a foreign implementation running this
/// suite inherits the corpus and nothing else, so the fixture may not reach for a workspace crate
/// the facade does not export.
pub(crate) fn encode_base64(bytes: &[u8]) -> String {
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
/// The two failures are kept apart. AWS answers `InvalidDigest` for a value that is not sixteen
/// base64-encoded bytes at all and `BadDigest` for one that is and disagrees with the body, and a
/// client branches on the difference: the first is a request it must rebuild, the second is a
/// transfer it may retry unchanged. `c-object-0026` is the case that draws the line; before it
/// existed both arrived here as `BadDigest`.
fn require_content_md5(claimed: Option<&str>, body: &[u8]) -> Result<(), HandlerError> {
    let Some(claimed) = claimed.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(());
    };
    if !is_base64_of_sixteen_bytes(claimed) {
        return Err(HandlerError::new(
            ErrorCode::INVALID_DIGEST,
            "The Content-MD5 you specified is not valid.",
        ));
    }
    if claimed == encode_base64(&crate::md5::digest(body)) {
        return Ok(());
    }
    Err(HandlerError::new(
        ErrorCode::BAD_DIGEST,
        "The Content-MD5 you specified did not match what we received.",
    ))
}

/// Whether a header value has the shape of sixteen base64-encoded bytes.
///
/// A shape check rather than a decode: sixteen bytes are always twenty-two characters carrying the
/// bits plus two of padding, so length, alphabet and padding decide it, and a decoder here would be
/// a second implementation of the one the gateway ships — which is the one thing a conformance
/// fixture must not borrow, because a suite that reuses the implementation's parser cannot catch
/// that parser being wrong.
fn is_base64_of_sixteen_bytes(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 || !value.ends_with("==") {
        return false;
    }
    bytes[..22]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
}

/// `InvalidArgument`, in AWS's own wording for a cursor the service did not issue.
fn bad_token() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, "The continuation token provided is incorrect")
}

/// A delimiter the request supplied, with the empty value read as "no delimiter".
///
/// `?delimiter=` arrives as `Some("")`, and folding on an empty string would put every key under
/// the same common prefix. S3 treats it as absent; `c-list-0039` is the case that says so.
///
/// The listings echo *this* value rather than the raw input, so a response reports the delimiter
/// it actually grouped on. That used to make no difference on the wire, because the encoder
/// dropped an optional member's empty text anyway; now that an empty member is written as an
/// empty element (rustfs/gateway#221), echoing the raw `Some("")` would answer `?delimiter=`
/// with a `<Delimiter></Delimiter>` the listing never applied.
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
/// The 301 for a bucket the fixture holds in another region.
///
/// One function for every operation of the lifecycle family, built through the exported
/// `permanent_redirect_for` so the `x-amz-bucket-region` header is structurally inseparable from
/// the status — the header SDKs need to complete the redirect, and the one this family's cases
/// pin in both places it must appear.
fn redirect_if_elsewhere(fixture: &Fixture, bucket: &str) -> Result<(), HandlerError> {
    let Some(region) = fixture.bucket_region(bucket) else {
        return Ok(());
    };
    if region == fixture.home_region {
        return Ok(());
    }
    let label = RegionLabel::new(region)
        .map_err(|_| HandlerError::internal_error("a fixture bucket's region is not a valid region label"))?;
    let bucket =
        BucketName::new(bucket.to_owned()).map_err(|_| HandlerError::internal_error("a fixture bucket name is not valid"))?;
    Err(permanent_redirect_for(bucket, label))
}

fn require_bucket(fixture: &Fixture, bucket: &BucketName) -> Result<(), HandlerError> {
    if fixture.has_bucket(bucket.as_str()) {
        return Ok(());
    }
    Err(HandlerErrorContext::missing_bucket().into())
}

/// The pair an upload was created for, read by the exported exchange rather than by this file.
impl RecordedUpload for StoredUpload {
    fn bucket(&self) -> &str {
        &self.bucket
    }

    fn key(&self) -> &str {
        &self.key
    }
}

/// Spends the upload id a request carried, and hands back the right to act on the upload it names.
///
/// This backend does not decide anything here. Every rule that used to live in this file — that
/// the id is resolved against the bucket **and** the key of the request that named it, that an id
/// no upload could have been minted with never reaches the store at all, and that all three
/// refusals render one indistinguishable document — is [`rustfs_gateway::resolve_upload`]'s. What
/// is left is the lookup, which is the one part of the exchange only a backend can perform, and
/// turning its rejection into this fixture's error type.
///
/// The two values come back separately on purpose. The record borrows the fixture and is released
/// as soon as the handler has read what it needs; the [`rustfs_gateway::ResolvedUploadId`] borrows the
/// request instead, so it survives into the `&mut` half of the handler and is the value every
/// mutation of an upload in this file is keyed by. A handler that skipped the exchange would have
/// no handle to key one with.
fn require_upload<'i, 'f>(
    fixture: &'f Fixture,
    upload_id: &'i UploadIdClaim,
    bucket: &BucketName,
    key: &ObjectKey,
) -> Result<(ResolvedUploadId<'i>, &'f StoredUpload), HandlerError> {
    resolve_upload(upload_id, bucket, key, |id| fixture.upload(id))
        .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))
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

/// A `412`, worded as AWS words it, naming the condition [`ConditionalOutcome::PreconditionFailed`]
/// carried when the caller chooses to report it.
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

/// The destination-side spelling of a failed condition, exactly as `<Condition>` reads it.
///
/// [`FailedCondition::as_str`] already returns this spelling — `evaluate` is the sole authority on
/// which header failed, so there is nothing left for a backend to reconstruct from which headers a
/// request happened to carry. [`guard_copy_source`] deliberately does not call this: its own
/// `<Condition>` is always `None`, because ADR-0008 admits no spelling for the copy-source side.
fn destination_condition(failed: Option<FailedCondition>) -> Option<&'static str> {
    failed.map(FailedCondition::as_str)
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
    settle_write(object, &conditions(if_match, None, if_none_match, None, now)?, destination_condition)
}

/// The copy-source conditions, evaluated against the source representation.
///
/// A copy is a write however much its source side looks like a read: a failed `If-None-Match` is a
/// `412` and never a `304`, which would tell the client its copy is up to date when no copy was
/// ever made. The four names are spelled the same as the destination's and name a different
/// object, which is why they are evaluated in their own call rather than merged into one — and why
/// the `<Condition>` this reports is nothing at all, whatever `evaluate` names: a client told
/// `If-Match` failed would look at the header it sent for the destination.
fn guard_copy_source(
    found: &StoredObject,
    if_match: Option<&str>,
    if_unmodified_since: Option<i64>,
    if_none_match: Option<&str>,
    if_modified_since: Option<i64>,
    now: i64,
) -> Result<(), HandlerError> {
    let conditions = conditions(if_match, if_unmodified_since, if_none_match, if_modified_since, now)?;
    // No `<Condition>`, even though `evaluate` now always knows which header failed. ADR-0008
    // closes that element to `If-Match`, `If-None-Match`, `If-Modified-Since` and
    // `If-Unmodified-Since`, and a refusal carrying anything else is not trimmed by the resolver —
    // the whole `412` is replaced by a static `InternalError`. Naming the source header would
    // therefore turn a precondition failure into a `500`, which is what it did until this comment
    // existed. The destination's four spellings are in the set and are still named; there is simply
    // no admitted spelling for the source side, so the element is omitted rather than mis-attributed
    // to the destination header of the same shape.
    let result = settle_write(Some(found), &conditions, |_| None);
    let only_if_match =
        if_match.is_some() && if_unmodified_since.is_none() && if_none_match.is_none() && if_modified_since.is_none();
    if only_if_match && copy_source_if_match_miss_proceeds() {
        Ok(())
    } else {
        result
    }
}

/// Turns the contract's verdict on a write into this backend's answer.
///
/// `name` decides whether the failing header reaches `<Condition>` at all — [`guard_write`] passes
/// [`destination_condition`], [`guard_copy_source`] passes a function that always answers `None` —
/// but never *which* header failed: that fact comes from `evaluate` alone, once, here.
fn settle_write(
    object: Option<&StoredObject>,
    conditions: &Preconditions,
    name: impl Fn(Option<FailedCondition>) -> Option<&'static str>,
) -> Result<(), HandlerError> {
    let validators = validators_of(object)?;
    match evaluate(conditions, &validators, RequestKind::Write).map_err(refused)? {
        ConditionalOutcome::Proceed => Ok(()),
        // A write is never answered `304`, and the contract guarantees it. The arm is spelled out
        // rather than folded into a catch-all so that an outcome added later cannot arrive here as
        // a silent success. Unreachable in practice, so it names nothing.
        ConditionalOutcome::NotModified => Err(precondition(None)),
        ConditionalOutcome::PreconditionFailed(failed) => Err(precondition(name(failed))),
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
    match evaluate(&conditions, &validators, RequestKind::Read).map_err(refused)? {
        outcome @ (ConditionalOutcome::Proceed | ConditionalOutcome::NotModified) => Ok(outcome),
        ConditionalOutcome::PreconditionFailed(failed) => Err(precondition(destination_condition(failed))),
        ConditionalOutcome::Conflict => Err(conflict()),
    }
}

/// The unconfigured answer for a bucket subresource read, taken from the operation's declaration.
///
/// `model/overlays/ops/**` is the one authority for which `404` an unconfigured subresource owes;
/// `OperationSpec::not_configured_error` is that value lowered into Rust through
/// `generated/routes.rs`. A backend that writes the code out again here is a second copy that can
/// disagree with the overlay without anything noticing, which is what gateway#242 recorded: before
/// this, flipping `GetBucketLifecycleConfiguration.errors.not_configured` in the overlay changed
/// no served byte and `q-lc-0001` reported `INERT`.
///
/// When the operation declares no code the fixture has none to answer with, and it says exactly
/// that rather than substituting one — a substituted `404` would keep every case green and put the
/// declaration back out of reach of the mutation gate.
fn not_configured<O: Operation>(message: &'static str) -> HandlerError {
    match O::spec().not_configured_error.clone() {
        Some(code) => HandlerError::new(code, message),
        None => HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "this operation declares no unconfigured-subresource error"),
    }
}

/// The same declaration for a read whose unconfigured answer is a `200`: the absence of a code is
/// the rule, so a declared one must reach the wire too (`q-acc-0001`, rustfs/backlog#1728).
fn unconfigured<O: Operation>(absent: bool) -> Result<(), HandlerError> {
    match O::spec().not_configured_error.clone() {
        Some(code) if absent => Err(HandlerError::new(code, "the subresource is not configured")),
        _ => Ok(()),
    }
}

/// `NoSuchCORSConfiguration`, in AWS's own wording for a bucket that never had a CORS document.
fn no_such_cors_configuration() -> HandlerError {
    not_configured::<dto::GetBucketCors>("The CORS configuration does not exist")
}

/// `NoSuchLifecycleConfiguration`, in AWS's own wording for a bucket that never had a lifecycle
/// document.
fn no_such_lifecycle_configuration() -> HandlerError {
    not_configured::<dto::GetBucketLifecycleConfiguration>("The lifecycle configuration does not exist")
}

/// `NoSuchWebsiteConfiguration`, for a bucket that never had a website document.
///
/// One of the three distinct not-configured literals in the 200-249 band, and not
/// interchangeable with the other two: a client tearing configuration down branches on which one
/// it got.
fn no_such_website_configuration() -> HandlerError {
    not_configured::<dto::GetBucketWebsite>("The specified bucket does not have a website configuration")
}

/// `NoSuchBucketPolicy`, for a bucket that never had a policy — answered by the policy read and,
/// because it is the same missing document, by the policy-status read beside it.
fn no_such_bucket_policy() -> HandlerError {
    not_configured::<dto::GetBucketPolicy>("The bucket policy does not exist")
}

/// The same missing document as [`no_such_bucket_policy`], read through the status operation.
///
/// Two helpers rather than one because the two operations carry the declaration separately: a
/// shared helper would answer the policy read's declared code for a status read whose own
/// declaration had been removed, and the removal would go unobserved.
fn no_such_bucket_policy_status() -> HandlerError {
    not_configured::<dto::GetBucketPolicyStatus>("The bucket policy does not exist")
}

/// `NoSuchPublicAccessBlockConfiguration`, for a bucket with no public-access block.
fn no_such_public_access_block() -> HandlerError {
    not_configured::<dto::GetPublicAccessBlock>("The public access block configuration was not found")
}

/// `ServerSideEncryptionConfigurationNotFoundError`, in AWS's own wording for a bucket that
/// never had a default-encryption document.
fn no_such_replication_configuration() -> HandlerError {
    not_configured::<dto::GetBucketReplication>("The replication configuration was not found")
}

fn no_such_encryption_configuration() -> HandlerError {
    not_configured::<dto::GetBucketEncryption>("The server side encryption configuration was not found")
}

/// `ObjectLockConfigurationNotFoundError`: the **bucket-level** unconfigured answer, for a
/// bucket that never enabled object lock.
fn object_lock_configuration_not_found() -> HandlerError {
    not_configured::<dto::GetObjectLockConfiguration>("Object Lock configuration does not exist for this bucket")
}

/// `NoSuchObjectLockConfiguration`: the **object-level** unconfigured answer, for an object with
/// no retention or no legal hold.
///
/// Deliberately a different code from the bucket read's, and deliberately not a `200` with an
/// empty document: a compliance audit reads "no lock state" and "a lock state that permits
/// everything" as opposite findings.
fn no_such_retention() -> HandlerError {
    not_configured::<dto::GetObjectRetention>("The specified object does not have an ObjectLock configuration")
}

/// The legal-hold read's own spelling of the same object-level absence.
///
/// Split from [`no_such_retention`] for the reason the two policy helpers are split: each read
/// declares the code separately, so each has to answer from its own declaration.
fn no_such_legal_hold() -> HandlerError {
    not_configured::<dto::GetObjectLegalHold>("The specified object does not have an ObjectLock configuration")
}

/// Refuses a lock-state write on a bucket that never enabled object lock (`q-lock-0015`).
///
/// `InvalidRequest` rather than a not-found: the bucket is there, and what is missing is the
/// configuration the request presupposes. Accepting the write would store a protection promise
/// no enforcement path reads — the client walks away believing its object is held.
///
/// # Errors
///
/// `InvalidRequest` when the bucket has no object lock, by either road.
fn require_object_lock(fixture: &Fixture, bucket: &str) -> Result<(), HandlerError> {
    if !object_lock_requires_enabled_bucket() {
        return Ok(());
    }
    if fixture.has_object_lock(bucket) {
        return Ok(());
    }
    Err(HandlerError::new(
        ErrorCode::INVALID_REQUEST,
        "Bucket is missing Object Lock Configuration",
    ))
}

/// The object version a lock-state read, or a restore, acts on: the newest one, or the one
/// `versionId` names.
///
/// Per-version lock state is the representation this fixture already had, not one it invents:
/// a [`StoredVersion`] owns its [`StoredObject`], and the retention and hold live on the object.
/// A named version is selected the way every other version-scoped read in this file selects it
/// ([`select_named`]): an id that names nothing is `NoSuchVersion`, an id that names a delete
/// marker is `405 MethodNotAllowed`. What it must never be is the current version's document —
/// on a compliance surface that is a confident wrong answer about whether data is locked, and
/// `c-lock-0040` is the case that tells the two apart.
fn lock_state_of<'a>(
    fixture: &'a Fixture,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<&'a StoredObject, HandlerError> {
    match version_id {
        None => fixture.object(bucket, key).ok_or_else(|| no_such_key(key)),
        Some(version_id) => select_named(fixture, bucket, key, version_id),
    }
}

/// [`lock_state_of`], writable, with the same two refusals for a named version.
///
/// The write is in place on the version it selects: protecting a version is not a new
/// representation of it, so nothing is minted and no other version is touched.
fn lock_state_of_mut<'a>(
    fixture: &'a mut Fixture,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<&'a mut StoredObject, HandlerError> {
    let Some(version_id) = version_id else {
        return fixture.object_mut(bucket, key).ok_or_else(|| no_such_key(key));
    };
    let version = fixture.version_mut(bucket, key, version_id).ok_or_else(no_such_version)?;
    let last_modified = version.last_modified;
    version
        .object
        .as_mut()
        .ok_or_else(|| versioned_delete_marker(version_id, last_modified))
}

/// What a read found under a key, before any precondition is evaluated.
///
/// Three states rather than an `Option`, because "there is nothing here" and "there is a deletion
/// recorded here" are different answers on the wire: the second carries `x-amz-delete-marker`, and
/// that header is the only thing that lets a client tell a key it deleted from one it never wrote.
#[derive(Debug, Clone, Copy)]
enum Selected<'a> {
    /// A representation the read may serve.
    Object(&'a StoredObject),
    /// No version of this key exists.
    Absent,
    /// The newest version is this delete marker.
    Deleted(&'a StoredVersion),
}

impl<'a> Selected<'a> {
    /// The representation, for the precondition evaluation that runs before the refusal is chosen.
    const fn object(self) -> Option<&'a StoredObject> {
        match self {
            Self::Object(object) => Some(object),
            Self::Absent | Self::Deleted(_) => None,
        }
    }
}

/// What a read with no `versionId` finds: the newest version, or the deletion that replaced it.
fn select_current<'a>(fixture: &'a Fixture, bucket: &str, key: &str) -> Selected<'a> {
    match fixture.newest_version(bucket, key) {
        None => Selected::Absent,
        Some(version) => match version.object.as_ref() {
            Some(object) => Selected::Object(object),
            None => Selected::Deleted(version),
        },
    }
}

/// What a read that named a `versionId` finds, or the refusal that version earns.
///
/// The two refusals are not interchangeable and the distinction is the whole point of the pair:
/// `NoSuchVersion` says the id names nothing, `MethodNotAllowed` says it names a deletion. It is
/// the same split [`read_copy_source`] draws for a copy source.
fn select_named<'a>(fixture: &'a Fixture, bucket: &str, key: &str, version_id: &str) -> Result<&'a StoredObject, HandlerError> {
    let version = fixture.version(bucket, key, version_id).ok_or_else(|| {
        HandlerError::from(HandlerErrorContext::missing_object(MissingObject::Version, ResourceVisibility::Visible))
    })?;
    version
        .object
        .as_ref()
        .ok_or_else(|| versioned_delete_marker(version_id, version.last_modified))
}

/// The `405` a read of a named delete marker gets, with the two headers it must carry.
fn versioned_delete_marker(version_id: &str, last_modified: i64) -> HandlerError {
    HandlerErrorContext::versioned_delete_marker(version_id, last_modified)
        .map(HandlerError::from)
        .unwrap_or_else(|_| HandlerError::internal_error("a fixture version id is not valid"))
}

/// The `404` a read with no `versionId` gets when the newest version is a delete marker.
fn deleted_by_marker(key: &str, marker: &StoredVersion) -> HandlerError {
    let named = ObjectKey::new(key.to_owned()).ok();
    HandlerErrorContext::current_delete_marker(ResourceVisibility::Visible, named, &marker.version_id, marker.last_modified)
        .map(HandlerError::from)
        .unwrap_or_else(|_| HandlerError::internal_error("a fixture delete marker is not renderable"))
}

/// `NoSuchKey`, raised only once every condition has been evaluated against the absence.
///
/// The document carries `<Key>`, which is the only element in it that says *which* read missed —
/// a client batching reads on one connection cannot tell two 404s apart without it. The key is the
/// one the request named, so it is an echo to a caller already authenticated and authorised, and
/// the writer escapes it: see `rustfs_gateway`'s renderer.
fn no_such_key(key: &str) -> HandlerError {
    match ObjectKey::new(key.to_owned()) {
        Ok(key) => HandlerErrorContext::missing_object_for(key, MissingObject::Key, ResourceVisibility::Visible).into(),
        Err(_) => HandlerError::internal_error("a fixture object key is not valid"),
    }
}

/// AWS's own wording for a version id that names nothing.
///
/// The message never repeats the id: a caller who can tell a mistyped id from one that belongs to
/// somebody else's object apart by the `<Message>` element has been told the id is genuine.
fn no_such_version() -> HandlerError {
    HandlerErrorContext::missing_object(MissingObject::Version, ResourceVisibility::Visible).into()
}

/// A resolved range: the window to send, the `Content-Range` value that describes it, and the two
/// head values a part selection adds.
#[derive(Debug)]
struct Slice {
    start: usize,
    end_exclusive: usize,
    content_range: Option<String>,
    suppress_object_checksum: bool,
    /// The status the contract chose, rather than one inferred from the presence of a header.
    ///
    /// Inferring it from `content_range.is_some()` gave the same answer for every decision this
    /// backend could serve, right up until a part selection — whose status is a policy
    /// (`part_number_outcome_policy`) that an inference cannot read. A backend that infers is a
    /// backend the mutation gate cannot reach.
    status: u16,
    /// `x-amz-mp-parts-count`, when the contract's policy says a part read publishes one.
    parts_count: Option<u32>,
}

impl Slice {
    /// The whole object.
    fn whole(length: usize) -> Slice {
        Slice {
            start: 0,
            end_exclusive: length,
            content_range: None,
            suppress_object_checksum: false,
            status: 200,
            parts_count: None,
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
/// on its own selects a part of a completed multipart object: it is resolved against the part table
/// [`StoredObject::part_lengths`] carries — by [`rustfs_gateway::resolve_part`], not here — and
/// refused by name for an object that has no parts, which is every object `[setup.objects]`
/// declares and every object a single `PUT` wrote.
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
    let served_len = decision.content_length(length as u64);
    let suppress_object_checksum = decision.suppresses_object_checksum();
    let status = decision.status().as_u16();
    // Offered the table's size for every decision, because the contract — not this backend —
    // decides that only a part selection publishes a count.
    let parts_count = decision.part_count_header(u32::try_from(object.part_lengths.len()).unwrap_or(u32::MAX));
    match decision {
        RangeDecision::Whole => Ok(Slice::whole(length)),
        RangeDecision::Partial { start, .. } => {
            let start = usize::try_from(start).unwrap_or(length).min(length);
            let served_len = usize::try_from(served_len).unwrap_or(length);
            let end_exclusive = start.saturating_add(served_len).min(length);
            Ok(Slice {
                start,
                end_exclusive,
                content_range,
                suppress_object_checksum,
                status,
                parts_count,
            })
        }
        RangeDecision::Part { part_number } => {
            if object.part_lengths.is_empty() {
                return Err(HandlerError::not_implemented(
                    "this object was not completed from a multipart upload, so it has no part table \
                     a partNumber selector could name a window in",
                ));
            }
            let window = resolve_part(part_number, &object.part_lengths).map_err(refused)?;
            let resolved = window.as_decision();
            let start = usize::try_from(window.start).unwrap_or(length).min(length);
            let served_len = usize::try_from(resolved.content_length(length as u64)).unwrap_or(length);
            let end_exclusive = start.saturating_add(served_len).min(length);
            Ok(Slice {
                start,
                end_exclusive,
                content_range: resolved.content_range(),
                suppress_object_checksum,
                status,
                parts_count,
            })
        }
        RangeDecision::Unsatisfiable {
            actual_object_size,
            range_requested,
        } => Err(HandlerError::unsatisfiable_range(range_requested, actual_object_size)),
    }
}

/// The stored `x-amz-checksum-*` value a read reports, and the two reasons it reports none.
///
/// * **The client has to ask.** S3 emits the digest only for `x-amz-checksum-mode: ENABLED`, so a
///   backend that volunteered it would put a header on every read that no case asked for.
/// * **The read has to be whole.** A checksum describes the bytes it travels with. A `206`
///   carrying the *object's* digest fails verification in every SDK that checks one, and the client
///   then reports data corruption — which sends an operator to look at storage rather than at a
///   header. `c-range-0016` is both halves of this, in two exchanges on one connection.
///
#[derive(Debug, Default, PartialEq, Eq)]
struct ReportedChecksum {
    crc32: Option<String>,
    crc32c: Option<String>,
    crc64nvme: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
    md5: Option<String>,
    xxhash64: Option<String>,
    xxhash3: Option<String>,
    xxhash128: Option<String>,
    kind: Option<dto::ChecksumType>,
}

fn reported_checksum_type(spec: ChecksumSpec) -> Option<dto::ChecksumType> {
    match spec.checksum_type() {
        PackedChecksumType::Composite => Some(dto::ChecksumType::COMPOSITE),
        PackedChecksumType::FullObject => Some(dto::ChecksumType::FULL_OBJECT),
    }
}

fn read_checksum(mode: Option<&dto::ChecksumMode>, partial: bool, stored: Option<ChecksumSpec>) -> ReportedChecksum {
    if partial || mode != Some(&dto::ChecksumMode::ENABLED) {
        return ReportedChecksum::default();
    }
    let Some(spec) = stored else {
        return ReportedChecksum::default();
    };
    let value = Some(spec.render_base64().to_owned());
    let kind = reported_checksum_type(spec);
    match spec.algorithm() {
        ChecksumAlgorithm::Crc32 => ReportedChecksum {
            crc32: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::Crc32c => ReportedChecksum {
            crc32c: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::Crc64Nvme => ReportedChecksum {
            crc64nvme: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::Sha1 => ReportedChecksum {
            sha1: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::Sha256 => ReportedChecksum {
            sha256: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::Sha512 => ReportedChecksum {
            sha512: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::Md5 => ReportedChecksum {
            md5: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::XxHash64 => ReportedChecksum {
            xxhash64: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::XxHash3 => ReportedChecksum {
            xxhash3: value,
            kind,
            ..ReportedChecksum::default()
        },
        ChecksumAlgorithm::XxHash128 => ReportedChecksum {
            xxhash128: value,
            kind,
            ..ReportedChecksum::default()
        },
        _ => ReportedChecksum::default(),
    }
}

/// The storage class a read reports, which S3 omits for the default class.
fn storage_class_header(object: &StoredObject) -> Option<dto::StorageClass> {
    if object.storage_class == "STANDARD" {
        return None;
    }
    Some(dto::StorageClass::custom(object.storage_class.clone()))
}

/// The `x-amz-restore-output-path` a select-on-restore reports, built from where it asked for the
/// answer to be written.
///
/// `None` when the location names no bucket, which the validator has already refused — so this is
/// total rather than defensive, and it is written with `?` so that a future shape with an optional
/// bucket cannot turn into a panic here.
fn output_path_of(location: &dto::OutputLocation) -> Option<String> {
    let s3 = location.s3.as_ref()?;
    Some(format!("{}/{}", s3.bucket_name.as_str(), s3.prefix))
}

/// The storage classes an object has to be retrieved from before it can be read.
///
/// Two, and not three: `GLACIER_IR` is an instant-retrieval class, so an object in it is readable
/// without a restore and a restore of it is the `InvalidObjectState` refusal.
const ARCHIVE_STORAGE_CLASSES: &[&str] = &["GLACIER", "DEEP_ARCHIVE"];

/// Whether this copy has to be retrieved before it can be read.
fn is_archived(object: &StoredObject) -> bool {
    ARCHIVE_STORAGE_CLASSES.contains(&object.storage_class.as_str())
}

/// The `x-amz-restore` value a read reports, or `None` when no retrieval was ever asked for.
///
/// Rendered by [`format_optional_restore_status`] rather than by a `format!` here, which is the whole
/// point of that function existing: this header has internal structure — two quoted values, a
/// comma, exactly one space — and a second renderer is how the two spellings drift. An object
/// nobody restored carries no header at all, which is a different observation from a header
/// saying the retrieval finished.
fn restore_header(object: &StoredObject) -> Option<String> {
    format_optional_restore_status(object.restore.as_ref())
}

/// The tag count an object read gives the response codec, including zero.
///
/// Suppression is the generated codec's responsibility: keeping it out of the fixture makes the
/// `omit_when` rule observable and gives `GetObject` and `HeadObject` the same policy. The ceiling
/// makes the cast total — a stored set is at most fifty pairs.
fn tag_count_header(object: &StoredObject) -> Option<i32> {
    i32::try_from(object.tags.len()).ok()
}

/// The checksum contract an initiating request declared, if it declared one.
///
/// Unsupported algorithms are refused rather than answered with an uncomputed digest.
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
    if !matches!(resolved, ChecksumAlgorithm::Crc32 | ChecksumAlgorithm::Crc32c) {
        return Err(HandlerError::not_implemented("this conformance fixture computes only CRC32 and CRC32C"));
    }
    Ok(Some(UploadChecksum {
        algorithm: resolved,
        kind: kind.cloned().unwrap_or(dto::ChecksumType::COMPOSITE),
    }))
}

/// The `x-amz-checksum-*` value for one run of bytes, under the algorithm the upload declared.
fn checksum_of(checksum: &UploadChecksum, bytes: &[u8]) -> Result<ChecksumSpec, HandlerError> {
    let digest = match checksum.algorithm {
        ChecksumAlgorithm::Crc32 => crate::crc32::digest(bytes),
        ChecksumAlgorithm::Crc32c => crate::crc32::digest_crc32c(bytes),
        _ => return Err(HandlerError::not_implemented("this conformance fixture computes only CRC32 and CRC32C")),
    };
    ChecksumSpec::from_digest(checksum.algorithm, &digest)
        .map_err(|_| HandlerError::internal_error("a computed digest is not a valid checksum"))
}

/// `x-amz-copy-source`, resolved to the object it names.
///
/// # Why this parser remains here
///
/// `crates/core/src/ops/shared/copy_source.rs` is this gateway's copy-source contract — the split
/// rule, the two ARN grammars, the self-copy classification and the stricter range rule — and the
/// parser below remains for direct fixture unit tests. The live `Handler` implementations do not
/// call it: they consume the normalized source from `Req::resources()` after the framework has
/// authorized it. Keeping the test helper out of the service path prevents a second parser from
/// deciding which object storage reads.
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
#[cfg(test)]
fn bad_copy_source(reason: &'static str) -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, reason)
}

/// Parses one `x-amz-copy-source` value.
///
/// The order is the point: the optional `?versionId=` suffix is split off the **raw** value at its
/// last `?`, and only then is each half percent-decoded. Decode first and `a%3Fb?versionId=v1`
/// becomes `a?b?versionId=v1`, where no split rule recovers which `?` the client sent.
#[cfg(test)]
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
#[cfg(test)]
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
/// The separator is the first slash of the decoded value, literal or `%2F` (rustfs/gateway#926): a
/// bucket name cannot contain `/`, so every later slash is key bytes. It is found on the raw value
/// so the key is still decoded exactly once — the shared parser's rule.
#[cfg(test)]
fn parse_source_path(path: &str) -> Result<(String, String), HandlerError> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some((bucket, key)) = ["/", "%2F", "%2f"]
        .into_iter()
        .filter_map(|separator| path.find(separator).map(|at| (at, separator.len())))
        .min_by_key(|&(at, _)| at)
        .map(|(at, len)| (&path[..at], &path[at + len..]))
    else {
        return Err(bad_copy_source("x-amz-copy-source must name a key as well as a bucket"));
    };
    Ok((decode_source(bucket)?, decode_source(key)?))
}

/// Parses the two S3 ARN spellings, and refuses every other ARN.
///
/// An unrecognised ARN is never demoted to a bucket name. `arn:aws:iam::1:user/bob` would otherwise
/// address a bucket literally called `arn:aws:iam::1:user`, and in a deployment where somebody has
/// created one, every unrecognised ARN copy is silently redirected into it.
#[cfg(test)]
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
#[cfg(test)]
fn unknown_source_arn() -> HandlerError {
    bad_copy_source("x-amz-copy-source accepts an access point or Outposts ARN, or a bucket and key")
}

/// Percent-decodes one half of the copy-source header, refusing bytes that are not UTF-8.
///
/// `%XX` is one octet and everything else is itself — a `+` stays a plus sign, because this is a
/// path and not a form. Percent encoding carries octets rather than characters, so a client can
/// spell a source whose decoded bytes are not text; that is a refusal and never a panic.
///
/// This used to be a hand-rolled decoder living in this file. It was the workspace's second
/// percent decoder and the second place a copy source was parsed, which is precisely the shape
/// `GHSA-f4vq-9ffr-m8m3` has: a backend that re-reads a name the framework already read. It now
/// calls [`rustfs_gateway::decode_once`], and `scripts/check_single_normalization.sh` refuses
/// a third one.
#[cfg(test)]
fn decode_source(value: &str) -> Result<String, HandlerError> {
    rustfs_gateway::decode_once(value).map_err(|_| bad_copy_source("x-amz-copy-source is not valid UTF-8 once decoded"))
}

/// Validates the bucket half of a copy source, through the framework's floor and rules.
#[cfg(test)]
fn source_bucket(name: &str) -> Result<BucketName, HandlerError> {
    BucketName::materialize(name, &rustfs_gateway::NamePolicy::default())
        .map_err(|_| bad_copy_source("the bucket named by x-amz-copy-source is not a valid bucket name"))
}

/// Validates the key half against the same safety floor the request path is held to.
///
/// A `.` segment is still opaque text — an S3 key has no directory semantics — but a `..` segment,
/// a control character or a UNC shape is refused here rather than looked up literally. A backend
/// that applied looser rules than the gateway would be the second normalisation the whole of
/// P6-05 exists to prevent, and it would be the one on the storage side of the authorisation
/// check.
#[cfg(test)]
fn source_key(key: &str) -> Result<ObjectKey, HandlerError> {
    ObjectKey::materialize_decoded(key, &rustfs_gateway::NamePolicy::default())
        .map_err(|rejection| bad_copy_source(rejection.reason()))
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

/// The stored pairs, rendered as the `<TagSet>` a tagging read answers with.
///
/// Total, and that is the point: `Tag.Key` is a `String`, so every pair this fixture stored has a
/// representation on the way out. It used to be fallible — the dto typed the key as an `ObjectKey`
/// and a key that type would not hold had to become an `InvalidTag` on a *read* — which put a
/// refusal on the answering path for a value the writing path had already accepted.
fn tag_elements(tags: &[(String, String)]) -> Vec<dto::Tag> {
    tags.iter()
        .map(|(key, value)| dto::Tag {
            key: key.clone(),
            value: value.clone(),
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
/// The refusal a `?tagging` request that named a version with no representation gets.
///
/// A delete marker is a version that exists and holds nothing, so it has no tag set to read or to
/// write — and `NoSuchKey` would be the wrong sentence for it, because the version is right there
/// in the history. It is the same distinction [`read_copy_source`] draws for a copy source, and it
/// is drawn here for the same reason: a client branches on the two answers.
fn tagging_delete_marker(version_id: &str, last_modified: i64) -> HandlerError {
    versioned_delete_marker(version_id, last_modified)
}

/// The version id a tagging answer reports, for the version it actually acted on.
///
/// Reported only for a versioned bucket, for [`read_copy_source`]'s reason: `null` is the version
/// of an object in a bucket that was never versioned, and a header carrying it tells a client its
/// object has a version to come back for. `None` on an unversioned bucket is the omission AWS
/// makes.
fn reported_tagging_version(fixture: &Fixture, bucket: &str, key: &str, requested: Option<&str>) -> Option<String> {
    if !fixture.is_versioned(bucket) {
        return None;
    }
    match requested {
        Some(version_id) => Some(version_id.to_owned()),
        None => fixture.newest_version_id(bucket, key).map(ToOwned::to_owned),
    }
}

/// The access control policy a bucket or an object that nobody configured answers with.
///
/// Every resource has one from the moment it exists, and this is it: the owner, and the owner's
/// `FULL_CONTROL`. Built rather than stored, because a fixture that had to write the default in
/// before a read could see it would make "the default" a property of the setup rather than of
/// the resource — and `c-acl-0028` asks precisely what a bucket nobody ever called
/// `PutBucketAcl` on answers.
fn default_acl() -> dto::AccessControlPolicy {
    dto::AccessControlPolicy {
        owner: Some(fixture_owner()),
        grants: Some(vec![dto::Grant {
            grantee: Some(dto::Grantee {
                id: Some(OWNER_ID.to_owned()),
                display_name: Some(OWNER_DISPLAY_NAME.to_owned()),
                r#type: Some(GranteeType::CanonicalUser.as_dto()),
                ..dto::Grantee::default()
            }),
            permission: Some(dto::Permission::FULL_CONTROL),
        }]),
    }
}

/// The owner every listing and every ACL in this fixture reports.
fn fixture_owner() -> dto::Owner {
    dto::Owner {
        id: Some(OWNER_ID.to_owned()),
        display_name: Some(OWNER_DISPLAY_NAME.to_owned()),
    }
}

/// The ACL headers of a request, lifted off the decoded input for the shared contract.
///
/// One function rather than two copies, because the bucket write and the object write carry the
/// same six headers and the exclusivity rule is decided from all of them at once: a version that
/// looked at `x-amz-acl` alone would let every grant header through beside a body.
fn acl_headers<'a>(
    canned: Option<&'a dto::Acl>,
    full_control: Option<&'a String>,
    read: Option<&'a String>,
    write: Option<&'a String>,
    read_acp: Option<&'a String>,
    write_acp: Option<&'a String>,
) -> AclHeaders<'a> {
    AclHeaders {
        canned: canned.map(dto::Acl::as_str),
        full_control: full_control.map(String::as_str),
        read: read.map(String::as_str),
        write: write.map(String::as_str),
        read_acp: read_acp.map(String::as_str),
        write_acp: write_acp.map(String::as_str),
    }
}

/// The shared ACL contract's own refusal, rendered.
fn refused_acl(rejection: AclRejection) -> HandlerError {
    HandlerError::new(rejection.code(), rejection.reason().to_owned())
}

/// The policy one resolved ACL write stores.
///
/// The body channel stores the document it carried. The header channel stores the grants the
/// explicit headers named, under this fixture's owner — and a canned ACL is *not* expanded into
/// grants: expansion depends on the bucket owner, the object owner and, for `log-delivery-write`,
/// a predefined group, and the shared contract deliberately validates canned values rather than
/// inventing an expansion. What is stored for a canned-only write is therefore the default
/// policy, and the case that asserts a canned write succeeds asserts the `200` and not a
/// read-back this fixture would have made up.
fn policy_of(resolved: AclInput) -> dto::AccessControlPolicy {
    match resolved {
        AclInput::Document(document) => document,
        AclInput::Headers { canned: _, grants } if grants.is_empty() => default_acl(),
        AclInput::Headers { canned: _, grants } => dto::AccessControlPolicy {
            owner: Some(fixture_owner()),
            grants: Some(grants),
        },
    }
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
        return Err(HandlerErrorContext::missing_bucket().into());
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
    let object = select_named(fixture, bucket, key, requested).map_err(HandlerError::as_copy_source_refusal)?;
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

async fn upload_part(state: &Arc<Mutex<Fixture>>, input: dto::UploadPartInput) -> HandlerResult<dto::UploadPart> {
    // The bucket before the part, as RustFS checks it: c-mpu-0053 must observe a body never read.
    let poisoned = || HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange");
    require_bucket(&*state.lock().map_err(|_| poisoned())?, &input.bucket)?;
    let bytes = drain(input.body).await?;
    let mut fixture = state.lock().map_err(|_| poisoned())?;
    require_bucket(&fixture, &input.bucket)?;
    let (handle, upload) = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
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
    let etag = fixture.put_part(handle.id(), input.part_number, bytes);
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
        // A named version is resolved before anything conditional: a precondition evaluated against
        // a representation the request cannot reach is not a question, and the two refusals a
        // version id earns — the id names nothing, the id names a deletion — are decided by the
        // version alone.
        let selected = match input.version_id.as_deref() {
            Some(version_id) => Selected::Object(select_named(&fixture, input.bucket.as_str(), input.key.as_str(), version_id)?),
            None => select_current(&fixture, input.bucket.as_str(), input.key.as_str()),
        };
        let found = selected.object();
        let condition = guard_read(
            found,
            input.if_match.as_deref(),
            input.if_unmodified_since.as_ref().map(|stamp| stamp.secs()),
            input.if_none_match.as_deref(),
            input.if_modified_since.as_ref().map(|stamp| stamp.secs()),
            fixture.now,
        )?;
        let object = match selected {
            Selected::Object(object) => object,
            Selected::Absent => return Err(no_such_key(input.key.as_str())),
            Selected::Deleted(marker) => return Err(deleted_by_marker(input.key.as_str(), marker)),
        };
        if condition == ConditionalOutcome::NotModified {
            let e_tag = if condition.includes_selected_etag() {
                Some(entity_tag(&object.etag)?)
            } else {
                None
            };
            return Ok(Resp::with_status(
                dto::GetObjectOutput {
                    e_tag,
                    content_length: Some(object.body.len() as i64),
                    body: Some(ByteStream::from_bytes(bytes::Bytes::copy_from_slice(&object.body))),
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
        let status = slice.status;
        let checksum = read_checksum(input.checksum_mode.as_ref(), slice.suppress_object_checksum, object.checksum);
        Ok(Resp::with_status(
            dto::GetObjectOutput {
                content_length: Some(body.len() as i64),
                content_type: object.content_type.clone(),
                content_range: slice.content_range,
                // How many parts the object holds, which is the only way a client parallelising a
                // download learns how many requests to issue. Absent on every read that did not
                // name a part.
                parts_count: slice.parts_count.map(|count| count as i32),
                accept_ranges: Some("bytes".to_owned()),
                // The two validators. They describe the *representation*, never the window served,
                // so a 206 reports the entity tag and the modification time of the whole object —
                // which is what makes a resumed download able to notice the object changed under it.
                e_tag: Some(entity_tag(&object.etag)?),
                last_modified: Some(Timestamp::from_secs(object.last_modified)),
                checksum_crc32: checksum.crc32,
                checksum_crc32c: checksum.crc32c,
                checksum_crc64nvme: checksum.crc64nvme,
                checksum_sha1: checksum.sha1,
                checksum_sha256: checksum.sha256,
                checksum_sha512: checksum.sha512,
                checksum_md5: checksum.md5,
                checksum_xxhash64: checksum.xxhash64,
                checksum_xxhash3: checksum.xxhash3,
                checksum_xxhash128: checksum.xxhash128,
                checksum_type: checksum.kind,
                cache_control: object.cache_control.clone(),
                content_disposition: object.content_disposition.clone(),
                content_encoding: object.content_encoding.clone(),
                content_language: object.content_language.clone(),
                expires: object.expires.clone().map(Into::into),
                metadata: object.metadata.clone(),
                storage_class: storage_class_header(object),
                // `x-amz-restore` when a retrieval was asked for, and no header at all when none
                // was: the absence is the observation that this copy was never archived or never
                // retrieved (q-restore-0002).
                restore: restore_header(object),
                tag_count: tag_count_header(object),
                body: Some(ByteStream::from_bytes(bytes::Bytes::from(body))),
                ..dto::GetObjectOutput::default()
            },
            status,
        ))
    }

    fn get_object_attributes(&self, input: &dto::GetObjectAttributesInput) -> HandlerResult<dto::GetObjectAttributes> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let selected = match input.version_id.as_deref() {
            Some(version_id) => Selected::Object(select_named(&fixture, input.bucket.as_str(), input.key.as_str(), version_id)?),
            None => select_current(&fixture, input.bucket.as_str(), input.key.as_str()),
        };
        let object = match selected {
            Selected::Object(object) => object,
            Selected::Absent => return Err(no_such_key(input.key.as_str())),
            Selected::Deleted(marker) => return Err(deleted_by_marker(input.key.as_str(), marker)),
        };
        let wants_etag = input.object_attributes.iter().any(|attribute| attribute.as_str() == "ETag");
        Ok(Resp::new(dto::GetObjectAttributesOutput {
            last_modified: Some(Timestamp::from_secs(object.last_modified)),
            e_tag: wants_etag.then(|| entity_tag(&object.etag)).transpose()?,
            ..dto::GetObjectAttributesOutput::default()
        }))
    }

    fn head_object(&self, input: &dto::HeadObjectInput) -> HandlerResult<dto::HeadObject> {
        // The same order as `get_object`'s, and for the same reason. A `HEAD` that disagreed with a
        // `GET` about which refusal comes first would be the harder half of the bug to find.
        refuse_conflicting_selectors(input.range.as_ref().map(|range| range.as_str()), input.part_number)?;
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // A named version is resolved before anything conditional: a precondition evaluated against
        // a representation the request cannot reach is not a question, and the two refusals a
        // version id earns — the id names nothing, the id names a deletion — are decided by the
        // version alone.
        let selected = match input.version_id.as_deref() {
            Some(version_id) => Selected::Object(select_named(&fixture, input.bucket.as_str(), input.key.as_str(), version_id)?),
            None => select_current(&fixture, input.bucket.as_str(), input.key.as_str()),
        };
        let found = selected.object();
        let condition = guard_read(
            found,
            input.if_match.as_deref(),
            input.if_unmodified_since.as_ref().map(|stamp| stamp.secs()),
            input.if_none_match.as_deref(),
            input.if_modified_since.as_ref().map(|stamp| stamp.secs()),
            fixture.now,
        )?;
        let object = match selected {
            Selected::Object(object) => object,
            Selected::Absent => return Err(no_such_key(input.key.as_str())),
            Selected::Deleted(marker) => return Err(deleted_by_marker(input.key.as_str(), marker)),
        };
        if condition == ConditionalOutcome::NotModified {
            let e_tag = if condition.includes_selected_etag() {
                Some(entity_tag(&object.etag)?)
            } else {
                None
            };
            return Ok(Resp::with_status(
                dto::HeadObjectOutput {
                    e_tag,
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
        let status = slice.status;
        let checksum = read_checksum(input.checksum_mode.as_ref(), slice.suppress_object_checksum, object.checksum);
        Ok(Resp::with_status(
            dto::HeadObjectOutput {
                content_length: Some(served as i64),
                content_type: object.content_type.clone(),
                content_range: slice.content_range,
                // The same rule as `GetObject`'s: a `HEAD` carries the head a `GET` would, and a
                // client that sized its download from a `HEAD` needs the same part count.
                parts_count: slice.parts_count.map(|count| count as i32),
                accept_ranges: Some("bytes".to_owned()),
                e_tag: Some(entity_tag(&object.etag)?),
                last_modified: Some(Timestamp::from_secs(object.last_modified)),
                // The same rule as `GetObject`'s, for the same reason: a `HEAD` carries the head a
                // `GET` would, so the two would otherwise disagree about the object's integrity.
                checksum_crc32: checksum.crc32,
                checksum_crc32c: checksum.crc32c,
                checksum_crc64nvme: checksum.crc64nvme,
                checksum_sha1: checksum.sha1,
                checksum_sha256: checksum.sha256,
                checksum_sha512: checksum.sha512,
                checksum_md5: checksum.md5,
                checksum_xxhash64: checksum.xxhash64,
                checksum_xxhash3: checksum.xxhash3,
                checksum_xxhash128: checksum.xxhash128,
                checksum_type: checksum.kind,
                cache_control: object.cache_control.clone(),
                content_disposition: object.content_disposition.clone(),
                content_encoding: object.content_encoding.clone(),
                content_language: object.content_language.clone(),
                expires: object.expires.clone().map(Into::into),
                metadata: object.metadata.clone(),
                storage_class: storage_class_header(object),
                // `x-amz-restore` when a retrieval was asked for, and no header at all when none
                // was: the absence is the observation that this copy was never archived or never
                // retrieved (q-restore-0002).
                restore: restore_header(object),
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
    #[cfg(test)]
    fn copy_object(&self, input: &dto::CopyObjectInput) -> HandlerResult<dto::CopyObject> {
        let source = parse_copy_source(&input.copy_source)?;
        self.copy_object_with_source(input, source)
    }

    fn copy_object_with_source(&self, input: &dto::CopyObjectInput, source: CopySource) -> HandlerResult<dto::CopyObject> {
        let metadata_from = directive_of(
            input.metadata_directive.as_ref().map(dto::MetadataDirective::as_str),
            "Unknown metadata directive.",
        )?;
        let tagging_from = directive_of(
            input.tagging_directive.as_ref().map(dto::TaggingDirective::as_str),
            "Unknown tagging directive.",
        )?;
        confirm_source_owner(input.expected_source_bucket_owner.as_deref())?;

        let mut fixture = self.borrow()?;
        let (found, source_version) = read_copy_source(&fixture, &source)?;
        if !copy_source_guards_before_target_write() {
            require_bucket(&fixture, &input.bucket)?;
            fixture.put_object(input.bucket.as_str(), input.key.as_str(), found.clone());
        }
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
        let guarded = if copy_target_uses_source_validators() {
            Some(&found)
        } else {
            existing.as_ref()
        };
        guard_write(guarded, input.if_match.as_deref(), input.if_none_match.as_deref(), now)?;

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
                // A copy is a single write, whatever the source was assembled from, so the part
                // table does not travel with the bytes. Carrying it would let a `partNumber` read
                // of the destination answer windows that describe an upload that never happened.
                part_lengths: Vec::new(),
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
        // Read while the guard is still held, reported only from inside the continuation. This is
        // the one thing a copy can still discover after the head is out: the source resolved, the
        // conditions held, and the bytes were not there when they came to be read.
        let fault = fixture.committed_fault(COPY_OBJECT, source.key.as_str());
        let destination_version = fixture.mint_version(input.bucket.as_str());
        let head = committed_head::<dto::CopyObject>(&[
            ("x-amz-copy-source-version-id", source_version.as_deref()),
            (
                "x-amz-version-id",
                (destination_version != UNVERSIONED).then_some(destination_version.as_str()),
            ),
        ])?;
        // The guard is released before the head goes out: the continuation is `'static` and takes
        // the state back on its own, so nothing holds the fixture across the commit.
        drop(fixture);

        let state = Arc::clone(&self.state);
        let bucket = input.bucket.clone();
        let key = input.key.clone();

        // The head is committed here. Everything below runs with the status line already on the
        // wire, and the only thing it can still report is a failure with no status of its own —
        // which is all a `[setup.fault]` arranged for this operation is able to be.
        Ok(Resp::commit(
            head,
            Box::pin(async move {
                match fault {
                    Some(ArmedFault::Reports(error)) => return Err(error),
                    Some(ArmedFault::StopsMakingProgress) => core::future::pending::<()>().await,
                    None => {}
                }
                let etag = object.etag.clone();
                let checksum = object.checksum.filter(|_| object.checksum_supplied);
                let mut fixture = state
                    .lock()
                    .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
                fixture.put_object_with_version(bucket.as_str(), key.as_str(), object, destination_version.clone());
                drop(fixture);

                Ok(dto::CopyObjectOutput {
                    e_tag: entity_tag(&etag)?,
                    last_modified: Some(Timestamp::from_secs(now)),
                    // Two headers, never one value written into both: one names the version the copy
                    // read and the other the version it created, and a client told they are the same
                    // records the source as its new object.
                    copy_source_version_id: source_version,
                    version_id: (destination_version != UNVERSIONED).then_some(destination_version),
                    ..copy_checksum::copy_result_checksum(checksum.as_ref())
                })
            }),
        ))
    }

    /// One part of a multipart upload, copied out of an object rather than sent.
    ///
    /// Shares the framework's `CopySourceResources` and [`confirm_source_owner`] with
    /// [`Stub::copy_object`]. Both advisories on this family were a part copy that authorized the
    /// upload it wrote to and never the object it read from, so both operations must consume the
    /// same proof-gated source type.
    fn upload_part_copy_with_source(
        &self,
        input: &dto::UploadPartCopyInput,
        source: CopySource,
    ) -> HandlerResult<dto::UploadPartCopy> {
        confirm_source_owner(input.expected_source_bucket_owner.as_deref())?;

        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let (handle, _) = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
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
        let etag = fixture.put_part(handle.id(), input.part_number, bytes);

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
    /// `versionId` is honoured rather than refused, the way the ACL family next door honours it: the
    /// tag set lives on the version, so the named one can be answered exactly. Ignoring the
    /// parameter would report the *current* labels as the named version's — a wrong answer wearing
    /// a `200`, which is worse than the gap the refusal used to be. An id this fixture never minted
    /// for this key is `NoSuchVersion`, and a version that is a delete marker has no tag set.
    fn get_object_tagging(&self, input: &dto::GetObjectTaggingInput) -> HandlerResult<dto::GetObjectTagging> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let requested = input.version_id.as_deref();
        let reported = reported_tagging_version(&fixture, input.bucket.as_str(), input.key.as_str(), requested);
        let object = match requested {
            None => fixture
                .object(input.bucket.as_str(), input.key.as_str())
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
            Some(version_id) => {
                let version = fixture
                    .version(input.bucket.as_str(), input.key.as_str(), version_id)
                    .ok_or_else(no_such_version)?;
                let last_modified = version.last_modified;
                version
                    .object
                    .as_ref()
                    .ok_or_else(|| tagging_delete_marker(version_id, last_modified))?
            }
        };
        Ok(Resp::new(dto::GetObjectTaggingOutput {
            tag_set: tag_elements(&object.tags),
            version_id: reported,
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
        let requested = input.version_id.clone();
        // Resolved before the writable borrow, because the reported id is read off the fixture and
        // the write holds it exclusively.
        let reported = reported_tagging_version(&fixture, input.bucket.as_str(), input.key.as_str(), requested.as_deref());
        let object = match requested.as_deref() {
            None => fixture
                .object_mut(input.bucket.as_str(), input.key.as_str())
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
            Some(version_id) => {
                let version = fixture
                    .version_mut(input.bucket.as_str(), input.key.as_str(), version_id)
                    .ok_or_else(no_such_version)?;
                let last_modified = version.last_modified;
                version
                    .object
                    .as_mut()
                    .ok_or_else(|| tagging_delete_marker(version_id, last_modified))?
            }
        };
        object.tags = pairs;
        Ok(Resp::new(dto::PutObjectTaggingOutput { version_id: reported }))
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
        let requested = input.version_id.clone();
        let reported = reported_tagging_version(&fixture, input.bucket.as_str(), input.key.as_str(), requested.as_deref());
        let object = match requested.as_deref() {
            None => fixture
                .object_mut(input.bucket.as_str(), input.key.as_str())
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
            Some(version_id) => {
                let version = fixture
                    .version_mut(input.bucket.as_str(), input.key.as_str(), version_id)
                    .ok_or_else(no_such_version)?;
                let last_modified = version.last_modified;
                version
                    .object
                    .as_mut()
                    .ok_or_else(|| tagging_delete_marker(version_id, last_modified))?
            }
        };
        object.tags.clear();
        Ok(Resp::new(dto::DeleteObjectTaggingOutput { version_id: reported }))
    }

    /// The bucket's access control policy — always a `200`, never a `404`.
    ///
    /// This is the family's defining difference from every other bucket subresource read in this
    /// file: `?cors`, `?lifecycle`, `?encryption`, `?replication` and `?object-lock` each answer
    /// an operation-specific not-found for a bucket that was never configured, and this one
    /// answers the owner's `FULL_CONTROL`, because an ACL is not something a bucket can be
    /// without. The bucket itself still has to exist.
    fn get_bucket_acl(&self, input: &dto::GetBucketAclInput) -> HandlerResult<dto::GetBucketAcl> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture.bucket_acl(input.bucket.as_str()).cloned().unwrap_or_else(default_acl);
        Ok(Resp::new(dto::GetBucketAclOutput {
            owner: stored.owner,
            grants: stored.grants,
        }))
    }

    /// The whole policy, replaced — after the one channel decision every backend shares.
    ///
    /// `rustfs_gateway::resolve_input` is called rather than mirrored: which of the two channels
    /// the request used, whether it used both or neither, whether the canned value is one a
    /// bucket accepts and whether each grant header parses are all its questions, and a second
    /// copy of any of them here would be the drift the shared contract exists to prevent. What
    /// comes back is already canonicalised, so what is stored carries the `xsi:type` the read
    /// writes back as an attribute.
    fn put_bucket_acl(&self, input: &dto::PutBucketAclInput) -> HandlerResult<dto::PutBucketAcl> {
        let headers = acl_headers(
            input.acl.as_ref(),
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_write.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write_acp.as_ref(),
        );
        let resolved = resolve_acl_input(headers, input.access_control_policy.clone(), AclTarget::Bucket).map_err(refused_acl)?;
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.set_bucket_acl(input.bucket.as_str(), policy_of(resolved));
        Ok(Resp::new(dto::PutBucketAclOutput::default()))
    }

    /// One object version's policy, defaulting the same way the bucket read does.
    ///
    /// `versionId` is honoured rather than refused, as it is for the tagging reads next door and
    /// unlike the lock-state ones: an ACL is held on the version, so the named one can be answered
    /// exactly. An id this fixture never minted is `NoSuchVersion`, and a version that is a delete
    /// marker has no object and therefore no policy.
    fn get_object_acl(&self, input: &dto::GetObjectAclInput) -> HandlerResult<dto::GetObjectAcl> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let object = match input.version_id.as_deref() {
            None => fixture
                .object(input.bucket.as_str(), input.key.as_str())
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
            Some(version_id) => fixture
                .version(input.bucket.as_str(), input.key.as_str(), version_id)
                .ok_or_else(no_such_version)?
                .object
                .as_ref()
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
        };
        let stored = object.acl.clone().unwrap_or_else(default_acl);
        Ok(Resp::new(dto::GetObjectAclOutput {
            owner: stored.owner,
            grants: stored.grants,
            ..dto::GetObjectAclOutput::default()
        }))
    }

    /// One object version's policy, replaced.
    ///
    /// The write is in place, for the tagging family's reason: a permission change is not a new
    /// representation of the object, so no version is minted and the bytes, the entity tag and
    /// `Last-Modified` are left exactly as they were.
    fn put_object_acl(&self, input: &dto::PutObjectAclInput) -> HandlerResult<dto::PutObjectAcl> {
        let headers = acl_headers(
            input.acl.as_ref(),
            input.grant_full_control.as_ref(),
            input.grant_read.as_ref(),
            input.grant_write.as_ref(),
            input.grant_read_acp.as_ref(),
            input.grant_write_acp.as_ref(),
        );
        let resolved = resolve_acl_input(headers, input.access_control_policy.clone(), AclTarget::Object).map_err(refused_acl)?;
        let policy = policy_of(resolved);
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let object = match input.version_id.clone() {
            None => fixture
                .object_mut(input.bucket.as_str(), input.key.as_str())
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
            Some(version_id) => fixture
                .version_mut(input.bucket.as_str(), input.key.as_str(), &version_id)
                .ok_or_else(no_such_version)?
                .object
                .as_mut()
                .ok_or_else(|| no_such_key(input.key.as_str()))?,
        };
        object.acl = Some(policy);
        Ok(Resp::new(dto::PutObjectAclOutput::default()))
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
            .ok_or_else(|| not_configured::<dto::GetBucketTagging>("The TagSet does not exist"))?;
        Ok(Resp::new(dto::GetBucketTaggingOutput {
            tag_set: tag_elements(tags),
        }))
    }

    /// The whole bucket tag set, replaced — under the bucket scope's ceilings.
    ///
    /// The same shared validator the object write goes through, with `TagScope::Bucket` naming
    /// the one rule that differs: fifty tags rather than ten. An empty `<TagSet/>` does reach here
    /// and clears the set (`c-tagging-0005`): `required` on `TagSet` says the wrapper must be
    /// present, not that the list must have a member, and AWS documents the empty tag set as
    /// deleting the existing one. The empty-to-`None` collapse below is what makes the cleared
    /// bucket answer `404 NoSuchTagSet` on the next read rather than a `200` with nothing in it —
    /// "labelled with nothing" is not a state this scope has.
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

    fn delete_objects<'a>(
        &self,
        bucket: &BucketName,
        quiet: bool,
        objects: impl IntoIterator<Item = (&'a ObjectKey, Option<&'a str>)>,
    ) -> HandlerResult<dto::DeleteObjects> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, bucket)?;
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        let locked = fixture.has_object_lock(bucket.as_str());
        for (key, version_id) in objects {
            // Deleting a *version* is where `setup.buckets[].object_lock` becomes observable. On a
            // lock-enabled bucket removing a version needs `s3:BypassGovernanceRetention`, and the
            // refusal is an authorisation decision taken before the version is looked up — so the
            // answer is `AccessDenied` and it does not disclose whether the version exists. Without
            // object lock the fixture keeps no version history, so the same request is a per-key
            // `NoSuchVersion`. Reporting either per key rather than failing the whole request is
            // the shape this operation is being measured for.
            if let Some(version) = version_id {
                let (code, message) = if locked {
                    ("AccessDenied", "Access Denied")
                } else {
                    ("NoSuchVersion", "The specified version does not exist.")
                };
                errors.push(dto::Error {
                    key: Some(key.clone()),
                    version_id: Some(version.to_owned()),
                    code: Some(code.to_owned()),
                    message: Some(message.to_owned()),
                });
                continue;
            }
            fixture.remove_object(bucket.as_str(), key.as_str());
            if !quiet {
                deleted.push(dto::DeletedObject {
                    key: Some(key.clone()),
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

    /// The bucket's region, with the us-east-1 answer being no constraint at all.
    ///
    /// Answered from the bucket's own `[[setup.buckets]] region`, not from a constant: an output
    /// that is the same value for every bucket cannot show the difference between the unwrapped
    /// body AWS sends and the generic wrapper `q-unwrapped-0001` records as the shipped defect.
    /// With `LocationConstraint` absent the two spellings render identical bytes — the root is
    /// written either way and the only member is omitted — so a case written against the constant
    /// is a case that cannot fail. `us-east-1` is excluded by name rather than by comparison with
    /// the fixture's home region, because AWS's null constraint is a fact about that one region
    /// and not about wherever the deployment happens to live.
    ///
    /// There is deliberately no redirect here: `GetBucketLocation` is answerable from any region,
    /// which is what makes it the operation a client uses to find out where a bucket is.
    fn get_bucket_location(&self, input: &dto::GetBucketLocationInput) -> HandlerResult<dto::GetBucketLocation> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let location_constraint = match fixture.bucket_region(input.bucket.as_str()) {
            None | Some("us-east-1") => None,
            Some(region) => Some(
                dto::LocationConstraint::VALUES
                    .iter()
                    .find(|known| **known == region)
                    .copied()
                    .map(dto::LocationConstraint::from)
                    // A `[[setup.buckets]] region` outside the pinned model would otherwise be
                    // reported as "this bucket is in us-east-1", which is a wrong answer wearing a
                    // valid shape.
                    .ok_or_else(|| HandlerError::internal_error("the fixture holds a bucket region the model does not name"))?,
            ),
        };
        Ok(Resp::new(dto::GetBucketLocationOutput { location_constraint }))
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

    /// Creates a bucket, or answers the region-dependent duplicate matrix.
    ///
    /// The constraint is judged first — `resolve_location_constraint` is the exported contract,
    /// carrying the us-east-1 omission rule, the `EU` alias and the strict match against the
    /// deployment's one region — so a request that is wrong about the region never reaches the
    /// ownership question. The three duplicate outcomes are S3's: another owner's name is
    /// `BucketAlreadyExists`, your own bucket is `BucketAlreadyOwnedByYou` — except in us-east-1,
    /// whose historical answer for your own bucket is a plain 200.
    fn create_bucket(&self, input: &dto::CreateBucketInput) -> HandlerResult<dto::CreateBucket> {
        let mut fixture = self.borrow()?;
        let name = input.bucket.as_str().to_owned();
        let constraint = input
            .create_bucket_configuration
            .as_ref()
            .and_then(|configuration| configuration.location_constraint.as_ref())
            .map(dto::LocationConstraint::as_str);
        let home = fixture.home_region.clone();
        let regions = RegionSet::new([home.as_str()])
            .map_err(|_| HandlerError::internal_error("the fixture's home region is not a valid region name"))?;
        // `REGION_MATCH_POLICY` rather than a policy chosen here: the posture belongs to the
        // operation's declaration, and a backend that picked its own would be the second copy that
        // stops matching the first.
        resolve_location_constraint(constraint, &regions, REGION_MATCH_POLICY)?;
        if fixture.has_bucket(&name) {
            if fixture.is_owned_by_other(&name) {
                return Err(HandlerError::new(
                    ErrorCode::BUCKET_ALREADY_EXISTS,
                    "The requested bucket name is not available. The bucket namespace is shared by all users of the \
                     system. Please select a different name and try again.",
                ));
            }
            let owned_region = fixture.bucket_region(&name);
            if owned_region.is_none_or(|region| region == home) && home == "us-east-1" {
                return Ok(Resp::new(dto::CreateBucketOutput {
                    location: Some(format!("/{name}")),
                }));
            }
            return Err(HandlerErrorContext::owned_bucket_recreation().into());
        } else {
            fixture.declare_bucket(&name, false);
        }
        Ok(Resp::new(dto::CreateBucketOutput {
            location: Some(format!("/{name}")),
        }))
    }

    /// Deletes a bucket that is here, empty, and yours.
    fn delete_bucket(&self, input: &dto::DeleteBucketInput) -> HandlerResult<dto::DeleteBucket> {
        let mut fixture = self.borrow()?;
        let name = input.bucket.as_str().to_owned();
        require_bucket(&fixture, &input.bucket)?;
        redirect_if_elsewhere(&fixture, &name)?;
        if !fixture.bucket_is_empty(&name) {
            return Err(HandlerError::new(
                ErrorCode::BUCKET_NOT_EMPTY,
                "The bucket you tried to delete is not empty",
            ));
        }
        fixture.remove_bucket(&name);
        Ok(Resp::new(dto::DeleteBucketOutput::default()))
    }

    /// Answers whether the bucket exists here, and in which region.
    ///
    /// The success carries the region because the output type gives it no choice: `BucketRegion`
    /// is a required member, so a 200 without `x-amz-bucket-region` is unconstructible. Every
    /// error path is status-and-headers only — the zero-body half is the response layer's HEAD
    /// invariant, which the corpus pins.
    fn head_bucket(&self, input: &dto::HeadBucketInput) -> HandlerResult<dto::HeadBucket> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let name = input.bucket.as_str();
        redirect_if_elsewhere(&fixture, name)?;
        Ok(Resp::new(dto::HeadBucketOutput {
            bucket_region: fixture.home_region.clone(),
        }))
    }

    /// The stored lifecycle document, or the family's defining 404.
    ///
    /// The bucket is resolved first, so a missing bucket is `NoSuchBucket` and only a bucket that
    /// exists without a document is `NoSuchLifecycleConfiguration` — two different facts a client
    /// tearing down configuration branches on. The transition-minimum header comes back only when
    /// the write that stored the document carried it: the fixture invents no default.
    fn get_bucket_lifecycle_configuration(
        &self,
        input: &dto::GetBucketLifecycleConfigurationInput,
    ) -> HandlerResult<dto::GetBucketLifecycleConfiguration> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture
            .lifecycle(input.bucket.as_str())
            .ok_or_else(no_such_lifecycle_configuration)?;
        Ok(Resp::new(dto::GetBucketLifecycleConfigurationOutput {
            rules: stored.configuration.rules.clone(),
            transition_default_minimum_object_size: stored.minimum_object_size.clone(),
        }))
    }

    /// The whole document, replaced — after the one validation pass every backend shares.
    ///
    /// The rules are `rustfs_gateway::validate_lifecycle`'s, not this file's: the filter grammar,
    /// the expiration mutex, the midnight rule and the caps live once in the shared contract, and
    /// this fixture calls it rather than mirroring it. What is stored is exactly what was sent,
    /// in the order it was sent — the read-back is a byte-level golden, and that includes the
    /// leniencies: an unknown `Status` spelling is stored as sent, not corrected.
    fn put_bucket_lifecycle_configuration(
        &self,
        input: &dto::PutBucketLifecycleConfigurationInput,
    ) -> HandlerResult<dto::PutBucketLifecycleConfiguration> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // The generated decoder always hands a document; the guard covers a caller that builds
        // the input by hand, and answers what an absent body deserves.
        let Some(configuration) = input.lifecycle_configuration.as_ref() else {
            return Err(HandlerError::new(ErrorCode::MALFORMED_XML, "the request carries no lifecycle document"));
        };
        validate_lifecycle(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_lifecycle(
            input.bucket.as_str(),
            configuration.clone(),
            input.transition_default_minimum_object_size.clone(),
        );
        Ok(Resp::new(dto::PutBucketLifecycleConfigurationOutput {
            transition_default_minimum_object_size: input.transition_default_minimum_object_size.clone(),
        }))
    }

    /// The document removed, the bucket left alone.
    ///
    /// The `204` is unconditional in the same sense `DeleteBucketCors`'s is: removing the
    /// lifecycle configuration of a bucket that has none is a success, not a `404`. The bucket
    /// itself still has to exist — a success for a bucket that is not there would tell a caller
    /// its teardown landed on something.
    fn delete_bucket_lifecycle(&self, input: &dto::DeleteBucketLifecycleInput) -> HandlerResult<dto::DeleteBucketLifecycle> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.clear_lifecycle(input.bucket.as_str());
        Ok(Resp::new(dto::DeleteBucketLifecycleOutput::default()))
    }

    /// The stored default-encryption document, or the family's defining 404.
    ///
    /// The bucket is resolved first, so a missing bucket is `NoSuchBucket` and only a bucket
    /// that exists without a document is `ServerSideEncryptionConfigurationNotFoundError` — two
    /// different facts a client tearing down configuration branches on.
    fn get_bucket_encryption(&self, input: &dto::GetBucketEncryptionInput) -> HandlerResult<dto::GetBucketEncryption> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture
            .encryption(input.bucket.as_str())
            .ok_or_else(no_such_encryption_configuration)?;
        Ok(Resp::new(dto::GetBucketEncryptionOutput {
            server_side_encryption_configuration: Some(stored.clone()),
        }))
    }

    /// The whole document, replaced — after the one validation pass every backend shares.
    ///
    /// The rules are `rustfs_gateway::validate_encryption`'s, not this file's: the closed
    /// `SSEAlgorithm` set and the KMS-key-id/algorithm agreement live once in the shared
    /// contract, and this fixture calls it rather than mirroring it. What is stored is exactly
    /// what was sent, in the order it was sent — the read-back is a byte-level golden, and that
    /// includes the leniencies: an unknown element was already skipped by the decoder, and a
    /// multi-rule document is stored whole.
    fn put_bucket_encryption(&self, input: &dto::PutBucketEncryptionInput) -> HandlerResult<dto::PutBucketEncryption> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.server_side_encryption_configuration;
        validate_encryption(configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason().to_owned()))?;
        fixture.set_encryption(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketEncryptionOutput::default()))
    }

    /// The document removed, the bucket left alone.
    ///
    /// The `204` is unconditional in the same sense `DeleteBucketLifecycle`'s is: removing the
    /// encryption configuration of a bucket that has none is a success, not a `404`. The bucket
    /// itself still has to exist — a success for a bucket that is not there would tell a caller
    /// its teardown landed on something.
    fn delete_bucket_encryption(&self, input: &dto::DeleteBucketEncryptionInput) -> HandlerResult<dto::DeleteBucketEncryption> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        if fixture.encryption(input.bucket.as_str()).is_none() && !encryption_delete_absent_succeeds() {
            return Err(no_such_encryption_configuration());
        }
        fixture.clear_encryption(input.bucket.as_str());
        Ok(Resp::new(dto::DeleteBucketEncryptionOutput::default()))
    }

    /// The stored replication document, or the family's defining 404.
    ///
    /// The bucket is resolved first, so a missing bucket is `NoSuchBucket` and only a bucket
    /// that exists without a document is `ReplicationConfigurationNotFoundError` — two
    /// different facts a client tearing down configuration branches on.
    fn get_bucket_replication(&self, input: &dto::GetBucketReplicationInput) -> HandlerResult<dto::GetBucketReplication> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture
            .replication(input.bucket.as_str())
            .ok_or_else(no_such_replication_configuration)?;
        Ok(Resp::new(dto::GetBucketReplicationOutput {
            replication_configuration: Some(stored.clone()),
        }))
    }

    /// The whole document, replaced — after the one validation pass every backend shares.
    ///
    /// The rules are `rustfs_gateway::validate_replication`'s, not this file's: the V1/V2
    /// schema couplings, the filter grammar and the `ID` bounds live once in the shared
    /// contract, and this fixture calls it rather than mirroring it. What is stored is exactly
    /// what was sent, in the order it was sent — the read-back is a byte-level golden, and that
    /// includes the leniencies: an unknown element was already skipped by the decoder, an
    /// out-of-set `Status` and a duplicated `Priority` are stored whole. The
    /// `x-amz-bucket-object-lock-token` header is available on the input and deliberately
    /// unread: whether the token permits enabling Object Lock is a semantic question this stub,
    /// like the codec, does not answer (`q-repl-0013`).
    fn put_bucket_replication(&self, input: &dto::PutBucketReplicationInput) -> HandlerResult<dto::PutBucketReplication> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.replication_configuration;
        validate_replication(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_replication(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketReplicationOutput::default()))
    }

    /// The document removed, the bucket left alone.
    ///
    /// The `204` is unconditional in the same sense `DeleteBucketEncryption`'s is: removing the
    /// replication configuration of a bucket that has none is a success, not a `404`. The
    /// bucket itself still has to exist — a success for a bucket that is not there would tell a
    /// caller its teardown landed on something.
    fn delete_bucket_replication(
        &self,
        input: &dto::DeleteBucketReplicationInput,
    ) -> HandlerResult<dto::DeleteBucketReplication> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.clear_replication(input.bucket.as_str());
        Ok(Resp::new(dto::DeleteBucketReplicationOutput::default()))
    }

    // =========================================================================================
    // The bucket-configuration band at 200-242.
    //
    // Nine subresources, and the thing worth reading them together for is the unconfigured
    // answer, which differs three ways. Six of the reads below turn a missing document into a
    // `200` — five into an empty document and one, `?requestPayment`, into a documented default
    // value — while three turn it into a `404` with three literals that are not interchangeable.
    // Every one of those nine answers is produced here by an explicit branch, so a case that
    // expects the wrong one fails rather than being absorbed.
    // =========================================================================================

    /// The versioning state, or the empty document a never-versioned bucket answers.
    ///
    /// `None` becomes `VersioningConfigurationOutput` with **no** `Status` — not `Suspended`, and
    /// not a `404`. The three are different facts: never versioned, versioned and stopped, and no
    /// such bucket.
    fn get_bucket_versioning(&self, input: &dto::GetBucketVersioningInput) -> HandlerResult<dto::GetBucketVersioning> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture.versioning(input.bucket.as_str());
        unconfigured::<dto::GetBucketVersioning>(stored.is_none())?;
        Ok(Resp::new(dto::GetBucketVersioningOutput {
            status: stored.and_then(|configuration| configuration.status.clone()),
            mfa_delete: stored.and_then(|configuration| configuration.mfa_delete.clone()),
        }))
    }

    /// The versioning state, replaced, after the shared closed-set check.
    ///
    /// `x-amz-mfa` is available on the input and deliberately unread: whether the device and code
    /// it names authorise the change is a semantic question this stub, like the codec, does not
    /// answer. It is never echoed and never appears in a refusal.
    fn put_bucket_versioning(&self, input: &dto::PutBucketVersioningInput) -> HandlerResult<dto::PutBucketVersioning> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.versioning_configuration;
        validate_versioning(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_versioning(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketVersioningOutput::default()))
    }

    /// The acceleration state, or the empty document an unconfigured bucket answers.
    fn get_bucket_accelerate_configuration(
        &self,
        input: &dto::GetBucketAccelerateConfigurationInput,
    ) -> HandlerResult<dto::GetBucketAccelerateConfiguration> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture.accelerate(input.bucket.as_str());
        unconfigured::<dto::GetBucketAccelerateConfiguration>(stored.is_none())?;
        Ok(Resp::new(dto::GetBucketAccelerateConfigurationOutput {
            status: stored.and_then(|configuration| configuration.status.clone()),
            ..dto::GetBucketAccelerateConfigurationOutput::default()
        }))
    }

    /// The acceleration state, replaced. No integrity claim is required of the request: this is
    /// one of the two writes in the band the model exempts.
    fn put_bucket_accelerate_configuration(
        &self,
        input: &dto::PutBucketAccelerateConfigurationInput,
    ) -> HandlerResult<dto::PutBucketAccelerateConfiguration> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.accelerate_configuration;
        validate_accelerate(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_accelerate(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketAccelerateConfigurationOutput::default()))
    }

    /// Who pays, or the documented default for a bucket that was never switched.
    ///
    /// This is the band's third shape of unconfigured answer: not a `404`, and not an empty
    /// document either — `BucketOwner`, because every bucket has a payer.
    fn get_bucket_request_payment(
        &self,
        input: &dto::GetBucketRequestPaymentInput,
    ) -> HandlerResult<dto::GetBucketRequestPayment> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        unconfigured::<dto::GetBucketRequestPayment>(fixture.request_payment(input.bucket.as_str()).is_none())?;
        let payer = fixture
            .request_payment(input.bucket.as_str())
            .map_or_else(|| dto::Payer::BUCKETOWNER, |configuration| configuration.payer.clone());
        Ok(Resp::new(dto::GetBucketRequestPaymentOutput { payer: Some(payer) }))
    }

    /// Who pays, switched, after the shared closed-set check.
    fn put_bucket_request_payment(
        &self,
        input: &dto::PutBucketRequestPaymentInput,
    ) -> HandlerResult<dto::PutBucketRequestPayment> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.request_payment_configuration;
        validate_request_payment(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_request_payment(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketRequestPaymentOutput::default()))
    }

    /// The logging destination, or the empty document a bucket that is not logging answers.
    fn get_bucket_logging(&self, input: &dto::GetBucketLoggingInput) -> HandlerResult<dto::GetBucketLogging> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture.logging(input.bucket.as_str());
        unconfigured::<dto::GetBucketLogging>(stored.is_none())?;
        Ok(Resp::new(dto::GetBucketLoggingOutput {
            logging_enabled: stored.and_then(|configuration| configuration.logging_enabled.clone()),
        }))
    }

    /// The logging destination, replaced — and an empty document is how logging is turned off,
    /// because the model declares no delete for this subresource.
    ///
    /// `<TargetGrants>` reaches the ACL family's `Grantee` through this document, which makes this
    /// the second producer of that element in the tree and puts it under the same rule. It goes
    /// through the ACL family's own `canonicalize_grantee` and not through a second check of this
    /// family's invention: that one function both refuses an `xsi:type` outside the closed set and
    /// derives the stored discriminator from the identifying member, and a copy here that did only
    /// the second would echo back a `<Grantee>` whose type this side never validated
    /// (`q-acl-0003`, `q-acl-0004`).
    fn put_bucket_logging(&self, input: &dto::PutBucketLoggingInput) -> HandlerResult<dto::PutBucketLogging> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let mut configuration = input.bucket_logging_status.clone();
        validate_logging(&configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        if let Some(enabled) = configuration.logging_enabled.as_mut() {
            for grant in enabled.target_grants.iter_mut().flatten() {
                if let Some(grantee) = grant.grantee.as_mut() {
                    canonicalize_grantee(grantee).map_err(refused_acl)?;
                }
            }
        }
        fixture.set_logging(input.bucket.as_str(), configuration);
        Ok(Resp::new(dto::PutBucketLoggingOutput::default()))
    }

    /// The notification document, or the empty one a bucket delivering nothing answers.
    ///
    /// What is stored is echoed member for member, in the order it was sent: the read-back is a
    /// byte-level golden, and that is where the flattened list shape becomes observable.
    fn get_bucket_notification_configuration(
        &self,
        input: &dto::GetBucketNotificationConfigurationInput,
    ) -> HandlerResult<dto::GetBucketNotificationConfiguration> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        unconfigured::<dto::GetBucketNotificationConfiguration>(fixture.notification(input.bucket.as_str()).is_none())?;
        let stored = fixture.notification(input.bucket.as_str()).cloned().unwrap_or_default();
        Ok(Resp::new(dto::GetBucketNotificationConfigurationOutput {
            topic_configurations: stored.topic_configurations,
            queue_configurations: stored.queue_configurations,
            lambda_function_configurations: stored.lambda_function_configurations,
            event_bridge_configuration: stored.event_bridge_configuration,
        }))
    }

    /// The notification document, replaced. The empty document is accepted and means "deliver
    /// nothing": there is no delete operation to say it any other way.
    fn put_bucket_notification_configuration(
        &self,
        input: &dto::PutBucketNotificationConfigurationInput,
    ) -> HandlerResult<dto::PutBucketNotificationConfiguration> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.notification_configuration;
        validate_notification(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_notification(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketNotificationConfigurationOutput::default()))
    }

    /// The website document, or this subresource's own `404`.
    fn get_bucket_website(&self, input: &dto::GetBucketWebsiteInput) -> HandlerResult<dto::GetBucketWebsite> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture
            .website(input.bucket.as_str())
            .ok_or_else(no_such_website_configuration)?;
        Ok(Resp::new(dto::GetBucketWebsiteOutput {
            error_document: stored.error_document.clone(),
            index_document: stored.index_document.clone(),
            redirect_all_requests_to: stored.redirect_all_requests_to.clone(),
            routing_rules: stored.routing_rules.clone(),
        }))
    }

    /// The website document, replaced, after the shared exclusion and rewrite checks.
    fn put_bucket_website(&self, input: &dto::PutBucketWebsiteInput) -> HandlerResult<dto::PutBucketWebsite> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.website_configuration;
        validate_website(configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_website(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutBucketWebsiteOutput::default()))
    }

    /// The website document removed. `204` whether or not one was there, even though the read of
    /// the same unconfigured bucket is a `404`.
    fn delete_bucket_website(&self, input: &dto::DeleteBucketWebsiteInput) -> HandlerResult<dto::DeleteBucketWebsite> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.clear_website(input.bucket.as_str());
        Ok(Resp::new(dto::DeleteBucketWebsiteOutput::default()))
    }

    /// The stored policy, answered as the bytes that were written.
    ///
    /// Not a re-serialisation of a parse: the documented behaviour is that the read hands back the
    /// document the write sent, and a gateway that normalised it would hand a client a policy it
    /// cannot compare with the one it stored.
    fn get_bucket_policy(&self, input: &dto::GetBucketPolicyInput) -> HandlerResult<dto::GetBucketPolicy> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture.policy(input.bucket.as_str()).ok_or_else(no_such_bucket_policy)?;
        Ok(Resp::new(dto::GetBucketPolicyOutput {
            policy: Some(stored.to_owned()),
        }))
    }

    /// The policy, replaced, after the three checks a gateway is allowed to make.
    ///
    /// `validate_policy` asks whether the document is within the size ceiling, is JSON, and is an
    /// object. It asks nothing about what the policy *grants*, and neither does this: the verdict
    /// the status read reports is the case's declaration, not a computation, because this
    /// workspace contains no policy evaluator and a fixture that invented one would be asserting
    /// its own guess. A write therefore leaves the previous verdict alone unless the case sets it.
    fn put_bucket_policy(&self, input: &dto::PutBucketPolicyInput) -> HandlerResult<dto::PutBucketPolicy> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        validate_policy(&input.policy).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let verdict = fixture.policy_is_public(input.bucket.as_str());
        fixture.set_policy(input.bucket.as_str(), input.policy.clone(), verdict);
        Ok(Resp::new(dto::PutBucketPolicyOutput::default()))
    }

    /// The policy removed. `204` whether or not one was there.
    fn delete_bucket_policy(&self, input: &dto::DeleteBucketPolicyInput) -> HandlerResult<dto::DeleteBucketPolicy> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.clear_policy(input.bucket.as_str());
        Ok(Resp::new(dto::DeleteBucketPolicyOutput::default()))
    }

    /// Whether the stored policy makes the bucket public.
    ///
    /// A bucket with no policy has no status to report and answers the policy read's own `404`,
    /// because it is the same missing document.
    fn get_bucket_policy_status(&self, input: &dto::GetBucketPolicyStatusInput) -> HandlerResult<dto::GetBucketPolicyStatus> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        if fixture.policy(input.bucket.as_str()).is_none() {
            return Err(no_such_bucket_policy_status());
        }
        Ok(Resp::new(dto::GetBucketPolicyStatusOutput {
            policy_status: Some(dto::PolicyStatus {
                is_public: Some(fixture.policy_is_public(input.bucket.as_str())),
            }),
        }))
    }

    /// The four switches, or this subresource's own `404`.
    fn get_public_access_block(&self, input: &dto::GetPublicAccessBlockInput) -> HandlerResult<dto::GetPublicAccessBlock> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture
            .public_access_block(input.bucket.as_str())
            .ok_or_else(no_such_public_access_block)?;
        Ok(Resp::new(dto::GetPublicAccessBlockOutput {
            public_access_block_configuration: Some(stored.clone()),
        }))
    }

    /// The four switches, replaced. An omitted switch is stored as omitted and read back as
    /// `false`, which is the same thing: the read renders every one of the four.
    fn put_public_access_block(&self, input: &dto::PutPublicAccessBlockInput) -> HandlerResult<dto::PutPublicAccessBlock> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.public_access_block_configuration;
        validate_public_access_block(configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_public_access_block(
            input.bucket.as_str(),
            dto::PublicAccessBlockConfiguration {
                block_public_acls: Some(configuration.block_public_acls.unwrap_or(false)),
                ignore_public_acls: Some(configuration.ignore_public_acls.unwrap_or(false)),
                block_public_policy: Some(configuration.block_public_policy.unwrap_or(false)),
                restrict_public_buckets: Some(configuration.restrict_public_buckets.unwrap_or(false)),
            },
        );
        Ok(Resp::new(dto::PutPublicAccessBlockOutput::default()))
    }

    /// The four switches removed. `204` whether or not they were there.
    fn delete_public_access_block(
        &self,
        input: &dto::DeletePublicAccessBlockInput,
    ) -> HandlerResult<dto::DeletePublicAccessBlock> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.clear_public_access_block(input.bucket.as_str());
        Ok(Resp::new(dto::DeletePublicAccessBlockOutput::default()))
    }

    /// The bucket's object-lock document, or the family's bucket-level 404.
    ///
    /// `ObjectLockConfigurationNotFoundError` and `NoSuchBucket` are different answers to
    /// different questions, and the object reads below answer a *third* code for the same
    /// unconfigured shape — three states a single not-found would flatten into one, and
    /// compliance tooling branches on all three.
    fn get_object_lock_configuration(
        &self,
        input: &dto::GetObjectLockConfigurationInput,
    ) -> HandlerResult<dto::GetObjectLockConfiguration> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let stored = fixture
            .lock_configuration(input.bucket.as_str())
            .ok_or_else(object_lock_configuration_not_found)?;
        Ok(Resp::new(dto::GetObjectLockConfigurationOutput {
            object_lock_configuration: Some(stored),
        }))
    }

    /// The whole lock document, replaced — and, per AWS, how object lock is switched on.
    ///
    /// The rules are `rustfs_gateway::validate_lock_configuration`'s, not this file's. What is
    /// stored is exactly what was sent: the read-back is a byte-level golden, leniencies
    /// included — an unknown element was already skipped by the decoder, and a configuration
    /// with no rule is a legal document meaning "locked, no default retention".
    ///
    /// Nothing here enforces anything. Enabling object lock on this fixture changes what a
    /// versioned delete answers (`has_object_lock`, which `DeleteObjects` already consults) and
    /// nothing else; a default retention is stored and never applied to a write.
    fn put_object_lock_configuration(
        &self,
        input: &dto::PutObjectLockConfigurationInput,
    ) -> HandlerResult<dto::PutObjectLockConfiguration> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let configuration = &input.object_lock_configuration;
        validate_lock_configuration(configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        fixture.set_lock_configuration(input.bucket.as_str(), configuration.clone());
        Ok(Resp::new(dto::PutObjectLockConfigurationOutput::default()))
    }

    /// One object version's retention document, or the object-level 404.
    ///
    /// `versionId` selects the version through `lock_state_of`: the named version's document,
    /// never the current one's, and `NoSuchVersion` for an id that names nothing.
    fn get_object_retention(&self, input: &dto::GetObjectRetentionInput) -> HandlerResult<dto::GetObjectRetention> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let object = lock_state_of(&fixture, input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())?;
        let retention = object.retention.clone().ok_or_else(no_such_retention)?;
        Ok(Resp::new(dto::GetObjectRetentionOutput {
            retention: Some(retention),
        }))
    }

    /// The object's retention document, replaced.
    ///
    /// Three refusals before anything is stored, in this order: the bucket must exist, it must
    /// have object lock on (`q-lock-0015` — a retention on an unlocked bucket is a promise no
    /// enforcement path will ever read), and the document must satisfy the shared validator
    /// against *this case's* clock (`q-lock-0013`). The bypass header is decoded by the
    /// generated codec and deliberately not consulted here: what it authorises is enforcement,
    /// and this fixture enforces nothing. The write is in place — protecting an object is not a
    /// new representation of it — so no version is minted and the bytes, the entity tag and
    /// `Last-Modified` are left exactly as they were.
    fn put_object_retention(&self, input: &dto::PutObjectRetentionInput) -> HandlerResult<dto::PutObjectRetention> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        require_object_lock(&fixture, input.bucket.as_str())?;
        let now = fixture.now;
        validate_retention(&input.retention, now).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let object = lock_state_of_mut(&mut fixture, input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())?;
        object.retention = Some(input.retention.clone());
        Ok(Resp::new(dto::PutObjectRetentionOutput::default()))
    }

    /// One object's legal-hold document, or the object-level 404.
    ///
    /// Never a `200` carrying `OFF` for an object that was never held: "no hold was ever placed"
    /// and "a hold was placed and lifted" are different facts, and only the second is a document.
    fn get_object_legal_hold(&self, input: &dto::GetObjectLegalHoldInput) -> HandlerResult<dto::GetObjectLegalHold> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let object = lock_state_of(&fixture, input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())?;
        let legal_hold = object.legal_hold.clone().ok_or_else(no_such_legal_hold)?;
        Ok(Resp::new(dto::GetObjectLegalHoldOutput {
            legal_hold: Some(legal_hold),
        }))
    }

    /// The object's legal-hold document, replaced. `OFF` is stored, not erased.
    ///
    /// Lifting a hold leaves a document saying `OFF`, which is what makes the read answer `200`
    /// afterwards rather than reverting to the never-held 404. The bucket must have object lock
    /// on, for the retention write's reason.
    fn put_object_legal_hold(&self, input: &dto::PutObjectLegalHoldInput) -> HandlerResult<dto::PutObjectLegalHold> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        require_object_lock(&fixture, input.bucket.as_str())?;
        validate_legal_hold(&input.legal_hold).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let object = lock_state_of_mut(&mut fixture, input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())?;
        object.legal_hold = Some(input.legal_hold.clone());
        Ok(Resp::new(dto::PutObjectLegalHoldOutput::default()))
    }

    /// An archive retrieval, in the one of four states the object is actually in.
    ///
    /// The order is fixed and the reasons differ: the document is validated first, because a
    /// request this side cannot read is a `400` whatever the object's class is; then the object
    /// has to exist; then the storage class decides whether a retrieval is even a question.
    ///
    /// **What is a fixture policy and what is not.** The status — `202`, `200`, `409`, `403` —
    /// is [`RestoreState`]'s, from the framework, and this method's only job is to say which
    /// state the copy is in. How long a retrieval takes is the fixture's, and it takes either no
    /// time or forever: an `Expedited` retrieval is back by the time the response is written, and
    /// every other tier is still running. That is a dial the corpus turns, not a claim about S3,
    /// where every tier takes minutes to hours — and it is written down here rather than left for
    /// a reader of a case to infer, because a case that asserts `200` is asserting the framework's
    /// mapping and not this stub's timing.
    fn restore_object(&self, input: &dto::RestoreObjectInput) -> HandlerResult<dto::RestoreObject> {
        let mut fixture = self.borrow()?;
        // The payload is a *required* member, so an empty body was already refused as
        // `MalformedXML` by the generated decoder and never reaches here (q-restore-0006).
        let document = &input.restore_request;
        validate_restore(document).map_err(|rejection| {
            HandlerError::new(
                rejection.code(),
                rejection.reason_with_expression(
                    document
                        .select_parameters
                        .as_ref()
                        .map(|parameters| parameters.expression.as_str()),
                ),
            )
        })?;
        require_bucket(&fixture, &input.bucket)?;
        let expedited = document.glacier_job_parameters.as_ref().map(|parameters| &parameters.tier)
            == Some(&dto::Tier::EXPEDITED)
            || document.tier.as_ref() == Some(&dto::Tier::EXPEDITED);
        let expiry = fixture.restore_expiry();
        // `versionId` selects the copy whose retrieval state changes, and only that one: an id
        // that names nothing is `NoSuchVersion` and one that names a delete marker is `405`, the
        // same selection every other version-scoped write in this file makes.
        let object = lock_state_of_mut(&mut fixture, input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())?;

        let state = if !is_archived(object) {
            RestoreState::NotArchived
        } else {
            match &object.restore {
                None => RestoreState::Initiated,
                Some(status) if status.ongoing => RestoreState::InProgress,
                Some(_) => RestoreState::AlreadyRestored,
            }
        };
        if state == RestoreState::Initiated {
            object.restore = Some(if expedited {
                RestoreStatus::restored(expiry)
            } else {
                RestoreStatus::ongoing()
            });
        }
        // The two refusals answer their own codes, and the two successes answer their own
        // statuses. Both halves come out of the framework's mapping: nothing here writes a number.
        if let Some(code) = state.error() {
            let reason = state.reason().unwrap_or("The restore request could not be served");
            return Err(HandlerError::new(code, reason));
        }
        let status = state.status().unwrap_or(202);
        Ok(Resp::with_status(
            dto::RestoreObjectOutput {
                // Present exactly when the request named one, which is what a select-on-restore
                // asks for and an ordinary retrieval does not.
                restore_output_path: document.output_location.as_ref().and_then(output_path_of),
                ..dto::RestoreObjectOutput::default()
            },
            status,
        ))
    }

    /// A select query, decoded and validated in full, then answered as a framed event stream.
    ///
    /// This fixture does not evaluate SQL: after validating the opaque expression and the input
    /// and output descriptions, it emits the scanned bytes as `Records`, the accounting, and `End`
    /// through [`frame_records`]. Two requests are framed by hand instead, because they need frames
    /// the adapter does not write: one that enables `RequestProgress` (a keep-alive, the records, a
    /// `Progress` and then the accounting) and a CSV or JSON scan that is not UTF-8 (the readable
    /// prefix, then an in-band `InvalidTextEncoding` error and no `End`). The response path under
    /// test is real — the handler returns [`Resp::event_stream`] and the same assembled service
    /// used by ordinary operations writes it.
    fn select_object_content(&self, input: &dto::SelectObjectContentInput) -> HandlerResult<dto::SelectObjectContent> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        validate_select(
            &input.expression,
            &input.expression_type,
            &input.input_serialization,
            &input.output_serialization,
            input.scan_range.as_ref(),
        )
        .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason_with_expression(&input.expression)))?;
        let body = fixture
            .object(input.bucket.as_str(), input.key.as_str())
            .ok_or_else(|| no_such_key(input.key.as_str()))?
            .body
            .clone();
        if !select_uses_event_stream() {
            return Ok(Resp::new(dto::SelectObjectContentOutput::default()));
        }
        let selected = select_scan_bytes(input.scan_range.as_ref(), &body);
        Ok(Resp::event_stream(select_answer::answer(input, selected)))
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
        let (handle, _) = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
        fixture.uploads.remove(handle.id());
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
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let (handle, upload) = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;
        let upload = upload.clone();
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
        if let Err(error) = guard_write(existing.as_ref(), input.if_match.as_deref(), input.if_none_match.as_deref(), fixture.now)
        {
            if !completion_failure_retains_upload() {
                fixture.uploads.remove(handle.id());
            }
            return Err(error);
        }
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
        // Read while the guard is still held, reported only from inside the continuation. A case
        // that armed `[setup.fault]` against this operation has said the completion fails once the
        // status line is spent, and every check above still runs first — which is why arming one
        // cannot turn any of the completions `REFUSED_BEFORE_COMMIT` names into a `200`.
        let fault = fixture.committed_fault(COMPLETE_MULTIPART_UPLOAD, upload.key.as_str());
        let destination_version = fixture.mint_version(&upload.bucket);
        let encryption_header = upload.encryption.as_ref().map(ToString::to_string);
        let head = committed_head::<dto::CompleteMultipartUpload>(&[
            (
                "x-amz-version-id",
                (destination_version != UNVERSIONED).then_some(destination_version.as_str()),
            ),
            ("x-amz-server-side-encryption", encryption_header.as_deref()),
        ])?;
        // The guard is released before the head goes out: the continuation is `'static` and takes
        // the state back on its own, so nothing holds the fixture across the commit.
        drop(fixture);

        let state = Arc::clone(&self.state);
        let upload_id = handle.id().to_owned();
        let bucket = input.bucket.clone();
        let key = input.key.clone();
        let location = format!("/{}/{}", input.bucket.as_str(), input.key.as_str());

        // The head is committed here. Everything below runs with the status line already on the
        // wire, and the only thing it can still report is a failure with no status of its own.
        Ok(Resp::commit(
            head,
            Box::pin(async move {
                match fault {
                    Some(ArmedFault::Reports(error)) => return Err(error),
                    // Nothing below runs: what ends this response is outside this future entirely.
                    Some(ArmedFault::StopsMakingProgress) => core::future::pending::<()>().await,
                    None => {}
                }
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
                let checksum = read_checksum(Some(&dto::ChecksumMode::ENABLED), false, checksum_spec);
                // The entity tag of a multipart object is not the digest of its bytes. It is the digest
                // of the concatenated part digests with the part count after a hyphen, and a client that
                // reads the plain MD5 back would compare it against the composite and conclude the
                // object is corrupt. `ETag::from_part_digests` is the framework's own derivation of that
                // rule, so the two spellings cannot drift.
                let composite = ETag::from_part_digests(&digests)
                    .map_err(|_| HandlerError::internal_error("a part digest set has no entity tag"))?;
                let stored_checksum = checksum_spec
                    .or_else(|| ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &crate::crc32::digest(&assembled)).ok());
                let mut fixture = state
                    .lock()
                    .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
                let now = fixture.now;
                let object = StoredObject {
                    body: assembled,
                    etag: composite.opaque_tag().to_owned(),
                    checksum_supplied: checksum_spec.is_some(),
                    checksum: stored_checksum,
                    last_modified: now,
                    // The part boundaries, recorded here because this is the only moment they exist:
                    // the upload is removed two lines below, and after that the object is the one
                    // witness to how it was assembled. Without them a `partNumber` read has nothing
                    // to resolve against, and `c-range-0007` cannot tell a server that serves part 2
                    // from one that serves the first sixteen bytes of part 1.
                    part_lengths: ordered_parts.iter().map(|part| part.body.len() as u64).collect(),
                    ..upload.attributes.clone()
                };
                fixture.put_object_with_version(&upload.bucket, &upload.key, object, destination_version.clone());
                fixture.uploads.remove(&upload_id);
                drop(fixture);
                Ok(dto::CompleteMultipartUploadOutput {
                    bucket: Some(bucket),
                    key: Some(key),
                    location: Some(location),
                    e_tag: Some(composite),
                    version_id: (destination_version != UNVERSIONED).then_some(destination_version),
                    checksum_crc32: checksum.crc32,
                    checksum_crc32c: checksum.crc32c,
                    checksum_type,
                    // Decided at initiation, reported here. That gap is the whole of what these cases
                    // measure: the completion's head is flushed before the body is assembled, so a value
                    // that is only looked up afterwards can never become a header.
                    server_side_encryption: upload.encryption.clone(),
                    ..dto::CompleteMultipartUploadOutput::default()
                })
            }),
        ))
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
            delimiter: delimiter_of(input.delimiter.as_deref()).map(ToOwned::to_owned),
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
        let (handle, upload) = require_upload(&fixture, &input.upload_id, &input.bucket, &input.key)?;

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
            upload_id: handle.id().to_owned(),
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
        let prefix = input.prefix.clone().unwrap_or_default();
        // The scope is built before the token is read, from the request's *own* parameters, so a
        // token minted for a different prefix fails its tag rather than resuming this listing.
        let scope = TokenScope::account_listing("ListBuckets", &prefix);
        let after = match input.continuation_token.as_ref() {
            None => None,
            Some(token) => Some(fixture.token_secret.read(&scope, token.as_str()).ok_or_else(bad_token)?),
        };
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
        let next = truncated
            .then(|| names.last().map(|name| fixture.token_secret.mint(&scope, name)))
            .flatten();

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
            delimiter: delimiter_of(input.delimiter.as_deref()).map(ToOwned::to_owned),
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
        let prefix = input.prefix.as_deref().unwrap_or("");
        let delimiter = delimiter_of(input.delimiter.as_deref());
        // Built from this request's own bucket, prefix and delimiter, so a token issued for any
        // other listing does not verify here. `start-after` is not in the scope: it is a position,
        // not a listing, and a client is entitled to page past one it chose itself.
        let scope = TokenScope::bucket_listing("ListObjectsV2", input.bucket.as_str(), prefix, delimiter);
        let start = match input.continuation_token.as_ref() {
            Some(token) => Some(fixture.token_secret.read(&scope, token.as_str()).ok_or_else(bad_token)?),
            None => input.start_after.clone(),
        };
        let max_keys = input.max_keys.unwrap_or(1000);
        let page = paginate(&fixture, input.bucket.as_str(), prefix, delimiter, start.as_deref(), max_keys);
        let contents = page.contents(&fixture, input.bucket.as_str(), input.fetch_owner.unwrap_or(false))?;
        Ok(Resp::new(dto::ListObjectsV2Output {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            delimiter: delimiter_of(input.delimiter.as_deref()).map(ToOwned::to_owned),
            encoding_type: input.encoding_type.clone(),
            max_keys,
            key_count: page.count(),
            is_truncated: page.truncated,
            next_continuation_token: page
                .next
                .as_deref()
                .map(|marker| fixture.token_secret.mint(&scope, marker).into()),
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
        // position for it to name. AWS refuses the pair rather than guessing one. An empty key
        // marker names no key either (`c-list-0046`).
        if input.version_id_marker.is_some() && input.key_marker.as_deref().is_none_or(str::is_empty) {
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
        // The pair is a position, not a reference (`c-list-0045`, rustfs/gateway#807): a cleanup
        // deletes each page before asking for the next, so the version it names is usually gone.
        // A marker that still stands resumes after itself; one that does not resumes at its key's
        // surviving versions, which repeats at worst and never strands a version behind the cursor.
        let marker_stands = version_marker.is_some_and(|marker| {
            all.iter()
                .any(|entry| entry.key == key_marker && entry.version.version_id == marker)
        });
        let mut resumed = !marker_stands;
        let mut entries: Vec<VersionEntry<'_>> = Vec::new();
        for entry in &all {
            if !entry.key.starts_with(&prefix) {
                continue;
            }
            if !resumed {
                if entry.key == key_marker && entry.version.version_id == version_marker.unwrap_or_default() {
                    resumed = true;
                }
                continue;
            }
            if version_marker.is_some() && !marker_stands && entry.key < key_marker {
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
            delimiter: delimiter_of(input.delimiter.as_deref()).map(ToOwned::to_owned),
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
    let limit = usize::try_from(max.max(0)).unwrap_or(usize::MAX);
    let mut entries: Vec<(String, bool)> = Vec::new();
    let mut truncated = false;
    // `max-keys=0` is a page of nothing and it is *not* truncated: AWS answers `IsTruncated`
    // false, and `c-list-0027` is the case that says so. Falling into the loop would report the
    // first entry it saw as proof that more was waiting, which is the one answer that makes a
    // client ask for a page it will never be given.
    if limit > 0 {
        for key in fixture.live_keys_from(bucket, prefix, after) {
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
            // Only the previous entry is consulted, not the whole page. Folding is monotone — a key's
            // folded prefix never sorts before an earlier key's — so every key that folds onto one
            // prefix is contiguous in this walk, and the duplicates are always adjacent. Scanning the
            // page instead would be the same answer at a cost that grows with the page.
            if entry.1
                && entries
                    .last()
                    .is_some_and(|(value, is_prefix)| *is_prefix && *value == entry.0)
            {
                continue;
            }
            // Checked after the duplicate is dropped and before the entry is kept: a key folded onto a
            // prefix already on the page is not a further entry, so it must not make the page look
            // truncated when nothing follows it.
            if entries.len() >= limit {
                truncated = true;
                break;
            }
            entries.push(entry);
        }
    }
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
    use rustfs_gateway::{ErrorContext, ResponseKind, resolve};

    use super::*;

    /// The elements of a refusal, in the order the document will write them.
    fn elements(error: &HandlerError) -> Vec<(&'static str, String)> {
        error
            .details()
            .iter()
            .map(|detail| (detail.element(), detail.text().into_owned()))
            .collect()
    }

    /// The status the *service* would answer with, rather than the one the backend intended.
    ///
    /// A `HandlerError` is a proposal. Everything a backend puts on one — code, message, headers,
    /// `<Condition>` and the rest — is re-validated by `ErrorContext::ordinary` against ADR-0008's
    /// closed matrix before any of it reaches a socket, and a proposal that fails that validation
    /// is not trimmed: the whole refusal is replaced by a static `InternalError`. So a test that
    /// reads `error.code()` is reading an intention, and a backend can carry a `412` all the way to
    /// a green unit test while the wire gets a `500`. This runs the proposal through the same gate
    /// the service does and reports what survived.
    fn resolved(error: &HandlerError) -> (u16, ErrorCode, Vec<(&'static str, String)>) {
        let proposal = HandlerError::new(error.code().clone(), error.message().to_owned());
        let proposal = error
            .details()
            .iter()
            .fold(proposal, |carried, detail| carried.with_detail(detail.clone()));
        let Ok(context) = ErrorContext::ordinary(proposal) else {
            // What `render::internal_resolution` produces for a refusal the resolver refuses.
            return (500, ErrorCode::INTERNAL_ERROR, Vec::new());
        };
        let resolution = resolve(context, ResponseKind::Other);
        (
            resolution.status().as_u16(),
            resolution.code().cloned().unwrap_or(ErrorCode::INTERNAL_ERROR),
            resolution
                .details()
                .iter()
                .map(|detail| (detail.element(), detail.text().into_owned()))
                .collect(),
        )
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
            upload_id: UploadIdClaim::from_wire(upload_id),
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

    /// The refusal a committed answer eventually produced, or `None` if it answered.
    ///
    /// Drives the continuation `Resp::commit` handed back. A test that only looked at the `Resp`
    /// would see `Answer::Committed(_)` and learn nothing: the fault this arms lives inside the
    /// future, which is the whole reason it is a fault after a commit and not a refusal.
    fn refusal_after_commit<O: rustfs_gateway::Operation>(resp: Resp<O>) -> Option<HandlerError> {
        let (answer, _status, _extra_headers) = resp.into_parts();
        match answer {
            rustfs_gateway::Answer::Committed(committed) => crate::exec::block_on(committed.into_parts().1).err(),
            _ => panic!("{} did not commit its head", O::NAME),
        }
    }

    /// Negative — every operation named in [`COMMITTED_OPERATIONS`] really reports a fault armed
    /// against it.
    ///
    /// The list is read by [`Fixture::arm_committed_fault`], which is what stops a case naming
    /// `UploadPartCopy` from arming nothing. But the list being *read* proves only that the name was
    /// admitted. What makes it true is a handler that looks the fault up and returns it, and
    /// `Fixture::committed_fault` answers `None` for a name no handler asks about — silently, which
    /// is exactly the shape that lets a case run against a scenario it did not get. So each name is
    /// driven through its own handler here, and the loop is over the list rather than over two
    /// hand-written calls: a third name added to `COMMITTED_OPERATIONS` without a call site fails
    /// this test instead of quietly arming nothing.
    #[test]
    fn every_operation_this_fixture_commits_for_reports_the_fault_armed_against_it() {
        for operation in COMMITTED_OPERATIONS {
            let mut fixture = Fixture::at(0);
            fixture.declare_bucket("conf-bucket", false);
            fixture.put_object("conf-bucket", "src", StoredObject::new(b"source bytes".to_vec(), None, 0));
            let upload = fixture.create_upload("conf-bucket", "k");
            let first = fixture.put_part(&upload, 1, vec![0_u8; MIN_PART_BYTES]);
            fixture
                .arm_committed_fault(operation, ErrorCode::INTERNAL_ERROR)
                .expect("a name this fixture commits for");
            let stub = Stub::new(Arc::new(Mutex::new(fixture)));

            let refusal = match *operation {
                "CompleteMultipartUpload" => {
                    let input = completion(&upload, vec![(1, Some(&first))]);
                    refusal_after_commit(stub.complete_multipart_upload(&input).expect("a committed answer"))
                }
                "CopyObject" => {
                    let input = copy("/conf-bucket/src", "dst");
                    refusal_after_commit(stub.copy_object(&input).expect("a committed answer"))
                }
                other => panic!("{other} is in COMMITTED_OPERATIONS and this test does not drive it"),
            };
            let refusal = refusal.unwrap_or_else(|| panic!("{operation} answered rather than reporting the armed fault"));
            assert_eq!(*refusal.code(), ErrorCode::INTERNAL_ERROR, "{operation}");
        }
    }

    /// **Negative — every operation named in [`COMMITTED_OPERATIONS`] really *stalls* when a stall
    /// is armed against it.**
    ///
    /// The same argument as the test above, for the other effect. A handler that read the armed
    /// fault but only knew how to report a code would run the *ordinary* path for a stall, and the
    /// case asserting a bound on progress would be red for a reason unrelated to the bound.
    ///
    /// "Never resolves" is observed by polling, not waiting — one poll with a no-op waker, which
    /// must answer `Pending`. Awaiting it would hang, and a hanging test reads as infrastructure.
    #[test]
    fn every_operation_this_fixture_commits_for_stalls_when_a_stall_is_armed_against_it() {
        for operation in COMMITTED_OPERATIONS {
            let mut fixture = Fixture::at(0);
            fixture.declare_bucket("conf-bucket", false);
            fixture.put_object("conf-bucket", "src", StoredObject::new(b"source bytes".to_vec(), None, 0));
            let upload = fixture.create_upload("conf-bucket", "k");
            let first = fixture.put_part(&upload, 1, vec![0_u8; MIN_PART_BYTES]);
            fixture
                .arm_committed_stall(operation)
                .expect("a name this fixture commits for");
            let stub = Stub::new(Arc::new(Mutex::new(fixture)));

            let pending = match *operation {
                "CompleteMultipartUpload" => {
                    let input = completion(&upload, vec![(1, Some(&first))]);
                    stalls_for_ever(stub.complete_multipart_upload(&input).expect("a committed answer"))
                }
                "CopyObject" => {
                    let input = copy("/conf-bucket/src", "dst");
                    stalls_for_ever(stub.copy_object(&input).expect("a committed answer"))
                }
                other => panic!("{other} is in COMMITTED_OPERATIONS and this test does not drive it"),
            };
            assert!(pending, "{operation} answered rather than stalling when a stall was armed");
        }
    }

    fn stalls_for_ever<O: rustfs_gateway::Operation>(resp: Resp<O>) -> bool {
        let (answer, _status, _extra_headers) = resp.into_parts();
        let rustfs_gateway::Answer::Committed(committed) = answer else {
            panic!("{} did not commit its head", O::NAME);
        };
        let (_, mut work) = committed.into_parts();
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        work.as_mut().poll(&mut context).is_pending()
    }

    /// Negative — a stall armed against an operation this fixture never commits for is refused.
    #[test]
    fn a_stall_armed_against_an_operation_this_fixture_never_commits_for_is_refused() {
        let mut fixture = Fixture::at(0);
        let refused = fixture
            .arm_committed_stall("UploadPartCopy")
            .expect_err("an operation this fixture does not commit for");
        assert_eq!(refused.operation(), "UploadPartCopy");
        assert!(fixture.committed_fault("UploadPartCopy", "k").is_none());
    }

    /// Negative — a fault armed against an operation this fixture never commits for is refused.
    ///
    /// `UploadPartCopy` is the one that matters. The model marks it as able to fail after a `200`,
    /// so a case may legitimately name it; this fixture answers it without committing anything, so
    /// there is no point in it at which the fault could arrive. Accepting the arming would leave the
    /// case running with nothing arranged and reporting whatever it happened to get.
    #[test]
    fn a_fault_armed_against_an_operation_this_fixture_never_commits_for_is_refused() {
        let mut fixture = Fixture::at(0);
        let refused = fixture
            .arm_committed_fault("UploadPartCopy", ErrorCode::INTERNAL_ERROR)
            .expect_err("an operation this fixture does not commit for");
        assert_eq!(refused.operation(), "UploadPartCopy");
        assert!(fixture.committed_fault("UploadPartCopy", "k").is_none());
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
            resolved(&error),
            (412, ErrorCode::PRECONDITION_FAILED, Vec::new()),
            "the source-side refusal reaches the wire as a 412 and attributes itself to no header"
        );
    }

    /// Negative — a copy-source precondition failure is a `412` on the wire, not a `500`.
    ///
    /// This is the assertion the family was missing. The copy test above reads `error.code()` and
    /// sees `PreconditionFailed`, and that was true and unobservable at the same time: while this
    /// backend named the failed condition
    /// `x-amz-copy-source-if-match`, ADR-0008's closed matrix admitted only the four RFC 9110
    /// spellings in `<Condition>`, so `ErrorContext::ordinary` refused the whole proposal and the
    /// service answered a static `InternalError`. Three cases went red — `c-cond-0026`,
    /// `c-copy-0031`, `c-copy-0032` — and every unit test in this file stayed green, because none
    /// of them had ever asked what survived resolution.
    ///
    /// Both directions are asserted: the destination guard still names its header, so this is not
    /// the element being dropped everywhere, and the copy-source guard resolves to the same `412`
    /// while naming nothing, because the vocabulary has no spelling for the side it failed on.
    #[test]
    fn a_copy_source_precondition_failure_survives_resolution_as_a_412() {
        let source_side = refusal(guard_copy_source(
            &StoredObject::new(b"hello".to_vec(), None, 0),
            Some("\"0000000000000000000000000000dead\""),
            None,
            None,
            None,
            0,
        ));
        assert_eq!(
            resolved(&source_side),
            (412, ErrorCode::PRECONDITION_FAILED, Vec::new()),
            "a copy-source condition has no spelling in the admitted `<Condition>` set, so the \
             refusal names none and stays a 412 rather than being replaced by a 500"
        );

        let destination_side = refusal(guard_write(
            Some(&StoredObject::new(b"original".to_vec(), None, 0)),
            Some("\"0000000000000000000000000000dead\""),
            None,
            0,
        ));
        assert_eq!(
            resolved(&destination_side),
            (412, ErrorCode::PRECONDITION_FAILED, vec![("Condition", "If-Match".to_owned())]),
            "the destination header is in the admitted set and must still reach the document"
        );
    }

    /// The refusal a guard produced, for a guard that was supposed to refuse.
    fn refusal(outcome: Result<(), HandlerError>) -> HandlerError {
        outcome.expect_err("the condition does not hold")
    }

    /// Positive — one conditional header arrived, so the `412` can say which one failed.
    ///
    /// Only the destination set is attributable: it is the canonical mixed case a client reads out
    /// of `<Condition>`, and it is the only set ADR-0008 admits into the element at all. The
    /// copy-source spellings were asserted here too until it turned out no client could ever see
    /// one; `a_copy_source_precondition_failure_survives_resolution_as_a_412` holds that side now,
    /// against the resolved response rather than against the proposal.
    #[test]
    fn a_single_condition_is_named_by_the_header_that_carried_it() {
        let current_etag = crate::md5::hex_digest(b"original");
        let error = guard_write(
            Some(&StoredObject::new(b"original".to_vec(), None, 0)),
            None,
            Some(&format!("\"{current_etag}\"")),
            0,
        )
        .expect_err("If-None-Match names the object's own entity tag, so it must not proceed");
        assert_eq!(
            resolved(&error),
            (412, ErrorCode::PRECONDITION_FAILED, vec![("Condition", "If-None-Match".to_owned())])
        );

        let error = refusal(guard_write(
            Some(&StoredObject::new(b"original".to_vec(), None, 0)),
            Some("\"0000000000000000000000000000dead\""),
            None,
            0,
        ));
        assert_eq!(
            resolved(&error),
            (412, ErrorCode::PRECONDITION_FAILED, vec![("Condition", "If-Match".to_owned())])
        );
    }

    /// Negative — a request with no conditional headers at all cannot produce a named `412`,
    /// because `evaluate` cannot fail a condition that was never sent.
    #[test]
    fn no_condition_is_named_when_the_request_carried_none() {
        assert_eq!(destination_condition(None), None);
    }

    /// Positive — the failed condition is named even when a second, unrelated condition also
    /// arrived on the same request.
    ///
    /// RFC 9110 §13.2.2 fixes the evaluation order at `If-Match`, `If-Unmodified-Since`,
    /// `If-None-Match`, `If-Modified-Since`. A request carrying `If-Unmodified-Since` and
    /// `If-None-Match` together fails at the second step without `evaluate` ever looking at the
    /// third, so the header that decided the outcome is `If-Unmodified-Since` however many other
    /// conditional headers rode along. A heuristic that only trusted a request carrying exactly
    /// one header could not say that — this case would have answered `412` with no `<Condition>`
    /// at all until the outcome itself started carrying the header it was decided by.
    #[test]
    fn a_condition_is_named_even_when_a_second_one_also_arrived() {
        let object = StoredObject::new(b"hello".to_vec(), None, 1_700_000_000);
        let error = guard_read(Some(&object), None, Some(1_700_000_000 - 1), Some("\"deliberately-different\""), None, 0)
            .expect_err("If-Unmodified-Since is not satisfied");
        assert_eq!(
            resolved(&error),
            (412, ErrorCode::PRECONDITION_FAILED, vec![("Condition", "If-Unmodified-Since".to_owned())]),
            "If-Unmodified-Since decided the outcome before If-None-Match was ever evaluated"
        );
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
        let stored = ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &crate::crc32::digest(b"123456789"))
            .expect("the published CRC32 digest has the right width");
        assert_eq!(
            read_checksum(Some(&dto::ChecksumMode::ENABLED), true, Some(stored)),
            ReportedChecksum::default()
        );
        assert_eq!(read_checksum(None, false, Some(stored)), ReportedChecksum::default());
        assert_eq!(read_checksum(None, true, Some(stored)), ReportedChecksum::default());
        // A value this build has no constant for is not `ENABLED` by resemblance.
        assert_eq!(
            read_checksum(Some(&dto::ChecksumMode::custom("enabled")), false, Some(stored)),
            ReportedChecksum::default()
        );
    }

    /// Positive — a whole read that asked reports the CRC-32 of the bytes it sends, base64 as the
    /// header carries it. Pinned against `crate::crc32`'s published check vector.
    #[test]
    fn a_whole_read_that_asked_reports_the_crc32_of_its_bytes() {
        let check = |bytes: &[u8]| {
            ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &crate::crc32::digest(bytes))
                .expect("a computed CRC32 digest has the right width")
        };
        assert_eq!(
            read_checksum(Some(&dto::ChecksumMode::ENABLED), false, Some(check(b"123456789")))
                .crc32
                .as_deref(),
            Some("y/Q5Jg==")
        );
        assert_eq!(
            read_checksum(Some(&dto::ChecksumMode::ENABLED), false, Some(check(b"")))
                .crc32
                .as_deref(),
            Some("AAAAAA==")
        );
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
    ///
    /// The rule itself is proved in `rustfs-gateway-core`, against the exchange every backend
    /// calls. What this proves is the wiring: that *this* backend reaches it, and that the document
    /// the four refusals render is one document. The last assertion is the one that would catch a
    /// fixture quietly regrowing a message of its own — a caller able to tell "wrong bucket" from
    /// "no such id" apart has been told the id it guessed is genuine.
    #[test]
    fn an_upload_id_resolves_only_against_the_bucket_and_key_that_own_it() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("mine", false);
        fixture.declare_bucket("theirs", false);
        let id = fixture.create_upload("theirs", "someone-elses-object");
        let claim = UploadIdClaim::from_wire(id.clone());
        let invented_claim = UploadIdClaim::from_wire("conformance-upload-9999");
        let traversal_claim = UploadIdClaim::from_wire("../../etc/passwd");

        let bucket = |name: &str| BucketName::new(name.to_owned()).expect("a fixture bucket name is valid");
        let key = |name: &str| ObjectKey::new(name.to_owned()).expect("a fixture key is valid");

        assert!(require_upload(&fixture, &claim, &bucket("theirs"), &key("someone-elses-object")).is_ok());
        // Same key, wrong bucket.
        let foreign = require_upload(&fixture, &claim, &bucket("mine"), &key("someone-elses-object"));
        assert_eq!(foreign.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));
        // Right bucket, wrong key.
        let crossed = require_upload(&fixture, &claim, &bucket("theirs"), &key("another-object"));
        assert_eq!(crossed.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));
        // An id nothing minted.
        let invented = require_upload(&fixture, &invented_claim, &bucket("theirs"), &key("someone-elses-object"));
        assert_eq!(invented.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));
        // A shape no minted id can have. It never reaches the store, and it is refused as the
        // other three are.
        let traversal = require_upload(&fixture, &traversal_claim, &bucket("theirs"), &key("someone-elses-object"));
        assert_eq!(traversal.err().map(|error| error.code().clone()), Some(ErrorCode::NO_SUCH_UPLOAD));

        let rendered: Vec<String> = ["conformance-upload-9999", "../../etc/passwd"]
            .into_iter()
            .map(|spent| {
                let spent = UploadIdClaim::from_wire(spent);
                require_upload(&fixture, &spent, &bucket("mine"), &key("someone-elses-object"))
                    .err()
                    .map(|error| error.message().to_owned())
                    .unwrap_or_else(|| panic!("the spent claim names no upload in mine/someone-elses-object"))
            })
            .chain(std::iter::once(
                require_upload(&fixture, &claim, &bucket("mine"), &key("someone-elses-object"))
                    .err()
                    .map(|error| error.message().to_owned())
                    .expect("a genuine id from another bucket is refused"),
            ))
            .collect();
        let first = rendered.first().expect("three refusals were collected");
        for message in &rendered {
            assert_eq!(message, first, "two upload-id refusals are distinguishable by their message");
        }
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

    /// The cursor this *fixture instance* mints round-trips, and every spelling it did not mint is
    /// refused rather than read as some other position.
    ///
    /// The codec's own contract is asserted in [`crate::token`]; what this adds is that the
    /// fixture holds a key of its own, so two fixtures do not share one. A fixture whose secret
    /// were a constant would pass every assertion in `crate::token` and still be forgeable by
    /// anybody who has read this file.
    #[test]
    fn a_continuation_token_round_trips_and_refuses_everything_else() {
        let fixture = Fixture::at(0);
        let scope = TokenScope::bucket_listing("ListObjectsV2", "b", "", None);
        let token = fixture.token_secret.mint(&scope, "a/2.txt");
        assert_ne!(token, "a/2.txt", "a cursor a client can read is a cursor a client can forge");
        assert_eq!(fixture.token_secret.read(&scope, &token).as_deref(), Some("a/2.txt"));
        assert_eq!(fixture.token_secret.read(&scope, &format!("{token}X")), None);
        assert_eq!(fixture.token_secret.read(&scope, "../../etc/passwd"), None);
        assert_eq!(fixture.token_secret.read(&scope, "\u{ff}\u{fe}\u{0}\u{1}"), None);
        // The ceiling is the contract's, and one byte over it is refused before anything decodes.
        let over = "A".repeat(rustfs_gateway::MAX_CURSOR_BYTES + 1);
        assert_eq!(fixture.token_secret.read(&scope, &over), None);
        // The first page of an empty prefix resumes from the empty marker, which must survive too.
        let empty = fixture.token_secret.mint(&scope, "");
        assert_eq!(fixture.token_secret.read(&scope, &empty).as_deref(), Some(""));

        // Negative: the token belongs to this fixture and to no other. Two fixtures in one process
        // hold two keys, which is what makes a captured token useless anywhere but where it came
        // from.
        let other = Fixture::at(0);
        assert_eq!(other.token_secret.read(&scope, &token), None, "a token crossed fixtures");
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
        // A traversal spelling used to be accepted here as ordinary key bytes and looked up
        // literally. That is the backend half of `GHSA-f4vq-9ffr-m8m3`: the gateway's floor
        // refuses it and a backend with its own parser did not, so the two disagreed about what
        // the name was. This backend now calls the same normalisation and refuses it too.
        assert!(parse_copy_source("/bucket/../../etc/passwd").is_err());
        // A single dot segment is still opaque text, so the rule is about `..` and not about dots.
        assert_eq!(parse_copy_source("/bucket/a/./b").expect("parses").key.as_str(), "a/./b");
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
            // An encoded separator relaxes none of these (rustfs/gateway#926).
            "bucket%2F",
            "/%2Fkey",
            "bucket%252Fkey",
            "bucket%2F..%2F..%2Fetc%2Fpasswd",
        ] {
            assert!(parse_copy_source(raw).is_err(), "{raw}");
        }
    }

    /// rustfs/gateway#926 — the mirror's separator is the first slash of the decoded value, as
    /// the shared parser's is: aws-sdk-dotnet's `bucket%2Fkey` names `key`, a later `%2F` is key
    /// bytes, and the key is still decoded exactly once.
    #[test]
    fn a_copy_source_separator_may_be_percent_encoded() {
        let cases = [
            ("bucket%2Fkey", "key"),
            ("/bucket%2fkey", "key"),
            ("bucket%2Fa%2Fc", "a/c"),
            ("bucket%2Fa%2541", "a%41"),
        ];
        for (raw, key) in cases {
            let source = parse_copy_source(raw).expect("parses");
            assert_eq!((source.bucket.as_str(), source.key.as_str()), ("bucket", key), "{raw}");
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
