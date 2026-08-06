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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rustfs_gateway::dto;
use rustfs_gateway::{
    BucketName, ByteStream, ETag, ErrorCode, Handler, HandlerError, HandlerResult, ObjectKey, Req, Resp, Timestamp, collect,
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

/// The longest continuation token this stub will even look at.
///
/// A cursor is a hex-encoded position plus a nine-character suffix, and the longest position is a
/// maximum-length object key — 1024 bytes, so 2057 characters. Anything past that is a token this
/// service could not have minted, and saying so before decoding it is what keeps `c-list-0030`
/// from being answered by the amount of work it asked for.
const MAX_TOKEN_BYTES: usize = 2304;

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
#[derive(Debug, Clone)]
pub struct StoredUpload {
    /// The bucket it belongs to.
    pub bucket: String,
    /// The key it will become.
    pub key: String,
    /// Parts by part number.
    pub parts: BTreeMap<i32, StoredPart>,
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

/// The state one case runs against.
#[derive(Debug, Default)]
pub struct Fixture {
    buckets: BTreeMap<String, bool>,
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
    pub fn declare_bucket(&mut self, name: &str, versioned: bool) {
        self.buckets.insert(name.to_owned(), versioned);
    }

    /// Removes a bucket, for `setup.buckets[].absent`.
    pub fn remove_bucket(&mut self, name: &str) {
        self.buckets.remove(name);
        self.objects.retain(|(bucket, _), _| bucket != name);
    }

    /// Places an object.
    ///
    /// In a versioned bucket this appends a version and leaves the earlier ones reachable through
    /// [`Fixture::versions_in`]; everywhere else it replaces the single `null` version. Either way
    /// the newest version is what a read sees, which is why `GetObject` needed no change.
    pub fn put_object(&mut self, bucket: &str, key: &str, object: StoredObject) {
        let last_modified = object.last_modified;
        let version = self.mint_version(bucket);
        let versions = self.objects.entry((bucket.to_owned(), key.to_owned())).or_default();
        if version == UNVERSIONED {
            versions.clear();
        }
        versions.push(StoredVersion {
            version_id: version,
            object: Some(object),
            last_modified,
        });
    }

    /// Removes an object, for `setup.objects[].absent`.
    ///
    /// A versioned bucket keeps the versions and hides them behind a delete marker, which is what
    /// makes `<DeleteMarker>` and `<IsLatest>false</IsLatest>` observable at all.
    pub fn remove_object(&mut self, bucket: &str, key: &str) {
        let identity = (bucket.to_owned(), key.to_owned());
        if !self.is_versioned(bucket) {
            self.objects.remove(&identity);
            return;
        }
        let Some(versions) = self.objects.get(&identity) else { return };
        if versions.is_empty() {
            return;
        }
        let last_modified = self.now;
        let version_id = self.mint_version(bucket);
        if let Some(versions) = self.objects.get_mut(&identity) {
            versions.push(StoredVersion {
                version_id,
                object: None,
                last_modified,
            });
        }
    }

    /// Whether a bucket was declared with versioning enabled.
    #[must_use]
    pub fn is_versioned(&self, name: &str) -> bool {
        self.buckets.get(name).copied().unwrap_or(false)
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
        self.next_upload += 1;
        let id = format!("conformance-upload-{:04}", self.next_upload);
        self.uploads.insert(
            id.clone(),
            StoredUpload {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                parts: BTreeMap::new(),
            },
        );
        id
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
fn read_token(token: &str) -> Option<String> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
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

/// The object, or `NoSuchKey`.
fn require_object<'a>(fixture: &'a Fixture, bucket: &BucketName, key: &ObjectKey) -> Result<&'a StoredObject, HandlerError> {
    require_bucket(fixture, bucket)?;
    fixture
        .object(bucket.as_str(), key.as_str())
        .ok_or_else(|| HandlerError::new(ErrorCode::NO_SUCH_KEY, "The specified key does not exist."))
}

/// Whether an `If-Match` / `If-None-Match` header value selects `etag`.
///
/// The header carries a list of entity tags, or `*`. Comparison is on the opaque tag with quotes
/// and any `W/` prefix stripped, which is the strong comparison S3 applies to both headers.
fn etag_list_matches(header: &str, etag: &str) -> bool {
    header.split(',').map(str::trim).any(|candidate| {
        if candidate == "*" {
            return true;
        }
        let candidate = candidate
            .strip_prefix("W/")
            .or_else(|| candidate.strip_prefix("w/"))
            .unwrap_or(candidate);
        candidate.trim_matches('"') == etag
    })
}

/// The four conditional headers, evaluated in the RFC 9110 order.
///
/// `read_kind` selects the two answers that differ between a read and a write: a read answers a
/// failed `If-None-Match` with `304`, a write answers it with `412`.
fn evaluate_conditions(
    object: &StoredObject,
    if_match: Option<&str>,
    if_unmodified_since: Option<i64>,
    if_none_match: Option<&str>,
    if_modified_since: Option<i64>,
    read: bool,
) -> Result<(), HandlerError> {
    if let Some(header) = if_match {
        if !etag_list_matches(header, &object.etag) {
            return Err(precondition("If-Match"));
        }
    } else if let Some(instant) = if_unmodified_since
        && object.last_modified > instant
    {
        return Err(precondition("If-Unmodified-Since"));
    }
    if let Some(header) = if_none_match {
        if etag_list_matches(header, &object.etag) {
            return Err(if read {
                HandlerError::new(ErrorCode::NOT_MODIFIED, "If-None-Match selected the current representation")
            } else {
                precondition("If-None-Match")
            });
        }
    } else if let Some(instant) = if_modified_since
        && read
        && object.last_modified <= instant
    {
        return Err(HandlerError::new(
            ErrorCode::NOT_MODIFIED,
            "the representation has not changed since the instant given",
        ));
    }
    Ok(())
}

/// A `412`, worded as AWS words it.
///
/// AWS also emits a `<Condition>` element naming the header that failed. A `HandlerError` carries
/// a code and a message and nothing else, so this backend cannot produce one — which is itself
/// what the conditional cases are measuring. The condition is therefore *not* smuggled into the
/// message: doing that would make the `<Message>` text differ too, and one failure would look like
/// two.
fn precondition(condition: &'static str) -> HandlerError {
    let _ = condition;
    HandlerError::new(
        ErrorCode::PRECONDITION_FAILED,
        "At least one of the pre-conditions you specified did not hold",
    )
}

/// A resolved range: the window to send, and the `Content-Range` value that describes it.
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

/// Reads the two offsets back out of a rendered `Content-Range`.
///
/// The parsed `Range` resolves to an outcome whose *variants* cannot be named through the facade
/// while its two accessors can, so the window is recovered from the string the outcome renders.
/// That is narrower than re-deriving RFC 9110's clamping rules here would be: a second copy of
/// them in the suite that checks them would agree with itself and with nothing else.
fn window_of(content_range: &str) -> Option<(usize, usize)> {
    let spec = content_range.strip_prefix("bytes ")?;
    let (window, _total) = spec.split_once('/')?;
    let (first, last) = window.split_once('-')?;
    let first: usize = first.parse().ok()?;
    let last: usize = last.parse().ok()?;
    Some((first, last.checked_add(1)?))
}

/// The storage class a read reports, which S3 omits for the default class.
fn storage_class_header(object: &StoredObject) -> Option<dto::StorageClass> {
    if object.storage_class == "STANDARD" {
        return None;
    }
    Some(dto::StorageClass::custom(object.storage_class.clone()))
}

/// `416`, with the `Content-Range` an unsatisfiable request must carry.
fn unsatisfiable() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_RANGE, "The requested range is not satisfiable")
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

impl Handler<dto::DeleteObject> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObject>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObject>> + Send {
        let outcome = self.delete_object(request.input());
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
    if let Some(existing) = fixture.object(input.bucket.as_str(), input.key.as_str()) {
        let existing = existing.clone();
        evaluate_conditions(&existing, input.if_match.as_deref(), None, input.if_none_match.as_deref(), None, false)?;
    } else if input.if_match.is_some() {
        // `If-Match` against a key that is not there fails the precondition rather than 404ing:
        // the client asked for a conditional overwrite and there was nothing to match.
        return Err(precondition("If-Match"));
    }
    let now = fixture.now;
    let mut object = StoredObject::new(bytes, input.content_type.clone(), now);
    object.cache_control = input.cache_control.clone();
    object.content_disposition = input.content_disposition.clone();
    object.content_encoding = input.content_encoding.clone();
    object.content_language = input.content_language.clone();
    object.expires = input.expires.as_ref().map(|value| value.as_str().to_owned());
    object.metadata = input.metadata.clone();
    if let Some(class) = input.storage_class.as_ref() {
        object.storage_class = class.to_string();
    }
    let size = object.body.len() as i64;
    fixture.put_object(input.bucket.as_str(), input.key.as_str(), object);
    Ok(Resp::new(dto::PutObjectOutput {
        size: Some(size),
        ..dto::PutObjectOutput::default()
    }))
}

async fn upload_part(state: &Arc<Mutex<Fixture>>, input: dto::UploadPartInput) -> HandlerResult<dto::UploadPart> {
    let bytes = drain(input.body).await?;
    let mut fixture = state
        .lock()
        .map_err(|_| HandlerError::internal_error("the fixture state was left poisoned by an earlier exchange"))?;
    require_bucket(&fixture, &input.bucket)?;
    if !fixture.uploads.contains_key(&input.upload_id) {
        return Err(HandlerError::new(
            ErrorCode::NO_SUCH_UPLOAD,
            "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
        ));
    }
    fixture.put_part(&input.upload_id, input.part_number, bytes);
    Ok(Resp::new(dto::UploadPartOutput::default()))
}

impl Stub {
    fn get_object(&self, input: &dto::GetObjectInput) -> HandlerResult<dto::GetObject> {
        let fixture = self.borrow()?;
        let object = require_object(&fixture, &input.bucket, &input.key)?;
        evaluate_conditions(
            object,
            input.if_match.as_deref(),
            input.if_unmodified_since.as_ref().map(|stamp| stamp.secs()),
            input.if_none_match.as_deref(),
            input.if_modified_since.as_ref().map(|stamp| stamp.secs()),
            true,
        )?;
        let length = object.body.len();
        let slice = match input.range.as_ref() {
            None => Slice::whole(length),
            Some(range) => {
                let outcome = range.resolve(length as u64);
                match outcome.content_range(length as u64) {
                    None => Slice::whole(length),
                    Some(text) => match window_of(&text) {
                        None => return Err(unsatisfiable()),
                        Some((start, end_exclusive)) => Slice {
                            start,
                            end_exclusive,
                            content_range: Some(text),
                        },
                    },
                }
            }
        };
        let body = object.body.get(slice.start..slice.end_exclusive).unwrap_or_default().to_vec();
        let status = if slice.content_range.is_some() { 206 } else { 200 };
        Ok(Resp::with_status(
            dto::GetObjectOutput {
                content_length: Some(body.len() as i64),
                content_type: object.content_type.clone(),
                content_range: slice.content_range,
                accept_ranges: Some("bytes".to_owned()),
                cache_control: object.cache_control.clone(),
                content_disposition: object.content_disposition.clone(),
                content_encoding: object.content_encoding.clone(),
                content_language: object.content_language.clone(),
                expires: object.expires.clone().map(Into::into),
                metadata: object.metadata.clone(),
                storage_class: storage_class_header(object),
                body: Some(ByteStream::from_bytes(bytes::Bytes::from(body))),
                ..dto::GetObjectOutput::default()
            },
            status,
        ))
    }

    fn head_object(&self, input: &dto::HeadObjectInput) -> HandlerResult<dto::HeadObject> {
        let fixture = self.borrow()?;
        let object = require_object(&fixture, &input.bucket, &input.key)?;
        evaluate_conditions(
            object,
            input.if_match.as_deref(),
            input.if_unmodified_since.as_ref().map(|stamp| stamp.secs()),
            input.if_none_match.as_deref(),
            input.if_modified_since.as_ref().map(|stamp| stamp.secs()),
            true,
        )?;
        let length = object.body.len();
        let slice = match input.range.as_ref() {
            None => Slice::whole(length),
            Some(range) => {
                let outcome = range.resolve(length as u64);
                match outcome.content_range(length as u64) {
                    None => Slice::whole(length),
                    Some(text) => match window_of(&text) {
                        None => return Err(unsatisfiable()),
                        Some((start, end_exclusive)) => Slice {
                            start,
                            end_exclusive,
                            content_range: Some(text),
                        },
                    },
                }
            }
        };
        let served = slice.end_exclusive.saturating_sub(slice.start);
        let status = if slice.content_range.is_some() { 206 } else { 200 };
        Ok(Resp::with_status(
            dto::HeadObjectOutput {
                content_length: Some(served as i64),
                content_type: object.content_type.clone(),
                content_range: slice.content_range,
                accept_ranges: Some("bytes".to_owned()),
                cache_control: object.cache_control.clone(),
                content_disposition: object.content_disposition.clone(),
                content_encoding: object.content_encoding.clone(),
                content_language: object.content_language.clone(),
                expires: object.expires.clone().map(Into::into),
                metadata: object.metadata.clone(),
                storage_class: storage_class_header(object),
                ..dto::HeadObjectOutput::default()
            },
            status,
        ))
    }

    fn delete_object(&self, input: &dto::DeleteObjectInput) -> HandlerResult<dto::DeleteObject> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        fixture.remove_object(input.bucket.as_str(), input.key.as_str());
        Ok(Resp::new(dto::DeleteObjectOutput::default()))
    }

    fn delete_objects(&self, input: &dto::DeleteObjectsInput) -> HandlerResult<dto::DeleteObjects> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let quiet = input.delete.quiet.unwrap_or(false);
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for identifier in &input.delete.objects {
            // The fixture keeps no version history, so a request naming a version cannot be
            // satisfied — and reporting that per key rather than failing the whole request is the
            // shape this operation is being measured for.
            if let Some(version) = identifier.version_id.as_ref() {
                errors.push(dto::Error {
                    key: Some(identifier.key.clone()),
                    version_id: Some(version.clone()),
                    code: Some("NoSuchVersion".to_owned()),
                    message: Some("The specified version does not exist.".to_owned()),
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

    fn create_multipart_upload(&self, input: &dto::CreateMultipartUploadInput) -> HandlerResult<dto::CreateMultipartUpload> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let upload_id = fixture.create_upload(input.bucket.as_str(), input.key.as_str());
        Ok(Resp::new(dto::CreateMultipartUploadOutput {
            bucket: input.bucket.clone(),
            key: input.key.clone(),
            upload_id,
            ..dto::CreateMultipartUploadOutput::default()
        }))
    }

    fn abort_multipart_upload(&self, input: &dto::AbortMultipartUploadInput) -> HandlerResult<dto::AbortMultipartUpload> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        if fixture.uploads.remove(&input.upload_id).is_none() {
            return Err(HandlerError::new(
                ErrorCode::NO_SUCH_UPLOAD,
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
            ));
        }
        Ok(Resp::new(dto::AbortMultipartUploadOutput::default()))
    }

    fn complete_multipart_upload(
        &self,
        input: &dto::CompleteMultipartUploadInput,
    ) -> HandlerResult<dto::CompleteMultipartUpload> {
        let mut fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let upload = fixture.uploads.get(&input.upload_id).cloned().ok_or_else(|| {
            HandlerError::new(ErrorCode::NO_SUCH_UPLOAD, "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")
        })?;
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
        match fixture.object(upload.bucket.as_str(), upload.key.as_str()).cloned() {
            Some(existing) => {
                evaluate_conditions(&existing, input.if_match.as_deref(), None, input.if_none_match.as_deref(), None, false)?
            }
            None if input.if_match.is_some() => return Err(precondition("If-Match")),
            None => {}
        }
        let mut assembled = Vec::new();
        for part in named {
            let stored = upload.parts.get(&part.part_number).ok_or_else(|| {
                HandlerError::new(ErrorCode::INVALID_PART, "One or more of the specified parts could not be found.")
            })?;
            // The entity tag is compared through its `Debug` rendering. `ETag`'s accessors are not
            // reachable through the facade — the same gap that makes a listing unbuildable — and
            // `Debug` is the only surface left that carries the opaque tag. An empty claim is
            // accepted rather than refused: this backend's own `UploadPart` cannot answer with an
            // entity tag either, so a case that echoes what it was given is unverifiable here and
            // refusing it would report a digest mismatch that never happened.
            if let Some(claimed) = part.e_tag.as_ref() {
                let rendered = format!("{claimed:?}");
                let claims_nothing = rendered.contains("tag: \"\"");
                if !claims_nothing && !rendered.contains(&stored.etag) {
                    return Err(HandlerError::new(
                        ErrorCode::INVALID_PART,
                        "One or more of the specified parts could not be found.",
                    ));
                }
            }
            assembled.extend_from_slice(&stored.body);
        }
        let now = fixture.now;
        let assembled = StoredObject::new(assembled, None, now);
        fixture.put_object(&upload.bucket, &upload.key, assembled);
        fixture.uploads.remove(&input.upload_id);
        Ok(Resp::new(dto::CompleteMultipartUploadOutput {
            bucket: Some(input.bucket.clone()),
            key: Some(input.key.clone()),
            location: Some(format!("/{}/{}", input.bucket.as_str(), input.key.as_str())),
            ..dto::CompleteMultipartUploadOutput::default()
        }))
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
        let upload = fixture.uploads.get(&input.upload_id).ok_or_else(|| {
            HandlerError::new(ErrorCode::NO_SUCH_UPLOAD, "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")
        })?;

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

    #[test]
    fn an_entity_tag_list_matches_on_the_opaque_tag_whatever_the_quoting() {
        assert!(etag_list_matches("\"abc\"", "abc"));
        assert!(etag_list_matches("W/\"abc\"", "abc"));
        assert!(etag_list_matches("*", "abc"));
        assert!(etag_list_matches("\"zzz\", \"abc\"", "abc"));
        assert!(!etag_list_matches("\"zzz\"", "abc"));
    }

    #[test]
    fn a_fixture_stamps_the_entity_tag_the_corpus_writes_by_hand() {
        let object = StoredObject::new(b"hello".to_vec(), None, 0);
        assert_eq!(object.etag, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn a_content_range_round_trips_into_a_window() {
        assert_eq!(window_of("bytes 0-4/10"), Some((0, 5)));
        assert_eq!(window_of("bytes 5-9/10"), Some((5, 10)));
        // The unsatisfiable rendering carries no window, which is how a 416 is recognised.
        assert_eq!(window_of("bytes */10"), None);
    }

    #[test]
    fn upload_ids_are_minted_deterministically() {
        let mut fixture = Fixture::at(0);
        fixture.declare_bucket("b", false);
        assert_eq!(fixture.create_upload("b", "k"), "conformance-upload-0001");
        assert_eq!(fixture.create_upload("b", "k"), "conformance-upload-0002");
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
        assert_eq!(read_token(&"A".repeat(MAX_TOKEN_BYTES + 1)), None);
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

    /// An empty delimiter is no delimiter: folding on it would put every key under one prefix.
    #[test]
    fn an_empty_delimiter_folds_nothing() {
        assert_eq!(delimiter_of(Some("")), None);
        assert_eq!(delimiter_of(Some("/")), Some("/"));
        assert_eq!(fold("xxABtail", "", Some("AB")).as_deref(), Some("xxAB"));
        assert_eq!(fold("xxAother", "", Some("AB")), None);
    }
}
