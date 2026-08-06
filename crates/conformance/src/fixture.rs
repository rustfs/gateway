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
//! # Why several operations answer `501` on a well-formed request
//!
//! `Object`, `ObjectVersion`, `Part` and `Bucket` each carry a **required** `ETag` or `Timestamp`
//! member, and neither type is reachable through the `rustfs-gateway` facade — the suite may
//! depend on the facade and nothing else internal (`check_layer_dependencies.sh`). A listing with
//! entries in it therefore cannot be *constructed* here, only refused. Those refusals name the
//! missing export instead of inventing a value, because a listing built out of placeholder scalars
//! would turn a facade gap into a hundred and forty mysterious byte-diffs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rustfs_gateway::dto;
use rustfs_gateway::{BucketName, ByteStream, ErrorCode, Handler, HandlerError, HandlerResult, ObjectKey, Req, Resp, collect};

/// What the facade would have to export before a listing could be built here.
///
/// Printed into the error a listing operation answers with, so the report says which export is
/// missing rather than which byte differed.
pub const MISSING_SCALAR_EXPORTS: &str = "the rustfs-gateway facade exports neither \
     `rustfs_gateway_types::ETag` nor `rustfs_gateway_types::Timestamp`, and `Object`, \
     `ObjectVersion`, `Part` and `Bucket` each require one; a backend outside this workspace \
     cannot construct a listing entry at all";

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

/// The state one case runs against.
#[derive(Debug, Default)]
pub struct Fixture {
    buckets: BTreeMap<String, bool>,
    objects: BTreeMap<(String, String), StoredObject>,
    uploads: BTreeMap<String, StoredUpload>,
    next_upload: u32,
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

    /// Declares a bucket. `versioned` records what the fixture asked for; nothing reads it yet,
    /// and a case that needs versioning will fail rather than be answered from a guess.
    pub fn declare_bucket(&mut self, name: &str, versioned: bool) {
        self.buckets.insert(name.to_owned(), versioned);
    }

    /// Removes a bucket, for `setup.buckets[].absent`.
    pub fn remove_bucket(&mut self, name: &str) {
        self.buckets.remove(name);
        self.objects.retain(|(bucket, _), _| bucket != name);
    }

    /// Places an object.
    pub fn put_object(&mut self, bucket: &str, key: &str, object: StoredObject) {
        self.objects.insert((bucket.to_owned(), key.to_owned()), object);
    }

    /// Removes an object, for `setup.objects[].absent`.
    pub fn remove_object(&mut self, bucket: &str, key: &str) {
        self.objects.remove(&(bucket.to_owned(), key.to_owned()));
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

    /// An object, if it is there.
    #[must_use]
    pub fn object(&self, bucket: &str, key: &str) -> Option<&StoredObject> {
        self.objects.get(&(bucket.to_owned(), key.to_owned()))
    }

    /// Every key in a bucket, in the lexicographic order S3 lists in.
    #[must_use]
    pub fn keys_in(&self, bucket: &str) -> Vec<&str> {
        self.objects
            .keys()
            .filter(|(name, _)| name == bucket)
            .map(|(_, key)| key.as_str())
            .collect()
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

/// The error a listing answers with when its entries cannot be constructed through the facade.
fn unconstructible(shape: &'static str) -> HandlerError {
    HandlerError::not_implemented(format!("the conformance stub cannot build a `{shape}` entry: {MISSING_SCALAR_EXPORTS}"))
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
        let prefix = input.prefix.clone().unwrap_or_default();
        let mut uploads: Vec<(&String, &StoredUpload)> = fixture
            .uploads
            .iter()
            .filter(|(_, upload)| upload.bucket == input.bucket.as_str() && upload.key.starts_with(&prefix))
            .collect();
        uploads.sort_by(|left, right| left.1.key.cmp(&right.1.key).then(left.0.cmp(right.0)));
        let mut listed = Vec::new();
        for (id, upload) in uploads {
            let key = ObjectKey::new(upload.key.clone())
                .map_err(|_| HandlerError::internal_error("a fixture key is not a valid object key"))?;
            listed.push(dto::MultipartUpload {
                upload_id: Some(id.clone()),
                key: Some(key),
                storage_class: Some(dto::StorageClass::STANDARD),
                ..dto::MultipartUpload::default()
            });
        }
        Ok(Resp::new(dto::ListMultipartUploadsOutput {
            bucket: input.bucket.clone(),
            prefix: input.prefix.clone(),
            delimiter: input.delimiter.clone(),
            max_uploads: input.max_uploads.unwrap_or(1000),
            is_truncated: false,
            uploads: listed,
            ..dto::ListMultipartUploadsOutput::default()
        }))
    }

    fn list_parts(&self, input: &dto::ListPartsInput) -> HandlerResult<dto::ListParts> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let upload = fixture.uploads.get(&input.upload_id).ok_or_else(|| {
            HandlerError::new(ErrorCode::NO_SUCH_UPLOAD, "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")
        })?;
        if !upload.parts.is_empty() {
            return Err(unconstructible("Part"));
        }
        Ok(Resp::new(dto::ListPartsOutput {
            bucket: input.bucket.clone(),
            key: input.key.clone(),
            upload_id: input.upload_id.clone(),
            max_parts: input.max_parts.unwrap_or(1000),
            is_truncated: false,
            ..dto::ListPartsOutput::default()
        }))
    }

    fn list_buckets(&self, _input: &dto::ListBucketsInput) -> HandlerResult<dto::ListBuckets> {
        let fixture = self.borrow()?;
        if !fixture.buckets.is_empty() {
            return Err(unconstructible("Bucket"));
        }
        Ok(Resp::new(dto::ListBucketsOutput::default()))
    }

    fn list_objects(&self, input: &dto::ListObjectsInput) -> HandlerResult<dto::ListObjects> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        let page = paginate(
            &fixture,
            input.bucket.as_str(),
            input.prefix.as_deref().unwrap_or(""),
            input.delimiter.as_deref(),
            input.marker.as_deref(),
            input.max_keys.unwrap_or(1000),
        );
        if !page.keys.is_empty() {
            return Err(unconstructible("Object"));
        }
        Ok(Resp::new(dto::ListObjectsOutput {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            marker: input.marker.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            max_keys: input.max_keys.unwrap_or(1000),
            is_truncated: page.truncated,
            next_marker: page.next.clone(),
            common_prefixes: page.common_prefixes(),
            ..dto::ListObjectsOutput::default()
        }))
    }

    fn list_objects_v2(&self, input: &dto::ListObjectsV2Input) -> HandlerResult<dto::ListObjectsV2> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        // The continuation token this stub mints is the last key of the previous page, verbatim.
        // An opaque token would be more faithful to S3 and would make the pagination cases assert
        // something the fixture cannot honour, so the token is exactly what it means.
        let start = input
            .continuation_token
            .as_ref()
            .map(|token| token.as_str().to_owned())
            .or_else(|| input.start_after.clone());
        let page = paginate(
            &fixture,
            input.bucket.as_str(),
            input.prefix.as_deref().unwrap_or(""),
            input.delimiter.as_deref(),
            start.as_deref(),
            input.max_keys.unwrap_or(1000),
        );
        if !page.keys.is_empty() {
            return Err(unconstructible("Object"));
        }
        Ok(Resp::new(dto::ListObjectsV2Output {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            max_keys: input.max_keys.unwrap_or(1000),
            key_count: page.count(),
            is_truncated: page.truncated,
            next_continuation_token: page.next.clone().map(Into::into),
            common_prefixes: page.common_prefixes(),
            continuation_token: input.continuation_token.clone(),
            start_after: input.start_after.clone(),
            ..dto::ListObjectsV2Output::default()
        }))
    }

    fn list_object_versions(&self, input: &dto::ListObjectVersionsInput) -> HandlerResult<dto::ListObjectVersions> {
        let fixture = self.borrow()?;
        require_bucket(&fixture, &input.bucket)?;
        if !fixture.keys_in(input.bucket.as_str()).is_empty() {
            return Err(unconstructible("ObjectVersion"));
        }
        Ok(Resp::new(dto::ListObjectVersionsOutput {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            max_keys: input.max_keys.unwrap_or(1000),
            is_truncated: false,
            ..dto::ListObjectVersionsOutput::default()
        }))
    }
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
        if after.is_some_and(|marker| key <= marker) {
            continue;
        }
        let folded = delimiter.and_then(|delimiter| {
            key.get(prefix.len()..)
                .and_then(|rest| rest.find(delimiter).map(|at| prefix.len() + at + delimiter.len()))
        });
        match folded {
            Some(end) => {
                let prefix = key.get(..end).unwrap_or(key).to_owned();
                if !entries.iter().any(|(value, is_prefix)| *is_prefix && *value == prefix) {
                    entries.push((prefix, true));
                }
            }
            None => entries.push((key.to_owned(), false)),
        }
    }
    entries.sort();
    let limit = usize::try_from(max.max(0)).unwrap_or(usize::MAX);
    let truncated = entries.len() > limit;
    entries.truncate(limit);
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
}
