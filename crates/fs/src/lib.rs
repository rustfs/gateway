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

//! Filesystem-backed reference handlers for `rustfs-gateway`.
//!
//! Responsible for: a small, inspectable persistence backend used to exercise real S3 handlers,
//! including atomically published multipart uploads, persistent object versions and tags, and lifecycle actions.
//! NOT responsible for: production durability, physical storage tiers, or cross-process coordination.
//! Upstream: `rustfs-gateway`. Downstream: examples and backend contract tests.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
// No stdout, no stderr, no `dbg!` outside tests: a diagnostic is a `tracing` event (docs/observability.md).
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro))]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use md5::{Digest as _, Md5};
use rustfs_gateway::dto::{
    AbortMultipartUpload, AbortMultipartUploadOutput, CreateMultipartUpload, CreateMultipartUploadOutput, ListParts,
    ListPartsOutput, Owner, Part, ServerSideEncryption, UploadPart, UploadPartOutput,
};
use rustfs_gateway::{
    BucketName, ByteStream, Clock, ETag, ErrorCode, Handler, HandlerError, HandlerErrorContext, HandlerResult, MissingObject,
    ObjectKey, REGION_MATCH_POLICY, RegionMatchPolicy, RegionSet, Req, ResourceVisibility, Resp, Timestamp, TrailingHeaders,
    US_EAST_1, UploadIdClaim, collect, normalize_location_constraint, request_checksum, resolve_upload, system_clock,
};
use sha2::Sha256;
use tokio::io::AsyncWriteExt as _;

const OBJECTS_DIR: &str = "objects";
const UPLOADS_DIR: &str = "uploads";
const VERSIONS_DIR: &str = "versions";
const PARTS_DIR: &str = "parts";
const UPLOAD_RECORD: &str = "record";
const MIN_MULTIPART_PART_BYTES: usize = 5 * 1024 * 1024;

macro_rules! reference_operations {
    ($visitor:ident) => {
        $visitor! {
            multipart AbortMultipartUpload => "AbortMultipartUpload",
            multipart CompleteMultipartUpload => "CompleteMultipartUpload",
            crud CopyObject => "CopyObject",
            crud CreateBucket => "CreateBucket",
            multipart CreateMultipartUpload => "CreateMultipartUpload",
            crud DeleteBucket => "DeleteBucket",
            cors DeleteBucketCors => "DeleteBucketCors",
            encryption DeleteBucketEncryption => "DeleteBucketEncryption",
            lifecycle DeleteBucketLifecycle => "DeleteBucketLifecycle",
            policy DeleteBucketPolicy => "DeleteBucketPolicy",
            tagging DeleteBucketTagging => "DeleteBucketTagging",
            crud DeleteObject => "DeleteObject",
            tagging DeleteObjectTagging => "DeleteObjectTagging",
            crud DeleteObjects => "DeleteObjects",
            policy DeletePublicAccessBlock => "DeletePublicAccessBlock",
            acl GetBucketAcl => "GetBucketAcl",
            cors GetBucketCors => "GetBucketCors",
            encryption GetBucketEncryption => "GetBucketEncryption",
            lifecycle GetBucketLifecycleConfiguration => "GetBucketLifecycleConfiguration",
            crud GetBucketLocation => "GetBucketLocation",
            policy GetBucketPolicy => "GetBucketPolicy",
            policy GetBucketPolicyStatus => "GetBucketPolicyStatus",
            tagging GetBucketTagging => "GetBucketTagging",
            versioning GetBucketVersioning => "GetBucketVersioning",
            crud GetObject => "GetObject",
            acl GetObjectAcl => "GetObjectAcl",
            crud GetObjectAttributes => "GetObjectAttributes",
            tagging GetObjectTagging => "GetObjectTagging",
            policy GetPublicAccessBlock => "GetPublicAccessBlock",
            crud HeadBucket => "HeadBucket",
            crud HeadObject => "HeadObject",
            crud ListBuckets => "ListBuckets",
            listing ListMultipartUploads => "ListMultipartUploads",
            versioning ListObjectVersions => "ListObjectVersions",
            listing ListObjects => "ListObjects",
            listing ListObjectsV2 => "ListObjectsV2",
            multipart ListParts => "ListParts",
            crud PostObject => "PostObject",
            acl PutBucketAcl => "PutBucketAcl",
            cors PutBucketCors => "PutBucketCors",
            encryption PutBucketEncryption => "PutBucketEncryption",
            lifecycle PutBucketLifecycleConfiguration => "PutBucketLifecycleConfiguration",
            policy PutBucketPolicy => "PutBucketPolicy",
            tagging PutBucketTagging => "PutBucketTagging",
            versioning PutBucketVersioning => "PutBucketVersioning",
            crud PutObject => "PutObject",
            acl PutObjectAcl => "PutObjectAcl",
            tagging PutObjectTagging => "PutObjectTagging",
            policy PutPublicAccessBlock => "PutPublicAccessBlock",
            multipart UploadPart => "UploadPart",
            multipart UploadPartCopy => "UploadPartCopy",
        }
    };
}

macro_rules! capability_names {
    ($($group:ident $operation:ty => $name:literal,)+) => {
        const OPERATION_NAMES: &[&str] = &[$($name,)+];
    };
}

reference_operations!(capability_names);

// First, so the `request_content_headers!` reader it defines is in scope for every module below.
#[macro_use]
mod content_headers;
// The `register_*` methods and the entry macros behind them, kept together.
mod acl;
mod bucket_cors;
mod bucket_tagging;
mod buckets;
mod completion;
mod completion_replay;
mod conditions;
#[macro_use]
mod checksums;
pub(crate) mod copy;
mod deletes;
mod encryption;
mod lifecycle;
mod lifecycle_scheduler;
mod listing;
mod object_attributes;
mod part_lengths;
mod part_metadata;
pub mod policy;
mod post_object;
mod reads;
mod records;
mod registry;
mod rustfs_parity;
mod tagging;
mod transitions;
mod upload_part_copy;
mod uploads;
mod version_listing;
mod versioning;

use records::ObjectAttributes;
use uploads::UploadRecord;

pub use lifecycle_scheduler::{LifecycleScheduler, LifecycleSchedulerReport};

/// A deliberately small filesystem reference backend.
///
/// Bucket names and object keys are never appended to the root as raw path components. Bucket
/// names are hex encoded and object keys select a SHA-256-named file, so S3 keys such as
/// `../outside` remain data rather than paths. This is a reference implementation, not a claim of
/// crash-consistent or hostile-concurrent-filesystem durability.
pub struct FsBackend {
    root: PathBuf,
    region: String,
    regions: RegionSet,
    region_match_policy: RegionMatchPolicy,
    owner: Option<Owner>,
    temporary_id: AtomicU64,
    /// Each bucket's reserved upload-ID window, keyed by bucket name; the lock serializes allocation.
    upload_id_windows: tokio::sync::Mutex<std::collections::HashMap<String, uploads::UploadIdWindow>>,
    version_lock: tokio::sync::Mutex<()>,
    clock: Arc<dyn Clock>,
    lifecycle_day_seconds: i64,
    lifecycle_scheduler_running: AtomicBool,
    lifecycle_sweep_interval: Duration,
    /// The legacy-RustFS answers a deployment asked for, each off by default ([`rustfs_parity`]).
    rustfs_parity: rustfs_parity::RustfsParity,
}

impl FsBackend {
    /// Opens or creates a backend rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the root cannot be created or resolved, or when the root itself
    /// is a symbolic link.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with_clock(root, Arc::new(system_clock()))
    }

    /// Opens or creates a backend with the supplied wall clock.
    ///
    /// # Errors
    ///
    /// Returns an I/O error under the same conditions as [`Self::open`].
    pub fn open_with_clock(root: impl AsRef<Path>, clock: Arc<dyn Clock>) -> io::Result<Self> {
        std::fs::create_dir_all(root.as_ref())?;
        let metadata = std::fs::symlink_metadata(root.as_ref())?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the backend root must not be a symbolic link",
            ));
        }
        if !metadata.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the backend root must be a directory"));
        }
        let regions = RegionSet::new([US_EAST_1])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "us-east-1 is not a usable region name"))?;
        Ok(Self {
            root: std::fs::canonicalize(root.as_ref())?,
            region: US_EAST_1.to_owned(),
            regions,
            region_match_policy: REGION_MATCH_POLICY,
            owner: None,
            temporary_id: AtomicU64::new(0),
            upload_id_windows: tokio::sync::Mutex::default(),
            version_lock: tokio::sync::Mutex::new(()),
            clock,
            lifecycle_day_seconds: 24 * 60 * 60,
            lifecycle_scheduler_running: AtomicBool::new(false),
            lifecycle_sweep_interval: Duration::from_secs(24 * 60 * 60),
            rustfs_parity: rustfs_parity::RustfsParity::default(),
        })
    }

    /// Uses `interval` as one lifecycle day and one automatic sweep cadence in debug mode.
    ///
    /// This hook lets conformance suites observe day-based expiration without waiting for wall-clock
    /// days. A scheduler started with [`Self::start_lifecycle_scheduler`] waits this same interval
    /// between sweeps. Production-like callers should leave the default 24-hour cadence unchanged.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when the interval is zero or cannot fit in signed seconds.
    pub fn with_lifecycle_debug_interval(mut self, interval: Duration) -> io::Result<Self> {
        let seconds = i64::try_from(interval.as_secs())
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the lifecycle debug interval must be non-zero"))?;
        self.lifecycle_day_seconds = seconds;
        self.lifecycle_sweep_interval = interval;
        Ok(self)
    }

    /// Serves `region` instead of `us-east-1`.
    ///
    /// One value answers three questions: the `x-amz-bucket-region` a `HeadBucket` reports, the
    /// `LocationConstraint` a `GetBucketLocation` answers, and the only constraint a `CreateBucket`
    /// may name. A deployment that could set them separately could hold a bucket it cannot report
    /// the region of, which is what `GetBucketLocation` exists to answer.
    ///
    /// `EU` is accepted and stored as `eu-west-1`: the alias denotes that region rather than being
    /// a second one (`q-region-0003`).
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for a region the `LocationConstraint` enumeration cannot
    /// name. It is refused here, when the backend is assembled, rather than when a client asks —
    /// the alternative is a `GetBucketLocation` that must either fail or report the wrong region,
    /// and by then the buckets already exist.
    pub fn with_region(mut self, region: &str) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "the served region is not a location the model names");
        let normalized = normalize_location_constraint(Some(region)).ok_or_else(invalid)?;
        if normalized != US_EAST_1 && !rustfs_gateway::dto::LocationConstraint::VALUES.contains(&normalized) {
            return Err(invalid());
        }
        self.regions = RegionSet::new([normalized]).map_err(|_| invalid())?;
        self.region = normalized.to_owned();
        Ok(self)
    }

    /// Matches a `CreateBucket`'s `LocationConstraint` under `policy` instead of the operation's
    /// default [`REGION_MATCH_POLICY`].
    ///
    /// The served region is unchanged: a relaxed posture accepts another spelling of it or
    /// discards the constraint, and never creates a bucket in another region. The RustFS-profile
    /// launcher uses [`RegionMatchPolicy::IgnoreConstraint`] (rustfs/gateway#914).
    #[must_use]
    pub const fn with_region_match_policy(mut self, policy: RegionMatchPolicy) -> Self {
        self.region_match_policy = policy;
        self
    }

    /// Reports one fixed owner for every object stored in this backend.
    ///
    /// The filesystem backend is single-tenant per data root. Configuring the owner at assembly
    /// time keeps listing responses independent of the identity that happened to request them.
    #[must_use]
    pub fn with_owner(mut self, id: impl Into<String>, display_name: impl Into<String>) -> Self {
        self.owner = Some(Owner {
            id: Some(id.into()),
            display_name: Some(display_name.into()),
        });
        self
    }

    fn reported_owner(&self) -> Option<&Owner> {
        self.owner.as_ref()
    }

    /// The one region this backend serves.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The exact operations this bounded reference backend registers.
    pub fn supported_operations(&self) -> impl ExactSizeIterator<Item = &'static str> + Clone {
        OPERATION_NAMES.iter().copied()
    }

    fn bucket_path(&self, bucket: &str) -> PathBuf {
        self.root.join(format!("b-{}", hex::encode(bucket.as_bytes())))
    }

    fn objects_path(&self, bucket: &str) -> PathBuf {
        self.bucket_path(bucket).join(OBJECTS_DIR)
    }

    fn uploads_path(&self, bucket: &str) -> PathBuf {
        self.bucket_path(bucket).join(UPLOADS_DIR)
    }

    fn versions_path(&self, bucket: &str) -> PathBuf {
        self.bucket_path(bucket).join(VERSIONS_DIR)
    }

    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        self.objects_path(bucket).join(format!("o-{}", hex::encode(digest)))
    }

    fn upload_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        let digest = Sha256::digest(upload_id.as_bytes());
        self.uploads_path(bucket).join(format!("u-{}", hex::encode(digest)))
    }

    fn part_path(upload: &Path, part_number: i32) -> PathBuf {
        upload.join(PARTS_DIR).join(format!("p-{part_number:05}"))
    }

    async fn require_directory(&self, path: &Path, missing: HandlerError) -> Result<(), HandlerError> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
            Ok(_) => Err(HandlerError::new(ErrorCode::INVALID_REQUEST, "the storage path is not a safe directory")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(missing),
            Err(_) => Err(storage_error()),
        }
    }

    async fn require_bucket(&self, bucket: &str) -> Result<(), HandlerError> {
        self.require_directory(&self.bucket_path(bucket), no_such_bucket()).await?;
        self.require_directory(&self.objects_path(bucket), storage_error()).await?;
        self.require_directory(&self.uploads_path(bucket), storage_error()).await?;
        self.require_directory(&self.versions_path(bucket), storage_error()).await
    }

    /// The plain object file and its metadata, or `None` when the key holds no object. Absence is a
    /// value here because a conditional request is evaluated against it (rustfs/gateway#808).
    async fn read_object_if_present(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Vec<u8>, std::fs::Metadata)>, HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.object_path(bucket, key);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                let bytes = tokio::fs::read(&path).await.map_err(|_| storage_error())?;
                Ok(Some((bytes, metadata)))
            }
            Ok(_) => Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the object path is not a safe regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(storage_error()),
        }
    }

    async fn write_atomic(&self, directory: &Path, destination: &Path, bytes: &[u8]) -> Result<(), HandlerError> {
        self.require_directory(directory, storage_error()).await?;
        let temporary = directory.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(|_| storage_error())?;
        let written = async {
            file.write_all(bytes).await?;
            file.sync_all().await?;
            tokio::fs::rename(&temporary, destination).await
        }
        .await;
        if written.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(storage_error());
        }
        Ok(())
    }

    async fn directory_is_empty(&self, path: &Path) -> Result<bool, HandlerError> {
        self.require_directory(path, storage_error()).await?;
        let mut entries = tokio::fs::read_dir(path).await.map_err(|_| storage_error())?;
        Ok(entries.next_entry().await.map_err(|_| storage_error())?.is_none())
    }

    fn resolve_upload(
        &self,
        claim: &UploadIdClaim,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<(String, UploadRecord), HandlerError> {
        let (resolved, record) =
            resolve_upload(claim, bucket, key, |upload_id| self.read_upload_record(bucket.as_str(), upload_id))
                .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
        Ok((resolved.id().to_owned(), record))
    }

    async fn list_part_numbers(&self, upload: &Path) -> Result<Vec<i32>, HandlerError> {
        let parts = upload.join(PARTS_DIR);
        self.require_directory(&parts, no_such_upload()).await?;
        let mut entries = tokio::fs::read_dir(parts).await.map_err(|_| storage_error())?;
        let mut numbers = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { return Err(storage_error()) };
            let Some(number) = name.strip_prefix("p-").and_then(|value| value.parse::<i32>().ok()) else {
                continue;
            };
            let metadata = entry.metadata().await.map_err(|_| storage_error())?;
            if !metadata.is_file() || entry.file_type().await.map_err(|_| storage_error())?.is_symlink() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the multipart part path is not a safe regular file",
                ));
            }
            numbers.push(number);
        }
        numbers.sort_unstable();
        Ok(numbers)
    }
}

fn storage_error() -> HandlerError {
    HandlerError::internal_error("the filesystem reference backend could not complete the storage operation")
}

fn no_such_bucket() -> HandlerError {
    HandlerErrorContext::missing_bucket().into()
}

fn no_such_key(key: &str) -> HandlerError {
    match ObjectKey::new(key.to_owned()) {
        Ok(key) => HandlerErrorContext::missing_object_for(key, MissingObject::Key, ResourceVisibility::Visible).into(),
        Err(_) => storage_error(),
    }
}

fn no_such_upload() -> HandlerError {
    HandlerError::new(
        ErrorCode::NO_SUCH_UPLOAD,
        "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
    )
}

fn etag(bytes: &[u8]) -> Result<ETag, HandlerError> {
    ETag::new(hex::encode(Md5::digest(bytes))).map_err(|_| storage_error())
}

fn last_modified(metadata: &std::fs::Metadata) -> Timestamp {
    let seconds = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default();
    Timestamp::from_secs(seconds)
}

async fn drain(body: Option<ByteStream>) -> Result<Vec<u8>, HandlerError> {
    drain_with_trailers(body).await.map(|(bytes, _)| bytes)
}

/// Reads a request body to its end, keeping the trailer section it ended with.
///
/// The section is reachable only here, after the last byte: a checksum carried as a trailer is
/// otherwise indistinguishable from no checksum (rustfs/gateway#929).
async fn drain_with_trailers(body: Option<ByteStream>) -> Result<(Vec<u8>, TrailingHeaders), HandlerError> {
    let Some(stream) = body else {
        return Ok((Vec::new(), TrailingHeaders::empty()));
    };
    let response = http::Response::new(stream.into_body());
    let collected = collect(response)
        .await
        .map_err(|_| HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed"))?;
    let trailers = TrailingHeaders::from_header_map(collected.trailers().iter().cloned().collect());
    Ok((collected.body().to_vec(), trailers))
}

impl Handler<CreateMultipartUpload> for FsBackend {
    async fn call(&self, request: Req<CreateMultipartUpload>) -> HandlerResult<CreateMultipartUpload> {
        let input = request.into_input();
        let checksum = uploads::UploadChecksum::negotiate(input.checksum_algorithm.as_ref(), input.checksum_type.as_ref())?;
        let checksum_type = checksum.map(uploads::UploadChecksum::dto_type);
        // S3 carries user metadata and the representation headers on the initiating request and on
        // neither the parts nor the completion, so this is the only call in the multipart family
        // that has them to persist.
        let encryption = self
            .write_encryption(
                input.bucket.as_str(),
                input.server_side_encryption.as_ref().map(ServerSideEncryption::as_str),
                input.ssekms_key_id.as_deref(),
            )
            .await?;
        let attributes = ObjectAttributes {
            checksum: None,
            tags: tagging::tags_from_header(input.tagging.as_deref())?,
            metadata: input.metadata.clone(),
            headers: request_content_headers!(self, input).with_encryption(encryption.clone()),
            ..ObjectAttributes::default()
        };
        let upload_id = self.create_upload(&input.bucket, &input.key, checksum, &attributes).await?;
        Ok(Resp::new(CreateMultipartUploadOutput {
            bucket: input.bucket,
            key: input.key,
            upload_id,
            checksum_algorithm: input.checksum_algorithm,
            checksum_type,
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            ..CreateMultipartUploadOutput::default()
        }))
    }
}

impl FsBackend {
    /// Writes one part of an upload, refusing a part path that is not a safe regular file.
    pub(crate) async fn store_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: i32,
        bytes: &[u8],
    ) -> Result<(), HandlerError> {
        let upload = self.upload_path(bucket, upload_id);
        let destination = Self::part_path(&upload, part_number);
        if let Ok(metadata) = tokio::fs::symlink_metadata(&destination).await
            && (!metadata.is_file() || metadata.file_type().is_symlink())
        {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the multipart part path is not a safe regular file",
            ));
        }
        self.write_atomic(&upload.join(PARTS_DIR), &destination, bytes).await
    }
}

impl Handler<UploadPart> for FsBackend {
    async fn call(&self, request: Req<UploadPart>) -> HandlerResult<UploadPart> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let (bytes, trailers) = drain_with_trailers(input.body).await?;
        if i64::try_from(bytes.len()).ok() != Some(input.content_length) {
            return Err(HandlerError::new(
                ErrorCode::INCOMPLETE_BODY,
                "the request body did not match its declared content length",
            ));
        }
        let (upload_id, record) = self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?;
        let claimed = request_checksum(input.checksum_spec, &trailers)?;
        let checksum_spec = match record.checksum {
            Some(checksum) => Some(checksum.validate_part(claimed, &bytes)?),
            None => claimed,
        };
        self.store_part(input.bucket.as_str(), &upload_id, input.part_number, &bytes)
            .await?;
        // A part reports the encryption its upload was initiated under.
        let encryption = record.attributes.headers.encryption();
        Ok(Resp::new(UploadPartOutput {
            e_tag: etag(&bytes)?,
            checksum_spec,
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            ..UploadPartOutput::default()
        }))
    }
}

impl Handler<ListParts> for FsBackend {
    async fn call(&self, request: Req<ListParts>) -> HandlerResult<ListParts> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let (upload_id, _) = self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?;
        let upload = self.upload_path(input.bucket.as_str(), &upload_id);
        let marker = input
            .part_number_marker
            .as_deref()
            .map(str::parse::<i32>)
            .transpose()
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "part-number-marker must be an integer"))?
            .unwrap_or_default();
        // AWS caps a ListParts response at 1000 parts (https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html).
        let max_parts_value = input.max_parts.unwrap_or(1000).min(1000);
        let max_parts = usize::try_from(max_parts_value)
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "max-parts must be a non-negative integer"))?;
        let numbers = self.list_part_numbers(&upload).await?;
        let selected: Vec<i32> = numbers
            .iter()
            .copied()
            .filter(|number| *number > marker)
            .take(max_parts)
            .collect();
        let is_truncated = max_parts > 0 && numbers.iter().copied().filter(|number| *number > marker).count() > selected.len();
        let mut parts = Vec::with_capacity(selected.len());
        for number in selected {
            let path = Self::part_path(&upload, number);
            let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|_| storage_error())?;
            let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
            parts.push(Part {
                e_tag: etag(&bytes)?,
                last_modified: Some(last_modified(&metadata)),
                part_number: number,
                size: i64::try_from(bytes.len()).map_err(|_| storage_error())?,
                ..Part::default()
            });
        }
        let next_part_number_marker = is_truncated
            .then(|| parts.last().map(|part| part.part_number.to_string()))
            .flatten();
        Ok(Resp::new(ListPartsOutput {
            bucket: input.bucket,
            key: input.key,
            upload_id,
            part_number_marker: input.part_number_marker,
            next_part_number_marker,
            max_parts: max_parts_value,
            is_truncated,
            parts,
            ..ListPartsOutput::default()
        }))
    }
}

impl Handler<AbortMultipartUpload> for FsBackend {
    async fn call(&self, request: Req<AbortMultipartUpload>) -> HandlerResult<AbortMultipartUpload> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let (upload_id, _) = self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?;
        let upload = self.upload_path(input.bucket.as_str(), &upload_id);
        let tombstone = self.uploads_path(input.bucket.as_str()).join(format!(
            ".abort-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::rename(upload, &tombstone).await.map_err(|_| no_such_upload())?;
        tokio::fs::remove_dir_all(tombstone).await.map_err(|_| storage_error())?;
        Ok(Resp::new(AbortMultipartUploadOutput::default()))
    }
}
