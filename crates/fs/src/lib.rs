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

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use md5::{Digest as _, Md5};
use rustfs_gateway::dto::{
    AbortMultipartUpload, AbortMultipartUploadOutput, CompleteMultipartUpload, CompleteMultipartUploadOutput, CopyObject,
    CreateBucket, CreateMultipartUpload, CreateMultipartUploadOutput, DeleteBucket, DeleteBucketLifecycle, DeleteObject,
    DeleteObjects, GetBucketLifecycleConfiguration, GetBucketLocation, GetBucketVersioning, GetObject, HeadBucket, HeadObject,
    ListBuckets, ListMultipartUploads, ListObjectVersions, ListObjects, ListObjectsV2, ListParts, ListPartsOutput, Owner, Part,
    PostObject, PutBucketLifecycleConfiguration, PutBucketVersioning, PutObject, UploadPart, UploadPartOutput,
};
use rustfs_gateway::{
    BucketName, ByteStream, Clock, ETag, ErrorCode, Handler, HandlerError, HandlerErrorContext, HandlerResult, MissingObject,
    ObjectKey, RegionSet, Req, ResourceVisibility, Resp, ServiceBuilder, Timestamp, US_EAST_1, UploadIdClaim, collect,
    normalize_location_constraint, resolve_upload, system_clock,
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
            lifecycle DeleteBucketLifecycle => "DeleteBucketLifecycle",
            crud DeleteObject => "DeleteObject",
            tagging DeleteObjectTagging => "DeleteObjectTagging",
            crud DeleteObjects => "DeleteObjects",
            lifecycle GetBucketLifecycleConfiguration => "GetBucketLifecycleConfiguration",
            crud GetBucketLocation => "GetBucketLocation",
            versioning GetBucketVersioning => "GetBucketVersioning",
            crud GetObject => "GetObject",
            tagging GetObjectTagging => "GetObjectTagging",
            crud HeadBucket => "HeadBucket",
            crud HeadObject => "HeadObject",
            crud ListBuckets => "ListBuckets",
            listing ListMultipartUploads => "ListMultipartUploads",
            versioning ListObjectVersions => "ListObjectVersions",
            listing ListObjects => "ListObjects",
            listing ListObjectsV2 => "ListObjectsV2",
            multipart ListParts => "ListParts",
            crud PostObject => "PostObject",
            lifecycle PutBucketLifecycleConfiguration => "PutBucketLifecycleConfiguration",
            versioning PutBucketVersioning => "PutBucketVersioning",
            crud PutObject => "PutObject",
            tagging PutObjectTagging => "PutObjectTagging",
            multipart UploadPart => "UploadPart",
        }
    };
}

macro_rules! capability_names {
    ($($group:ident $operation:ty => $name:literal,)+) => {
        const OPERATION_NAMES: &[&str] = &[$($name,)+];
    };
}

reference_operations!(capability_names);

macro_rules! register_crud_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; crud $operation:ty => $name:literal, $($rest:tt)*) => {
        register_crud_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_crud_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_multipart_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; multipart $operation:ty => $name:literal, $($rest:tt)*) => {
        register_multipart_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_multipart_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_versioning_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; versioning $operation:ty => $name:literal, $($rest:tt)*) => {
        register_versioning_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_versioning_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_listing_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; listing $operation:ty => $name:literal, $($rest:tt)*) => {
        register_listing_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_listing_entries!($backend, $builder; $($rest)*)
    };
}

macro_rules! register_lifecycle_entries {
    ($backend:expr, $builder:expr;) => { $builder };
    ($backend:expr, $builder:expr; lifecycle $operation:ty => $name:literal, $($rest:tt)*) => {
        register_lifecycle_entries!($backend, $builder.register::<$operation, _>(Arc::clone($backend)); $($rest)*)
    };
    ($backend:expr, $builder:expr; $group:ident $operation:ty => $name:literal, $($rest:tt)*) => {
        register_lifecycle_entries!($backend, $builder; $($rest)*)
    };
}

// First, so the `request_content_headers!` reader it defines is in scope for every module below.
#[macro_use]
mod content_headers;
mod buckets;
mod copy;
mod deletes;
mod lifecycle;
mod lifecycle_scheduler;
mod listing;
mod post_object;
mod reads;
mod records;
mod tagging;
mod transitions;
mod uploads;
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
    owner: Option<Owner>,
    temporary_id: AtomicU64,
    upload_id_lock: tokio::sync::Mutex<()>,
    version_lock: tokio::sync::Mutex<()>,
    clock: Arc<dyn Clock>,
    lifecycle_day_seconds: i64,
    lifecycle_scheduler_running: AtomicBool,
    lifecycle_sweep_interval: Duration,
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
            owner: None,
            temporary_id: AtomicU64::new(0),
            upload_id_lock: tokio::sync::Mutex::new(()),
            version_lock: tokio::sync::Mutex::new(()),
            clock,
            lifecycle_day_seconds: 24 * 60 * 60,
            lifecycle_scheduler_running: AtomicBool::new(false),
            lifecycle_sweep_interval: Duration::from_secs(24 * 60 * 60),
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

    /// Registers the bucket and object CRUD operations with the production service builder.
    #[must_use]
    pub fn register_crud(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_crud_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers the bounded multipart operation family with the production service builder.
    #[must_use]
    pub fn register_multipart(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_multipart_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers bucket versioning and version-aware object operations.
    #[must_use]
    pub fn register_versioning(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_versioning_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers the bounded object listing operation family.
    #[must_use]
    pub fn register_listing(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_listing_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
    }

    /// Registers persistent bucket lifecycle configuration operations and one-shot expiration support.
    #[must_use]
    pub fn register_lifecycle(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operations:tt)*) => {
                register_lifecycle_entries!(self, builder; $($operations)*)
            };
        }
        reference_operations!(register)
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

    async fn read_object(&self, bucket: &str, key: &str) -> Result<(Vec<u8>, std::fs::Metadata), HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.object_path(bucket, key);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                let bytes = tokio::fs::read(&path).await.map_err(|_| storage_error())?;
                Ok((bytes, metadata))
            }
            Ok(_) => Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the object path is not a safe regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(no_such_key(key)),
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
    let Some(stream) = body else { return Ok(Vec::new()) };
    let response = http::Response::new(stream.into_body());
    let collected = collect(response)
        .await
        .map_err(|_| HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed"))?;
    Ok(collected.body().to_vec())
}

impl Handler<CreateMultipartUpload> for FsBackend {
    async fn call(&self, request: Req<CreateMultipartUpload>) -> HandlerResult<CreateMultipartUpload> {
        let input = request.into_input();
        let checksum = uploads::UploadChecksum::negotiate(input.checksum_algorithm.as_ref(), input.checksum_type.as_ref())?;
        let checksum_type = checksum.map(uploads::UploadChecksum::dto_type);
        // S3 carries user metadata and the representation headers on the initiating request and on
        // neither the parts nor the completion, so this is the only call in the multipart family
        // that has them to persist.
        let attributes = ObjectAttributes {
            metadata: input.metadata.clone(),
            headers: request_content_headers!(input),
        };
        let upload_id = self.create_upload(&input.bucket, &input.key, checksum, &attributes).await?;
        Ok(Resp::new(CreateMultipartUploadOutput {
            bucket: input.bucket,
            key: input.key,
            upload_id,
            checksum_algorithm: input.checksum_algorithm,
            checksum_type,
            ..CreateMultipartUploadOutput::default()
        }))
    }
}

impl Handler<UploadPart> for FsBackend {
    async fn call(&self, request: Req<UploadPart>) -> HandlerResult<UploadPart> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let bytes = drain(input.body).await?;
        if i64::try_from(bytes.len()).ok() != Some(input.content_length) {
            return Err(HandlerError::new(
                ErrorCode::INCOMPLETE_BODY,
                "the request body did not match its declared content length",
            ));
        }
        let (upload_id, record) = self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?;
        let checksum_spec = match record.checksum {
            Some(checksum) => Some(checksum.validate_part(input.checksum_spec, &bytes)?),
            None => input.checksum_spec,
        };
        let upload = self.upload_path(input.bucket.as_str(), &upload_id);
        let destination = Self::part_path(&upload, input.part_number);
        if let Ok(metadata) = tokio::fs::symlink_metadata(&destination).await
            && (!metadata.is_file() || metadata.file_type().is_symlink())
        {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the multipart part path is not a safe regular file",
            ));
        }
        self.write_atomic(&upload.join(PARTS_DIR), &destination, &bytes).await?;
        Ok(Resp::new(UploadPartOutput {
            e_tag: etag(&bytes)?,
            checksum_spec,
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
        let max_parts_value = input.max_parts.unwrap_or(1000);
        let max_parts = usize::try_from(max_parts_value)
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "max-parts must be a non-negative integer"))?;
        let numbers = self.list_part_numbers(&upload).await?;
        let selected: Vec<i32> = numbers
            .iter()
            .copied()
            .filter(|number| *number > marker)
            .take(max_parts)
            .collect();
        let is_truncated = numbers.iter().copied().filter(|number| *number > marker).count() > selected.len();
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

impl Handler<CompleteMultipartUpload> for FsBackend {
    async fn call(&self, request: Req<CompleteMultipartUpload>) -> HandlerResult<CompleteMultipartUpload> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let (upload_id, record) = self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?;
        let completion_claim = input.checksum_spec;
        if let Some(checksum) = record.checksum {
            checksum.validate_completion_type(input.checksum_type.as_ref())?;
        } else if input.checksum_type.is_some() || completion_claim.is_some() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the completion names a checksum type for an upload without checksum negotiation",
            ));
        }
        let completed = input.multipart_upload.parts;
        if completed.is_empty() {
            return Err(HandlerError::new(ErrorCode::INVALID_PART, "the completion names no uploaded part"));
        }
        let mut requested = Vec::with_capacity(completed.len());
        let mut previous = 0;
        for part in completed {
            let number = part.part_number;
            uploads::validate_completion_part_number(record.checksum, previous, number)?;
            previous = number;
            let checksum = record
                .checksum
                .map(|selection| selection.completed_part(&part))
                .transpose()?
                .flatten();
            let entity_tag = part
                .e_tag
                .ok_or_else(|| HandlerError::new(ErrorCode::INVALID_PART, "a completed part has no entity tag"))?;
            requested.push((number, entity_tag, checksum));
        }

        let upload = self.upload_path(input.bucket.as_str(), &upload_id);
        let mut completed_bytes = Vec::new();
        let mut part_digests = Vec::with_capacity(requested.len());
        let mut part_checksums = Vec::with_capacity(requested.len());
        let final_part = requested.len().saturating_sub(1);
        for (index, (number, expected, expected_checksum)) in requested.iter().enumerate() {
            let path = Self::part_path(&upload, *number);
            let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => HandlerError::new(ErrorCode::INVALID_PART, "a completed part was not uploaded"),
                _ => storage_error(),
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the multipart part path is not a safe regular file",
                ));
            }
            let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
            if index != final_part && bytes.len() < MIN_MULTIPART_PART_BYTES {
                return Err(HandlerError::new(
                    ErrorCode::ENTITY_TOO_SMALL,
                    "the proposed multipart upload contains an undersized non-final part",
                ));
            }
            let actual = etag(&bytes)?;
            if actual != *expected {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_PART,
                    "a completed part entity tag does not match the uploaded part",
                ));
            }
            if let Some(selection) = record.checksum {
                let actual_checksum = selection.validate_part(*expected_checksum, &bytes)?;
                part_checksums.push(actual_checksum);
            }
            part_digests.push(Md5::digest(&bytes).into());
            completed_bytes.extend_from_slice(&bytes);
        }
        let composite = ETag::from_part_digests(&part_digests).map_err(|_| storage_error())?;
        let completed_checksum = record
            .checksum
            .map(|selection| selection.complete(&part_checksums, &completed_bytes))
            .transpose()?;
        if let (Some(selection), Some(actual)) = (record.checksum, completed_checksum.as_ref()) {
            selection.validate_completed_object(completion_claim, actual)?;
        }

        let tombstone = self.uploads_path(input.bucket.as_str()).join(format!(
            ".complete-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::rename(&upload, &tombstone).await.map_err(|_| no_such_upload())?;
        let published = match self
            .publish_object(
                input.bucket.as_str(),
                input.key.as_str(),
                &completed_bytes,
                &composite,
                &record.attributes,
            )
            .await
        {
            Ok(published) => published,
            Err(error) => {
                let _ = tokio::fs::rename(&tombstone, &upload).await;
                return Err(error);
            }
        };
        let _ = tokio::fs::remove_dir_all(tombstone).await;
        let mut output = CompleteMultipartUploadOutput {
            location: Some(format!("/{}/{}", input.bucket.as_str(), input.key.as_str())),
            bucket: Some(input.bucket),
            key: Some(input.key),
            e_tag: Some(composite),
            version_id: published.version_id,
            checksum_type: record.checksum.map(uploads::UploadChecksum::dto_type),
            ..CompleteMultipartUploadOutput::default()
        };
        if let Some(checksum) = completed_checksum {
            let rendered = checksum.render_base64().to_owned();
            match checksum.algorithm() {
                rustfs_gateway::ChecksumAlgorithm::Crc32 => output.checksum_crc32 = Some(rendered),
                rustfs_gateway::ChecksumAlgorithm::Crc32c => output.checksum_crc32c = Some(rendered),
                rustfs_gateway::ChecksumAlgorithm::Crc64Nvme => output.checksum_crc64nvme = Some(rendered),
                rustfs_gateway::ChecksumAlgorithm::Sha1 => output.checksum_sha1 = Some(rendered),
                rustfs_gateway::ChecksumAlgorithm::Sha256 => output.checksum_sha256 = Some(rendered),
                _ => return Err(storage_error()),
            }
        }
        Ok(Resp::new(output))
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
