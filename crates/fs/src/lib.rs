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
//! Responsible for: a small, inspectable persistence backend used to exercise real S3 handlers.
//! NOT responsible for: production durability, multipart uploads, versioning, or lifecycle policy.
//! Upstream: `rustfs-gateway`. Downstream: examples and backend contract tests.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use md5::{Digest as _, Md5};
use rustfs_gateway::dto::{
    CreateBucket, CreateBucketOutput, DeleteBucket, DeleteBucketOutput, DeleteObject, DeleteObjectOutput, GetObject,
    GetObjectOutput, HeadBucket, HeadBucketOutput, HeadObject, HeadObjectOutput, PutObject, PutObjectOutput,
};
use rustfs_gateway::{
    ByteStream, ETag, ErrorCode, Handler, HandlerError, HandlerErrorContext, HandlerResult, MissingObject, ObjectKey, Req,
    ResourceVisibility, Resp, ServiceBuilder, Timestamp, collect,
};
use sha2::Sha256;
use tokio::io::AsyncWriteExt as _;

const OBJECTS_DIR: &str = "objects";

macro_rules! crud_operations {
    ($visitor:ident) => {
        $visitor! {
            CreateBucket => "CreateBucket",
            DeleteBucket => "DeleteBucket",
            DeleteObject => "DeleteObject",
            GetObject => "GetObject",
            HeadBucket => "HeadBucket",
            HeadObject => "HeadObject",
            PutObject => "PutObject",
        }
    };
}

macro_rules! capability_names {
    ($($operation:ty => $name:literal,)+) => {
        const CRUD_OPERATION_NAMES: &[&str] = &[$($name,)+];
    };
}

crud_operations!(capability_names);

/// A deliberately small filesystem reference backend.
///
/// Bucket names and object keys are never appended to the root as raw path components. Bucket
/// names are hex encoded and object keys select a SHA-256-named file, so S3 keys such as
/// `../outside` remain data rather than paths. This is a reference implementation, not a claim of
/// crash-consistent or hostile-concurrent-filesystem durability.
pub struct FsBackend {
    root: PathBuf,
    temporary_id: AtomicU64,
}

impl FsBackend {
    /// Opens or creates a backend rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the root cannot be created or resolved, or when the root itself
    /// is a symbolic link.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
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
        Ok(Self {
            root: std::fs::canonicalize(root.as_ref())?,
            temporary_id: AtomicU64::new(0),
        })
    }

    /// The exact operations this bounded reference backend registers.
    pub fn supported_operations(&self) -> impl ExactSizeIterator<Item = &'static str> + Clone {
        CRUD_OPERATION_NAMES.iter().copied()
    }

    /// Registers every supported operation with the production service builder.
    #[must_use]
    pub fn register_crud(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        macro_rules! register {
            ($($operation:ty => $name:literal,)+) => {{
                let builder = builder;
                $(let builder = builder.register::<$operation, _>(Arc::clone(self));)+
                builder
            }};
        }
        crud_operations!(register)
    }

    fn bucket_path(&self, bucket: &str) -> PathBuf {
        self.root.join(format!("b-{}", hex::encode(bucket.as_bytes())))
    }

    fn objects_path(&self, bucket: &str) -> PathBuf {
        self.bucket_path(bucket).join(OBJECTS_DIR)
    }

    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        self.objects_path(bucket).join(format!("o-{}", hex::encode(digest)))
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
        self.require_directory(&self.objects_path(bucket), storage_error()).await
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

    async fn write_object(&self, bucket: &str, key: &str, bytes: &[u8]) -> Result<(), HandlerError> {
        self.require_bucket(bucket).await?;
        let objects = self.objects_path(bucket);
        let temporary = objects.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, Ordering::Relaxed)
        ));
        let destination = self.object_path(bucket, key);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(|_| storage_error())?;
        let written = async {
            file.write_all(bytes).await?;
            file.sync_all().await?;
            tokio::fs::rename(&temporary, &destination).await
        }
        .await;
        if written.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(storage_error());
        }
        Ok(())
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

impl Handler<CreateBucket> for FsBackend {
    async fn call(&self, request: Req<CreateBucket>) -> HandlerResult<CreateBucket> {
        let bucket = request.input().bucket.as_str();
        let path = self.bucket_path(bucket);
        match tokio::fs::create_dir(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.require_directory(&path, no_such_bucket()).await?;
                return Ok(Resp::new(CreateBucketOutput {
                    location: Some(format!("/{bucket}")),
                }));
            }
            Err(_) => return Err(storage_error()),
        }
        if tokio::fs::create_dir(path.join(OBJECTS_DIR)).await.is_err() {
            let _ = tokio::fs::remove_dir(&path).await;
            return Err(storage_error());
        }
        Ok(Resp::new(CreateBucketOutput {
            location: Some(format!("/{bucket}")),
        }))
    }
}

impl Handler<HeadBucket> for FsBackend {
    async fn call(&self, request: Req<HeadBucket>) -> HandlerResult<HeadBucket> {
        self.require_bucket(request.input().bucket.as_str()).await?;
        Ok(Resp::new(HeadBucketOutput {
            bucket_region: "us-east-1".to_owned(),
        }))
    }
}

impl Handler<DeleteBucket> for FsBackend {
    async fn call(&self, request: Req<DeleteBucket>) -> HandlerResult<DeleteBucket> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        let objects = self.objects_path(bucket);
        let mut entries = tokio::fs::read_dir(&objects).await.map_err(|_| storage_error())?;
        if entries.next_entry().await.map_err(|_| storage_error())?.is_some() {
            return Err(HandlerError::new(
                ErrorCode::BUCKET_NOT_EMPTY,
                "The bucket you tried to delete is not empty",
            ));
        }
        tokio::fs::remove_dir(&objects).await.map_err(|_| storage_error())?;
        tokio::fs::remove_dir(self.bucket_path(bucket))
            .await
            .map_err(|_| storage_error())?;
        Ok(Resp::new(DeleteBucketOutput::default()))
    }
}

impl Handler<PutObject> for FsBackend {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let input = request.into_input();
        let bytes = drain(input.body).await?;
        self.write_object(input.bucket.as_str(), input.key.as_str(), &bytes).await?;
        Ok(Resp::new(PutObjectOutput {
            size: i64::try_from(bytes.len()).ok(),
            e_tag: etag(&bytes)?,
            ..PutObjectOutput::default()
        }))
    }
}

impl Handler<GetObject> for FsBackend {
    async fn call(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        let input = request.input();
        let (bytes, metadata) = self.read_object(input.bucket.as_str(), input.key.as_str()).await?;
        Ok(Resp::new(GetObjectOutput {
            content_length: i64::try_from(bytes.len()).ok(),
            e_tag: Some(etag(&bytes)?),
            last_modified: Some(last_modified(&metadata)),
            body: Some(ByteStream::from_bytes(bytes::Bytes::from(bytes))),
            ..GetObjectOutput::default()
        }))
    }
}

impl Handler<HeadObject> for FsBackend {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        let input = request.input();
        let (bytes, metadata) = self.read_object(input.bucket.as_str(), input.key.as_str()).await?;
        Ok(Resp::new(HeadObjectOutput {
            content_length: i64::try_from(bytes.len()).ok(),
            e_tag: Some(etag(&bytes)?),
            last_modified: Some(last_modified(&metadata)),
            ..HeadObjectOutput::default()
        }))
    }
}

impl Handler<DeleteObject> for FsBackend {
    async fn call(&self, request: Req<DeleteObject>) -> HandlerResult<DeleteObject> {
        let input = request.input();
        self.require_bucket(input.bucket.as_str()).await?;
        let path = self.object_path(input.bucket.as_str(), input.key.as_str());
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|_| storage_error())?;
            }
            Ok(_) => {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the object path is not a safe regular file",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        Ok(Resp::new(DeleteObjectOutput::default()))
    }
}
