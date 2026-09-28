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

//! Persistent object-tagging handlers.
//!
//! Responsible for: validating and atomically replacing one version's complete tag set, answering
//! current or explicit-version reads, and removing tags without removing object bytes.
//! Also: reading and validating the packed `x-amz-tagging` header a `PutObject` or `CopyObject`
//! carries, and the byte form those tags are published in beside a new version.
//! NOT responsible for: bucket tags, version publication, or lifecycle action timing.
//! Upstream: the shared tagging validator and filesystem version authority. Downstream: production
//! object-tagging routes, object publication, and lifecycle tag-filter evaluation.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustfs_gateway::dto::{
    DeleteObjectTagging, DeleteObjectTaggingOutput, GetObjectTagging, GetObjectTaggingOutput, PutObjectTagging,
    PutObjectTaggingOutput, Tag, Tagging,
};
use rustfs_gateway::persistence::{parse_tagging_dto, serialize_tagging_dto};
use rustfs_gateway::{
    ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, ServiceBuilder, TagScope, parse_tagging_header, validate_tag_set,
};

use super::{FsBackend, storage_error};

pub(super) const TAGS_FILE: &str = "tags";

/// Reads and validates the packed `x-amz-tagging` header a write carries.
///
/// The header is the same tag set the `?tagging` subresource carries as a document, so it passes
/// the same object-scope validation before anything is written.
///
/// # Errors
///
/// The header grammar's refusals, and the object-scope tag-set refusals.
pub(super) fn tags_from_header(header: Option<&str>) -> Result<Vec<(String, String)>, HandlerError> {
    let pairs =
        parse_tagging_header(header).map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
    validate_tag_set(&pairs, TagScope::Object)
        .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
    Ok(pairs)
}

/// The persisted form of a tag set, identical to what `PutObjectTagging` writes.
pub(super) fn serialize_tags(pairs: &[(String, String)]) -> impl AsRef<[u8]> {
    serialize_tagging_dto(&Tagging {
        tag_set: pairs
            .iter()
            .map(|(key, value)| Tag {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    })
}

fn unsafe_tags() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_REQUEST, "the object tag path is not a safe regular file")
}

async fn read_tagging(directory: &Path) -> Result<Tagging, HandlerError> {
    let path = directory.join(TAGS_FILE);
    match tokio::fs::symlink_metadata(&path).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Tagging { tag_set: Vec::new() }),
        Err(_) => Err(storage_error()),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
            parse_tagging_dto(&bytes).map_err(|_| storage_error())
        }
        Ok(_) => Err(unsafe_tags()),
    }
}

pub(super) async fn read_persisted_tags(directory: &Path) -> Result<Vec<(String, String)>, HandlerError> {
    Ok(read_tagging(directory)
        .await?
        .tag_set
        .into_iter()
        .map(|tag| (tag.key, tag.value))
        .collect())
}

impl FsBackend {
    /// Registers persistent current and version-specific object tagging operations.
    #[must_use]
    pub fn register_tagging(self: &Arc<Self>, builder: ServiceBuilder) -> ServiceBuilder {
        builder
            .register::<rustfs_gateway::dto::DeleteBucketTagging, _>(Arc::clone(self))
            .register::<rustfs_gateway::dto::GetBucketTagging, _>(Arc::clone(self))
            .register::<rustfs_gateway::dto::PutBucketTagging, _>(Arc::clone(self))
            .register::<DeleteObjectTagging, _>(Arc::clone(self))
            .register::<GetObjectTagging, _>(Arc::clone(self))
            .register::<PutObjectTagging, _>(Arc::clone(self))
    }

    async fn write_tags(&self, directory: &Path, tagging: &Tagging) -> Result<(), HandlerError> {
        let destination = directory.join(TAGS_FILE);
        match tokio::fs::symlink_metadata(&destination).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(unsafe_tags()),
        }
        self.write_atomic(directory, &destination, &serialize_tagging_dto(tagging))
            .await
    }

    async fn delete_tags(&self, directory: &Path) -> Result<(), HandlerError> {
        let path = directory.join(TAGS_FILE);
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage_error()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|_| storage_error())
            }
            Ok(_) => Err(unsafe_tags()),
        }
    }
}

impl Handler<GetObjectTagging> for FsBackend {
    async fn call(&self, request: Req<GetObjectTagging>) -> HandlerResult<GetObjectTagging> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let target = self
            .object_tag_target(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let tagging = read_tagging(&target.directory).await?;
        Ok(Resp::new(GetObjectTaggingOutput {
            tag_set: tagging.tag_set,
            version_id: target.version_id,
        }))
    }
}

impl Handler<PutObjectTagging> for FsBackend {
    async fn call(&self, request: Req<PutObjectTagging>) -> HandlerResult<PutObjectTagging> {
        let input = request.into_input();
        let pairs = input
            .tagging
            .tag_set
            .iter()
            .map(|tag| (tag.key.clone(), tag.value.clone()))
            .collect::<Vec<_>>();
        validate_tag_set(&pairs, TagScope::Object)
            .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
        let _guard = self.version_lock.lock().await;
        let target = self
            .object_tag_target(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        self.write_tags(&target.directory, &input.tagging).await?;
        Ok(Resp::new(PutObjectTaggingOutput {
            version_id: target.version_id,
        }))
    }
}

impl Handler<DeleteObjectTagging> for FsBackend {
    async fn call(&self, request: Req<DeleteObjectTagging>) -> HandlerResult<DeleteObjectTagging> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let target = self
            .object_tag_target(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        self.delete_tags(&target.directory).await?;
        Ok(Resp::new(DeleteObjectTaggingOutput {
            version_id: target.version_id,
        }))
    }
}
