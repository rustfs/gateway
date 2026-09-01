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

//! Persistent bucket versioning and version-aware object handlers.
//!
//! Responsible for: storing opaque versions and delete markers, selecting current or explicit
//! versions, and enumerating a deterministic version census.
//! NOT responsible for: multipart version publication, lifecycle, copy, tags, or ordinary listing.
//! Upstream: the filesystem safety primitives in the crate root. Downstream: production handlers.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use bytes::Bytes;
use rustfs_gateway::dto::{
    DeleteMarkerEntry, DeleteObject, DeleteObjectOutput, GetBucketVersioning, GetBucketVersioningOutput, GetObject,
    GetObjectOutput, HeadObject, HeadObjectOutput, ListObjectVersions, ListObjectVersionsOutput, ObjectVersion,
    PutBucketVersioning, PutBucketVersioningOutput, PutObject, PutObjectOutput, Status, StorageClass,
};
use rustfs_gateway::{
    ByteStream, ErrorCode, Handler, HandlerError, HandlerErrorContext, HandlerResult, MissingObject, ObjectKey, Req,
    ResourceVisibility, Resp, Timestamp, validate_versioning,
};
use sha2::{Digest as _, Sha256};

use super::{FsBackend, drain, etag, last_modified, storage_error};

pub(super) const STATUS_FILE: &str = "versioning-status";
pub(super) const SEQUENCE_FILE: &str = "version-sequence";
const RECORD_FILE: &str = "record";
const BODY_FILE: &str = "body";

#[derive(Clone, Copy)]
enum VersioningState {
    Never,
    Enabled,
    Suspended,
}

#[derive(Clone, Copy)]
enum RecordKind {
    Object,
    DeleteMarker,
}

#[derive(Clone)]
struct VersionRecord {
    path: PathBuf,
    sequence: u64,
    key: String,
    version_id: String,
    kind: RecordKind,
    modified: i64,
    e_tag: String,
    size: i64,
}

#[derive(Clone)]
pub(super) struct CurrentObjectRecord {
    pub(super) key: String,
    pub(super) version_id: String,
    pub(super) sequence: u64,
    pub(super) modified: i64,
    pub(super) e_tag: String,
    pub(super) size: i64,
}

impl FsBackend {
    pub(super) async fn current_object_records(&self, bucket: &str) -> Result<Vec<CurrentObjectRecord>, HandlerError> {
        let records = self.version_records(bucket).await?;
        let mut current = BTreeMap::<String, VersionRecord>::new();
        for record in records {
            match current.get(&record.key) {
                Some(held) if held.sequence >= record.sequence => {}
                _ => {
                    current.insert(record.key.clone(), record);
                }
            }
        }
        Ok(current
            .into_values()
            .filter(|record| matches!(record.kind, RecordKind::Object))
            .map(|record| CurrentObjectRecord {
                key: record.key,
                version_id: record.version_id,
                sequence: record.sequence,
                modified: record.modified,
                e_tag: record.e_tag,
                size: record.size,
            })
            .collect())
    }

    async fn versioning_state(&self, bucket: &str) -> Result<VersioningState, HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.bucket_path(bucket).join(STATUS_FILE);
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(VersioningState::Never),
            Err(_) => Err(storage_error()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                match tokio::fs::read_to_string(path).await.map_err(|_| storage_error())?.as_str() {
                    "Enabled\n" => Ok(VersioningState::Enabled),
                    "Suspended\n" => Ok(VersioningState::Suspended),
                    _ => Err(storage_error()),
                }
            }
            Ok(_) => Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the versioning status path is not a safe regular file",
            )),
        }
    }

    async fn set_versioning_state(&self, bucket: &str, state: VersioningState) -> Result<(), HandlerError> {
        let value = match state {
            VersioningState::Enabled => b"Enabled\n".as_slice(),
            VersioningState::Suspended => b"Suspended\n".as_slice(),
            VersioningState::Never => return Err(storage_error()),
        };
        self.write_atomic(&self.bucket_path(bucket), &self.bucket_path(bucket).join(STATUS_FILE), value)
            .await
    }

    async fn version_records(&self, bucket: &str) -> Result<Vec<VersionRecord>, HandlerError> {
        self.require_bucket(bucket).await?;
        let versions = self.versions_path(bucket);
        let mut entries = tokio::fs::read_dir(&versions).await.map_err(|_| storage_error())?;
        let mut records = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { return Err(storage_error()) };
            if name.starts_with(".tmp-") {
                return Err(storage_error());
            }
            let file_type = entry.file_type().await.map_err(|_| storage_error())?;
            if !file_type.is_dir() || file_type.is_symlink() || !name.starts_with("v-") {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the version path is not a safe record directory",
                ));
            }
            records.push(self.read_version_record(entry.path()).await?);
        }
        Ok(records)
    }

    async fn read_version_record(&self, path: PathBuf) -> Result<VersionRecord, HandlerError> {
        let record_path = path.join(RECORD_FILE);
        let metadata = tokio::fs::symlink_metadata(&record_path).await.map_err(|_| storage_error())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the version record is not a safe regular file",
            ));
        }
        let encoded = tokio::fs::read_to_string(record_path).await.map_err(|_| storage_error())?;
        let mut lines = encoded.lines();
        let sequence = lines
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(storage_error)?;
        let key = decode_record_text(lines.next()).ok_or_else(storage_error)?;
        let version_id = decode_record_text(lines.next()).ok_or_else(storage_error)?;
        let kind = match lines.next() {
            Some("object") => RecordKind::Object,
            Some("delete") => RecordKind::DeleteMarker,
            _ => return Err(storage_error()),
        };
        let modified = lines
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(storage_error)?;
        let e_tag = lines.next().map(ToOwned::to_owned).ok_or_else(storage_error)?;
        let size = lines
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(storage_error)?;
        if lines.next().is_some() || version_id.is_empty() {
            return Err(storage_error());
        }
        if matches!(kind, RecordKind::Object) {
            let body = path.join(BODY_FILE);
            let body_metadata = tokio::fs::symlink_metadata(body).await.map_err(|_| storage_error())?;
            if !body_metadata.is_file() || body_metadata.file_type().is_symlink() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the version body is not a safe regular file",
                ));
            }
            if i64::try_from(body_metadata.len()).ok() != Some(size) {
                return Err(storage_error());
            }
        }
        Ok(VersionRecord {
            path,
            sequence,
            key,
            version_id,
            kind,
            modified,
            e_tag,
            size,
        })
    }

    async fn publish_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<VersionRecord, HandlerError> {
        let held = self.version_records(bucket).await?;
        let sequence = self.next_version_sequence(bucket, &held).await?;
        let version_id = version_id.map_or_else(|| opaque_version_id(bucket, key, sequence), ToOwned::to_owned);
        let modified = self.clock.now().unix_seconds();
        let digest = Sha256::digest(format!("{sequence}\0{key}\0{version_id}").as_bytes());
        let versions = self.versions_path(bucket);
        let destination = versions.join(format!("v-{sequence:020}-{}", hex::encode(digest)));
        let temporary = versions.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        tokio::fs::create_dir(&temporary).await.map_err(|_| storage_error())?;
        let object_metadata = match body {
            Some(bytes) => Some((
                hex::encode(md5::Md5::digest(bytes)),
                i64::try_from(bytes.len()).map_err(|_| storage_error())?,
            )),
            None => None,
        };
        let result = async {
            let (kind, tag, size) = match (body, object_metadata) {
                (Some(bytes), Some((tag, size))) => {
                    tokio::fs::write(temporary.join(BODY_FILE), bytes).await?;
                    ("object", tag, size)
                }
                _ => ("delete", String::new(), 0),
            };
            let record = format!(
                "{sequence}\n{}\n{}\n{kind}\n{modified}\n{tag}\n{size}\n",
                hex::encode(key),
                hex::encode(&version_id)
            );
            tokio::fs::write(temporary.join(RECORD_FILE), record).await?;
            tokio::fs::rename(&temporary, &destination).await
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_dir_all(&temporary).await;
            return Err(storage_error());
        }
        self.read_version_record(destination).await
    }

    async fn next_version_sequence(&self, bucket: &str, held: &[VersionRecord]) -> Result<u64, HandlerError> {
        let path = self.bucket_path(bucket).join(SEQUENCE_FILE);
        let previous = match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => held.iter().map(|record| record.sequence).max().unwrap_or(0),
            Err(_) => return Err(storage_error()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => tokio::fs::read_to_string(&path)
                .await
                .map_err(|_| storage_error())?
                .strip_suffix('\n')
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(storage_error)?,
            Ok(_) => {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the version sequence path is not a safe regular file",
                ));
            }
        };
        let next = previous.checked_add(1).ok_or_else(storage_error)?;
        self.write_atomic(&self.bucket_path(bucket), &path, format!("{next}\n").as_bytes())
            .await?;
        Ok(next)
    }

    async fn read_version_body(&self, record: &VersionRecord) -> Result<Vec<u8>, HandlerError> {
        tokio::fs::read(record.path.join(BODY_FILE))
            .await
            .map_err(|_| storage_error())
    }

    async fn remove_null_versions(&self, records: &[VersionRecord], key: &str) -> Result<(), HandlerError> {
        for record in records
            .iter()
            .filter(|record| record.key == key && record.version_id == "null")
        {
            tokio::fs::remove_dir_all(&record.path).await.map_err(|_| storage_error())?;
        }
        Ok(())
    }

    async fn remove_legacy_object(&self, bucket: &str, key: &str) -> Result<(), HandlerError> {
        let path = self.object_path(bucket, key);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|_| storage_error())
            }
            Ok(_) => Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the object path is not a safe regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage_error()),
        }
    }
}

fn decode_record_text(value: Option<&str>) -> Option<String> {
    String::from_utf8(hex::decode(value?).ok()?).ok()
}

fn opaque_version_id(bucket: &str, key: &str, sequence: u64) -> String {
    hex::encode(Sha256::digest(format!("{bucket}\0{key}\0{sequence}").as_bytes()))
}

fn missing_version(key: &str) -> HandlerError {
    match ObjectKey::new(key.to_owned()) {
        Ok(key) => HandlerErrorContext::missing_object_for(key, MissingObject::Version, ResourceVisibility::Visible).into(),
        Err(_) => storage_error(),
    }
}

fn delete_marker_error(record: &VersionRecord, key: &str, explicit: bool) -> HandlerError {
    if explicit {
        return HandlerErrorContext::versioned_delete_marker(&record.version_id, record.modified)
            .map(Into::into)
            .unwrap_or_else(|_| storage_error());
    }
    let key = ObjectKey::new(key.to_owned()).ok();
    HandlerErrorContext::current_delete_marker(ResourceVisibility::Visible, key, record.modified)
        .map(Into::into)
        .unwrap_or_else(|_| storage_error())
}

fn newest_for_key<'a>(records: &'a [VersionRecord], key: &str) -> Option<&'a VersionRecord> {
    records
        .iter()
        .filter(|record| record.key == key)
        .max_by_key(|record| record.sequence)
}

fn explicit_for_key<'a>(records: &'a [VersionRecord], key: &str, version_id: &str) -> Option<&'a VersionRecord> {
    records
        .iter()
        .find(|record| record.key == key && record.version_id == version_id)
}

impl Handler<PutBucketVersioning> for FsBackend {
    async fn call(&self, request: Req<PutBucketVersioning>) -> HandlerResult<PutBucketVersioning> {
        let input = request.input();
        self.require_bucket(input.bucket.as_str()).await?;
        validate_versioning(&input.versioning_configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let state = match input.versioning_configuration.status.as_ref().map(Status::as_str) {
            Some("Enabled") => VersioningState::Enabled,
            Some("Suspended") => VersioningState::Suspended,
            _ => return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "versioning status is required")),
        };
        let _guard = self.version_lock.lock().await;
        self.set_versioning_state(input.bucket.as_str(), state).await?;
        Ok(Resp::new(PutBucketVersioningOutput::default()))
    }
}

impl Handler<GetBucketVersioning> for FsBackend {
    async fn call(&self, request: Req<GetBucketVersioning>) -> HandlerResult<GetBucketVersioning> {
        let _guard = self.version_lock.lock().await;
        let status = match self.versioning_state(request.input().bucket.as_str()).await? {
            VersioningState::Never => None,
            VersioningState::Enabled => Some(Status::ENABLED),
            VersioningState::Suspended => Some(Status::SUSPENDED),
        };
        Ok(Resp::new(GetBucketVersioningOutput {
            status,
            mfa_delete: None,
        }))
    }
}

impl Handler<PutObject> for FsBackend {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let input = request.into_input();
        let bytes = drain(input.body).await?;
        let _guard = self.version_lock.lock().await;
        let state = self.versioning_state(input.bucket.as_str()).await?;
        let existing = self.version_records(input.bucket.as_str()).await?;
        let version_id = if matches!(state, VersioningState::Enabled) {
            None
        } else {
            Some("null")
        };
        let record = self
            .publish_version(input.bucket.as_str(), input.key.as_str(), version_id, Some(&bytes))
            .await?;
        if version_id.is_some() {
            self.remove_null_versions(
                &existing
                    .into_iter()
                    .filter(|held| held.path != record.path)
                    .collect::<Vec<_>>(),
                input.key.as_str(),
            )
            .await?;
            self.remove_legacy_object(input.bucket.as_str(), input.key.as_str()).await?;
        }
        Ok(Resp::new(PutObjectOutput {
            size: Some(record.size),
            e_tag: etag(&bytes)?,
            version_id: (!matches!(state, VersioningState::Never)).then_some(record.version_id),
            ..PutObjectOutput::default()
        }))
    }
}

impl Handler<GetObject> for FsBackend {
    async fn call(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let _state = self.versioning_state(input.bucket.as_str()).await?;
        let records = self.version_records(input.bucket.as_str()).await?;
        let selected = input
            .version_id
            .as_ref()
            .and_then(|id| explicit_for_key(&records, input.key.as_str(), id.as_str()))
            .or_else(|| {
                input
                    .version_id
                    .is_none()
                    .then(|| newest_for_key(&records, input.key.as_str()))
                    .flatten()
            });
        if let Some(record) = selected {
            if matches!(record.kind, RecordKind::DeleteMarker) {
                return Err(delete_marker_error(record, input.key.as_str(), input.version_id.is_some()));
            }
            let bytes = self.read_version_body(record).await?;
            return Ok(Resp::new(GetObjectOutput {
                content_length: Some(record.size),
                e_tag: Some(rustfs_gateway::ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?),
                last_modified: Some(Timestamp::from_secs(record.modified)),
                version_id: (record.version_id != "null").then(|| record.version_id.clone()),
                body: Some(ByteStream::from_bytes(Bytes::from(bytes))),
                ..GetObjectOutput::default()
            }));
        }
        if input.version_id.as_ref().is_some_and(|id| id.as_str() != "null") {
            return Err(missing_version(input.key.as_str()));
        }
        let (bytes, metadata) = self.read_object(input.bucket.as_str(), input.key.as_str()).await?;
        Ok(Resp::new(GetObjectOutput {
            content_length: i64::try_from(bytes.len()).ok(),
            e_tag: Some(etag(&bytes)?),
            last_modified: Some(last_modified(&metadata)),
            body: Some(ByteStream::from_bytes(Bytes::from(bytes))),
            ..GetObjectOutput::default()
        }))
    }
}

impl Handler<HeadObject> for FsBackend {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let _state = self.versioning_state(input.bucket.as_str()).await?;
        let records = self.version_records(input.bucket.as_str()).await?;
        let selected = input
            .version_id
            .as_ref()
            .and_then(|id| explicit_for_key(&records, input.key.as_str(), id.as_str()))
            .or_else(|| {
                input
                    .version_id
                    .is_none()
                    .then(|| newest_for_key(&records, input.key.as_str()))
                    .flatten()
            });
        if let Some(record) = selected {
            if matches!(record.kind, RecordKind::DeleteMarker) {
                return Err(delete_marker_error(record, input.key.as_str(), input.version_id.is_some()));
            }
            return Ok(Resp::new(HeadObjectOutput {
                content_length: Some(record.size),
                e_tag: Some(rustfs_gateway::ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?),
                last_modified: Some(Timestamp::from_secs(record.modified)),
                version_id: (record.version_id != "null").then(|| record.version_id.clone()),
                ..HeadObjectOutput::default()
            }));
        }
        if input.version_id.as_ref().is_some_and(|id| id.as_str() != "null") {
            return Err(missing_version(input.key.as_str()));
        }
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
        let _guard = self.version_lock.lock().await;
        let state = self.versioning_state(input.bucket.as_str()).await?;
        let records = self.version_records(input.bucket.as_str()).await?;
        if let Some(version_id) = input.version_id.as_ref() {
            if let Some(record) = explicit_for_key(&records, input.key.as_str(), version_id.as_str()) {
                let delete_marker = matches!(record.kind, RecordKind::DeleteMarker);
                tokio::fs::remove_dir_all(&record.path).await.map_err(|_| storage_error())?;
                return Ok(Resp::new(DeleteObjectOutput {
                    delete_marker: Some(delete_marker),
                    version_id: Some(record.version_id.clone()),
                    ..DeleteObjectOutput::default()
                }));
            }
            if version_id.as_str() == "null" {
                self.remove_legacy_object(input.bucket.as_str(), input.key.as_str()).await?;
            }
            return Ok(Resp::new(DeleteObjectOutput::default()));
        }
        match state {
            VersioningState::Never => {
                self.remove_null_versions(&records, input.key.as_str()).await?;
                self.remove_legacy_object(input.bucket.as_str(), input.key.as_str()).await?;
                Ok(Resp::new(DeleteObjectOutput::default()))
            }
            VersioningState::Enabled => {
                let marker = self
                    .publish_version(input.bucket.as_str(), input.key.as_str(), None, None)
                    .await?;
                Ok(Resp::new(DeleteObjectOutput {
                    delete_marker: Some(true),
                    version_id: Some(marker.version_id),
                    ..DeleteObjectOutput::default()
                }))
            }
            VersioningState::Suspended => {
                let marker = self
                    .publish_version(input.bucket.as_str(), input.key.as_str(), Some("null"), None)
                    .await?;
                self.remove_null_versions(
                    &records
                        .into_iter()
                        .filter(|held| held.path != marker.path)
                        .collect::<Vec<_>>(),
                    input.key.as_str(),
                )
                .await?;
                self.remove_legacy_object(input.bucket.as_str(), input.key.as_str()).await?;
                Ok(Resp::new(DeleteObjectOutput {
                    delete_marker: Some(true),
                    version_id: Some(marker.version_id),
                    ..DeleteObjectOutput::default()
                }))
            }
        }
    }
}

impl Handler<ListObjectVersions> for FsBackend {
    async fn call(&self, request: Req<ListObjectVersions>) -> HandlerResult<ListObjectVersions> {
        let input = request.input();
        let _guard = self.version_lock.lock().await;
        let _state = self.versioning_state(input.bucket.as_str()).await?;
        let mut records = self.version_records(input.bucket.as_str()).await?;
        records.retain(|record| input.prefix.as_deref().is_none_or(|prefix| record.key.starts_with(prefix)));
        records.sort_by(|left, right| left.key.cmp(&right.key).then_with(|| right.sequence.cmp(&left.sequence)));
        let mut latest = BTreeMap::new();
        for record in &records {
            latest.entry(record.key.as_str()).or_insert(record.sequence);
        }
        let start = match input.key_marker.as_deref() {
            None => 0,
            Some(key) if input.version_id_marker.is_none() => records.partition_point(|record| record.key.as_str() <= key),
            Some(key) => {
                let marker = input
                    .version_id_marker
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap_or_default();
                records
                    .iter()
                    .position(|record| record.key == key && record.version_id == marker)
                    .map(|position| position + 1)
                    .ok_or_else(|| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "the version cursor does not exist"))?
            }
        };
        let max_keys = input.max_keys.unwrap_or(1000);
        let limit = usize::try_from(max_keys.max(0)).map_err(|_| storage_error())?;
        let selected = records.iter().skip(start).take(limit).collect::<Vec<_>>();
        let is_truncated = start.saturating_add(selected.len()) < records.len();
        let mut versions = Vec::new();
        let mut delete_markers = Vec::new();
        for record in &selected {
            let is_latest = latest.get(record.key.as_str()).copied() == Some(record.sequence);
            match record.kind {
                RecordKind::Object => versions.push(ObjectVersion {
                    key: ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?,
                    version_id: record.version_id.clone().into(),
                    is_latest,
                    last_modified: Timestamp::from_secs(record.modified),
                    e_tag: rustfs_gateway::ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?,
                    size: record.size,
                    storage_class: StorageClass::custom("STANDARD"),
                    ..ObjectVersion::default()
                }),
                RecordKind::DeleteMarker => delete_markers.push(DeleteMarkerEntry {
                    key: ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?,
                    version_id: record.version_id.clone().into(),
                    is_latest,
                    last_modified: Timestamp::from_secs(record.modified),
                    owner: None,
                }),
            }
        }
        let next = is_truncated.then(|| selected.last()).flatten();
        Ok(Resp::new(ListObjectVersionsOutput {
            name: input.bucket.clone(),
            prefix: input.prefix.clone().unwrap_or_default(),
            delimiter: input.delimiter.clone(),
            encoding_type: input.encoding_type.clone(),
            key_marker: input.key_marker.clone().unwrap_or_default(),
            version_id_marker: input.version_id_marker.clone().unwrap_or_default(),
            next_key_marker: next.map(|record| record.key.clone()),
            next_version_id_marker: next.map(|record| record.version_id.clone().into()),
            max_keys,
            is_truncated,
            versions,
            delete_markers,
            common_prefixes: Vec::new(),
            ..ListObjectVersionsOutput::default()
        }))
    }
}
