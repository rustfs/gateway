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
//! Responsible for: publishing ordinary and multipart object bytes into opaque/null versions,
//! preflighting legacy cleanup before null publication, storing delete markers, selecting current
//! or explicit versions, exposing the selected metadata directory to object subresources,
//! enumerating a deterministic version census, and keeping every member of a bucket's versioning
//! configuration — MinIO's excluded prefixes and folders applied to writes and deletes as legacy
//! RustFS applies them (rustfs/gateway#1078).
//! NOT responsible for: multipart part validation, lifecycle, copy, tag-document persistence,
//! ordinary listing, or the version listing itself (`version_listing`).
//! Upstream: the filesystem safety primitives and validated multipart assembly. Downstream:
//! production object, multipart-completion, and version-listing handlers.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use rustfs_gateway::dto::{
    DeleteObject, DeleteObjectOutput, GetBucketVersioning, GetBucketVersioningOutput, PutBucketVersioning,
    PutBucketVersioningOutput, Status, StorageClass,
};
use rustfs_gateway::{
    ETag, ErrorCode, Handler, HandlerError, HandlerErrorContext, HandlerResult, MissingObject, ObjectKey, Preconditions, Req,
    ResourceVisibility, Resp, Timestamp, validate_versioning,
};

use super::records::{
    ObjectAttributes, RecordKind, VersionRecord, decode_version_record, encode_version_record, validate_attributes,
};
use super::root_lock::RootVersionGuard;
use super::{FsBackend, no_such_key, storage_error};

pub(super) const STATUS_FILE: &str = "versioning-status";
pub(super) const SEQUENCE_FILE: &str = "version-sequence";
pub(super) const RECORD_FILE: &str = "record";
const BODY_FILE: &str = "body";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VersioningState {
    Never,
    Enabled,
    Suspended,
}

impl VersioningState {
    /// The state a write of a key publishes under: an excluded key of an enabled bucket is written
    /// as a suspended bucket's key is, as the null version (legacy RustFS's `put_opts`,
    /// `prefix_suspended`).
    const fn for_write(self, excluded: bool) -> Self {
        match (self, excluded) {
            (Self::Enabled, true) => Self::Suspended,
            (state, _) => state,
        }
    }

    /// The state a delete of a key's current version runs under: an excluded key of an enabled
    /// bucket is deleted as an unversioned bucket's key is, with no delete marker (legacy RustFS's
    /// `del_opts`, `delete_state`, which its lifecycle expiry uses too).
    const fn for_delete(self, excluded: bool) -> Self {
        match (self, excluded) {
            (Self::Enabled, true) => Self::Never,
            (state, _) => state,
        }
    }
}

#[derive(Clone)]
pub(super) struct CurrentObjectRecord {
    pub(super) key: String,
    pub(super) version_id: String,
    pub(super) sequence: u64,
    pub(super) modified: i64,
    pub(super) e_tag: String,
    pub(super) size: i64,
    pub(super) storage_class: StorageClass,
    pub(super) tags: Vec<(String, String)>,
}

pub(super) struct ObjectTagTarget {
    pub(super) directory: PathBuf,
    pub(super) version_id: Option<String>,
}

pub(super) struct PublishedObject {
    pub(super) size: i64,
    pub(super) version_id: Option<String>,
    pub(super) last_modified: Timestamp,
}

impl FsBackend {
    pub(super) fn reconcile_nulls_for_key_locked(
        &self,
        bucket: &str,
        key: &str,
        records: &mut Vec<VersionRecord>,
    ) -> Result<(), HandlerError> {
        let legacy = self.object_path(bucket, key);
        null_recovery::reconcile_null_records_for_key(records, key, &legacy, self.clock.now().unix_seconds())
    }

    pub(super) fn reconcile_all_nulls_locked(&self, bucket: &str, records: &mut Vec<VersionRecord>) -> Result<(), HandlerError> {
        null_recovery::reconcile_all_null_records(self, bucket, records, self.clock.now().unix_seconds())
    }

    /// Publishes one object's bytes and the attributes — user metadata and representation headers —
    /// that must outlive them.
    ///
    /// The attributes are validated **before** the version lock is taken and before any byte is
    /// written: a value this backend could not hand back on a later `GET` must fail the request,
    /// not become an object whose metadata quietly disappears.
    pub(super) async fn publish_object(
        &self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        e_tag: &ETag,
        attributes: &ObjectAttributes,
    ) -> Result<PublishedObject, HandlerError> {
        self.publish_object_if(bucket, key, bytes, e_tag, attributes, None).await
    }

    /// [`Self::publish_object`] under the request's write conditions (rustfs/gateway#808).
    ///
    /// The conditions are evaluated against the current representation **inside** the version
    /// lock, which is held until the new version is published: `If-None-Match: *` is how a client
    /// takes a lock, and a check made before the lock would let two writers both pass it.
    pub(super) async fn publish_object_if(
        &self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        e_tag: &ETag,
        attributes: &ObjectAttributes,
        conditions: Option<&Preconditions>,
    ) -> Result<PublishedObject, HandlerError> {
        validate_attributes(attributes)?;
        let guard = self.version_lock.lock().await?;
        let (_guard, _tombstone, published) = self
            .publish_object_if_locked(
                guard,
                PublishPlan {
                    bucket,
                    key,
                    bytes,
                    e_tag,
                    attributes,
                    conditions,
                    receipt: None,
                },
                None,
            )
            .await?;
        Ok(published)
    }

    /// Every key's current record, read under the version lock.
    pub(super) async fn current_object_records(&self, bucket: &str) -> Result<Vec<CurrentObjectRecord>, HandlerError> {
        let _guard = self.version_lock.lock().await?;
        let mut records = self.version_records(bucket).await?;
        self.reconcile_all_nulls_locked(bucket, &mut records)?;
        let mut current = BTreeMap::<String, VersionRecord>::new();
        for record in records {
            match current.get(&record.key) {
                Some(held) if held.sequence >= record.sequence => {}
                _ => {
                    current.insert(record.key.clone(), record);
                }
            }
        }
        let mut objects = Vec::new();
        for record in current
            .into_values()
            .filter(|record| matches!(record.kind, RecordKind::Object))
        {
            let tags = super::tagging::read_persisted_tags(&record.path).await?;
            objects.push(CurrentObjectRecord {
                key: record.key,
                version_id: record.version_id,
                sequence: record.sequence,
                modified: record.modified,
                e_tag: record.e_tag,
                size: record.size,
                storage_class: record.storage_class,
                tags,
            });
        }
        Ok(objects)
    }

    pub(super) async fn object_tag_target(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<ObjectTagTarget, HandlerError> {
        let state = self.versioning_state(bucket).await?;
        let mut records = self.version_records(bucket).await?;
        self.reconcile_nulls_for_key_locked(bucket, key, &mut records)?;
        let selected = version_id
            .and_then(|id| explicit_for_key(&records, key, id))
            .or_else(|| version_id.is_none().then(|| newest_for_key(&records, key)).flatten());
        let Some(record) = selected else {
            return Err(if version_id.is_some_and(|id| id != "null") {
                missing_version(key)
            } else {
                no_such_key(key)
            });
        };
        if matches!(record.kind, RecordKind::DeleteMarker) {
            return Err(delete_marker_error(record, key, version_id.is_some()));
        }
        Ok(ObjectTagTarget {
            directory: record.path.clone(),
            version_id: (!matches!(state, VersioningState::Never)).then(|| record.version_id.clone()),
        })
    }

    pub(super) async fn expire_current_if_unchanged(
        &self,
        bucket: &str,
        key: &str,
        observed_sequence: u64,
    ) -> Result<bool, HandlerError> {
        let guard = self.version_lock.lock().await?;
        let state = self.versioning_state(bucket).await?;
        let state = state.for_delete(self.excluded(bucket, key, state).await?);
        let mut records = self.version_records(bucket).await?;
        self.reconcile_nulls_for_key_locked(bucket, key, &mut records)?;
        if newest_for_key(&records, key)
            .is_none_or(|record| record.sequence != observed_sequence || !matches!(record.kind, RecordKind::Object))
        {
            return Ok(false);
        }
        self.delete_current_locked(guard, bucket, key, state, records).await?;
        Ok(true)
    }

    pub(super) async fn transition_current_if_unchanged(
        &self,
        bucket: &str,
        key: &str,
        observed_sequence: u64,
        storage_class: &StorageClass,
    ) -> Result<bool, HandlerError> {
        let _guard = self.version_lock.lock().await?;
        let mut records = self.version_records(bucket).await?;
        self.reconcile_nulls_for_key_locked(bucket, key, &mut records)?;
        let Some(record) = newest_for_key(&records, key) else {
            return Ok(false);
        };
        if record.sequence != observed_sequence || !matches!(record.kind, RecordKind::Object) {
            return Ok(false);
        }
        if record.storage_class.as_str() == storage_class.as_str() {
            return Ok(false);
        }
        let mut updated = record.clone();
        updated.storage_class = storage_class.clone();
        let encoded = encode_version_record(&updated);
        self.write_atomic(&updated.path, &updated.path.join(RECORD_FILE), encoded.as_bytes())
            .await?;
        Ok(true)
    }

    async fn delete_current_locked(
        &self,
        guard: RootVersionGuard,
        bucket: &str,
        key: &str,
        state: VersioningState,
        records: Vec<VersionRecord>,
    ) -> Result<Option<String>, HandlerError> {
        let now = self.clock.now().unix_seconds();
        if !matches!(state, VersioningState::Enabled) {
            super::lock_record::ensure_null_deletable(&records, key, now)?;
        }
        match state {
            VersioningState::Never => {
                let remove_paths: Vec<PathBuf> = records
                    .into_iter()
                    .filter(|record| record.key == key && record.version_id == "null")
                    .map(|record| record.path)
                    .collect();
                let legacy_object = self.preflight_legacy_object(bucket, key).await?;
                let (_guard, ()) = guard
                    .run_blocking(move || {
                        for path in remove_paths {
                            null_recovery::remove_version_dir_strict(&path)?;
                        }
                        if let Some(path) = legacy_object.as_deref() {
                            null_recovery::remove_legacy_object_sync(path)?;
                        }
                        Ok(())
                    })
                    .await?;
                Ok(None)
            }
            VersioningState::Enabled => {
                let staged = self
                    .stage_version(publish::StageVersion {
                        bucket,
                        key,
                        version_id: None,
                        body: None,
                        e_tag: None,
                        attributes: &ObjectAttributes::default(),
                        lock: None,
                        held: &records,
                        superseded_nulls: &[],
                        supersedes_legacy: false,
                        receipt: None,
                        report_version_id: true,
                    })
                    .await?;
                let version_id = staged.version_id.clone();
                let (_guard, _) = guard
                    .run_blocking(move || {
                        null_recovery::commit_staged_version(null_recovery::CommitStagedVersion {
                            temporary: staged.temporary,
                            destination: staged.destination,
                            temp_guard: staged.temp_guard,
                            tombstone_guard: None,
                            superseded_nulls: Vec::new(),
                            legacy_object: None,
                            now,
                        })
                    })
                    .await?;
                Ok(Some(version_id))
            }
            VersioningState::Suspended => {
                let legacy_object = self.preflight_legacy_object(bucket, key).await?;
                let superseded_nulls: Vec<&VersionRecord> = records
                    .iter()
                    .filter(|record| record.key == key && record.version_id == "null")
                    .collect();
                let staged = self
                    .stage_version(publish::StageVersion {
                        bucket,
                        key,
                        version_id: Some("null"),
                        body: None,
                        e_tag: None,
                        attributes: &ObjectAttributes::default(),
                        lock: None,
                        held: &records,
                        superseded_nulls: &superseded_nulls,
                        supersedes_legacy: legacy_object.is_some(),
                        receipt: None,
                        report_version_id: false,
                    })
                    .await?;
                let version_id = staged.version_id.clone();
                let superseded_paths = superseded_nulls
                    .into_iter()
                    .map(|record| (record.path.clone(), record.lock.clone()))
                    .collect();
                let (_guard, _) = guard
                    .run_blocking(move || {
                        null_recovery::commit_staged_version(null_recovery::CommitStagedVersion {
                            temporary: staged.temporary,
                            destination: staged.destination,
                            temp_guard: staged.temp_guard,
                            tombstone_guard: None,
                            superseded_nulls: superseded_paths,
                            legacy_object,
                            now,
                        })
                    })
                    .await?;
                Ok(Some(version_id))
            }
        }
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

    /// Fails a read closed when the bucket's versioning state cannot be read.
    ///
    /// The state itself decides nothing about a read — which version a `GET` selects is the record
    /// set's answer — but a status file this backend cannot decode means the bucket's lineage is
    /// unknown, and answering the current object anyway would report a guess as a fact.
    pub(super) async fn require_readable_versioning(&self, bucket: &str) -> Result<(), HandlerError> {
        self.versioning_state(bucket).await.map(|_state| ())
    }

    pub(super) async fn versioning_state_for_lock(&self, bucket: &str) -> Result<VersioningState, HandlerError> {
        self.versioning_state(bucket).await
    }

    /// Whether a read of `bucket` reports the `null` version id.
    ///
    /// A bucket that has ever been versioned reports `x-amz-version-id: null` for its null
    /// version, as `PutObject` already did for the write that made it; a bucket that never was
    /// carries no version id at all. The two answers came from different rules — the write from
    /// the state, the read from the record's id, which is `null` in both kinds of bucket — so a
    /// suspended bucket's `PUT` said `null` and its `GET` said nothing.
    pub(super) async fn reports_null_version(&self, bucket: &str) -> Result<bool, HandlerError> {
        Ok(!matches!(self.versioning_state(bucket).await?, VersioningState::Never))
    }

    pub(super) async fn version_records(&self, bucket: &str) -> Result<Vec<VersionRecord>, HandlerError> {
        self.require_bucket(bucket).await?;
        let versions = self.versions_path(bucket);
        let mut entries = tokio::fs::read_dir(&versions).await.map_err(|_| storage_error())?;
        let mut records = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { return Err(storage_error()) };
            if name.starts_with(".tmp-") {
                let file_type = entry.file_type().await.map_err(|_| storage_error())?;
                if !file_type.is_dir() || file_type.is_symlink() {
                    return Err(HandlerError::new(
                        ErrorCode::INVALID_REQUEST,
                        "the version path is not a safe record directory",
                    ));
                }
                // An interrupted staging directory left by a killed writer holds no committed
                // version; skip it instead of permanently failing every read on the bucket.
                continue;
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
        let record = decode_version_record(path, &encoded)?;
        if matches!(record.kind, RecordKind::Object) {
            let body = record.path.join(BODY_FILE);
            let body_metadata = tokio::fs::symlink_metadata(body).await.map_err(|_| storage_error())?;
            if !body_metadata.is_file() || body_metadata.file_type().is_symlink() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the version body is not a safe regular file",
                ));
            }
            if i64::try_from(body_metadata.len()).ok() != Some(record.size) {
                return Err(storage_error());
            }
        }
        Ok(record)
    }

    pub(super) async fn read_version_body(&self, record: &VersionRecord) -> Result<Vec<u8>, HandlerError> {
        tokio::fs::read(record.path.join(BODY_FILE))
            .await
            .map_err(|_| storage_error())
    }

    async fn preflight_legacy_object(&self, bucket: &str, key: &str) -> Result<Option<PathBuf>, HandlerError> {
        let path = self.object_path(bucket, key);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(Some(path)),
            Ok(_) => Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the object path is not a safe regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(storage_error()),
        }
    }
}

pub(super) fn missing_version(key: &str) -> HandlerError {
    match ObjectKey::new(key.to_owned()) {
        Ok(key) => HandlerErrorContext::missing_object_for(key, MissingObject::Version, ResourceVisibility::Visible).into(),
        Err(_) => storage_error(),
    }
}

pub(super) fn delete_marker_error(record: &VersionRecord, key: &str, explicit: bool) -> HandlerError {
    if explicit {
        return HandlerErrorContext::versioned_delete_marker(&record.version_id, record.modified)
            .map(Into::into)
            .unwrap_or_else(|_| storage_error());
    }
    let key = ObjectKey::new(key.to_owned()).ok();
    HandlerErrorContext::current_delete_marker(ResourceVisibility::Visible, key, &record.version_id, record.modified)
        .map(Into::into)
        .unwrap_or_else(|_| storage_error())
}

pub(super) fn newest_for_key<'a>(records: &'a [VersionRecord], key: &str) -> Option<&'a VersionRecord> {
    records
        .iter()
        .filter(|record| record.key == key)
        .max_by_key(|record| record.sequence)
}

pub(super) fn explicit_for_key<'a>(records: &'a [VersionRecord], key: &str, version_id: &str) -> Option<&'a VersionRecord> {
    records
        .iter()
        .filter(|record| record.key == key && record.version_id == version_id)
        .max_by_key(|record| record.sequence)
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
        let _guard = self.version_lock.lock().await?;
        if self.bucket_has_object_lock(input.bucket.as_str()).await? {
            if state == VersioningState::Suspended {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_BUCKET_STATE,
                    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                ));
            }
            if input.versioning_configuration.exclude_folders == Some(true)
                || !input.versioning_configuration.excluded_prefixes.is_empty()
            {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_BUCKET_STATE,
                    "An Object Lock configuration is present on this bucket, so versioning exclusions cannot be enabled.",
                ));
            }
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS stores `MfaDelete` with the rest of the
        // configuration and neither enforces it — a delete never needs an MFA token — nor returns
        // it from GetBucketVersioning (`rustfs/src/app/bucket_usecase.rs:2265-2270` at
        // rustfs/rustfs@e870a6d25). Kept: stored, never enforced or returned. The intended
        // behaviour is to refuse `MfaDelete` `Enabled` as unsupported, or to enforce and return it.
        self.set_versioning_configuration(input.bucket.as_str(), &input.versioning_configuration)
            .await?;
        self.set_versioning_state(input.bucket.as_str(), state).await?;
        Ok(Resp::new(PutBucketVersioningOutput::default()))
    }
}

impl Handler<GetBucketVersioning> for FsBackend {
    async fn call(&self, request: Req<GetBucketVersioning>) -> HandlerResult<GetBucketVersioning> {
        let _guard = self.version_lock.lock().await?;
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

impl FsBackend {
    /// Deletes one key, or one explicit version of it, under the bucket's versioning state.
    ///
    /// This is the one deletion both `DeleteObject` and every entry of a `DeleteObjects` batch run,
    /// so a key removed singly and a key removed in a batch cannot diverge in what they leave
    /// behind or report.
    pub(super) async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<DeleteObjectOutput, HandlerError> {
        self.delete_object_version_if(bucket, key, version_id, None, false).await
    }

    /// [`Self::delete_object_version`] under a delete's `If-Match`, judged inside the version lock
    /// and held until the delete is done, so a write racing it cannot change what was judged.
    async fn delete_object_version_if(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        condition: Option<&DeleteIfMatch>,
        bypass_governance: bool,
    ) -> Result<DeleteObjectOutput, HandlerError> {
        let guard = self.version_lock.lock().await?;
        let state = self.versioning_state(bucket).await?;
        let mut records = self.version_records(bucket).await?;
        self.reconcile_nulls_for_key_locked(bucket, key, &mut records)?;
        if let Some(version_id) = version_id {
            let record = explicit_for_key(&records, key, version_id);
            if let Some(condition) = condition {
                self.judge_named(condition, bucket, key, version_id, record).await?;
            }
            if let Some(record) = record {
                super::lock_record::ensure_deletable_with_bypass(
                    record.lock.as_ref(),
                    self.clock.now().unix_seconds(),
                    bypass_governance,
                )?;
                let delete_marker = matches!(record.kind, RecordKind::DeleteMarker);
                let path = record.path.clone();
                let removed_id = record.version_id.clone();
                let (_guard, ()) = guard
                    .run_blocking(move || null_recovery::remove_version_dir_strict(&path))
                    .await?;
                return Ok(DeleteObjectOutput {
                    delete_marker: Some(delete_marker),
                    version_id: Some(removed_id),
                    ..DeleteObjectOutput::default()
                });
            }
            if version_id == "null" {
                let legacy = self.preflight_legacy_object(bucket, key).await?;
                if let Some(path) = legacy {
                    let (_guard, ()) = guard
                        .run_blocking(move || null_recovery::remove_legacy_object_sync(&path))
                        .await?;
                }
            }
            return Ok(DeleteObjectOutput::default());
        }
        let state = state.for_delete(self.excluded(bucket, key, state).await?);
        if let Some(condition) = condition {
            self.judge_current(condition, bucket, key, state, &records).await?;
        }
        let marker = self.delete_current_locked(guard, bucket, key, state, records).await?;
        Ok(DeleteObjectOutput {
            delete_marker: marker.as_ref().map(|_| true),
            version_id: marker,
            ..DeleteObjectOutput::default()
        })
    }
}

impl Handler<DeleteObject> for FsBackend {
    async fn call(&self, request: Req<DeleteObject>) -> HandlerResult<DeleteObject> {
        let bypass =
            super::object_lock::authorized_governance_bypass(request.input().bypass_governance_retention, request.context());
        let input = request.input();
        let condition = self.delete_condition(input.if_match.as_deref());
        let output = self
            .delete_object_version_if(
                input.bucket.as_str(),
                input.key.as_str(),
                input.version_id.as_deref(),
                condition.as_ref(),
                bypass,
            )
            .await?;
        Ok(Resp::new(output))
    }
}

mod configuration;
mod delete_conditions;
mod lifecycle;
mod null_recovery;
mod publish;

use delete_conditions::DeleteIfMatch;

pub(super) use configuration::CONFIGURATION_FILE;
pub(super) use publish::PublishPlan;

#[cfg(test)]
mod shared_root_tests;
#[cfg(test)]
mod tests;
