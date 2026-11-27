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

//! Version directory staging, sequence allocation, and locked object publication.
//!
//! Responsible for: staging `.tmp-*` version directories with body, tags, durable `supersedes-null`
//! cleanup intent, and best-effort multipart `completion` receipts before atomic rename; committing
//! staged versions and retiring superseded nulls inside `RootVersionGuard::run_blocking`.
//! NOT responsible for: version reading (`reads`), listing (`version_listing`), or delete handlers
//! (`super`).
//! Upstream: `super` (`versioning`) and `super::super::completion`. Downstream: `super::null_recovery`,
//! `super::super::completion_replay`, and `super::super::staging`.

use std::io;
use std::path::PathBuf;

use rustfs_gateway::dto::StorageClass;
use rustfs_gateway::{ETag, ErrorCode, HandlerError, Preconditions, Timestamp};
use sha2::{Digest as _, Sha256};

use super::super::completion_replay::{CompletionReceiptSpec, write_staged_completion_receipt};
use super::super::conditions::guard_write;
use super::super::reads::Selected;
use super::super::records::{ObjectAttributes, RecordKind, VersionRecord, encode_version_record, validate_attributes};
use super::super::root_lock::RootVersionGuard;
use super::super::staging::{CompletionTombstoneGuard, TempDirGuard};
use super::super::tagging::{TAGS_FILE, serialize_tags};
use super::super::{FsBackend, storage_error};
use super::{BODY_FILE, PublishedObject, RECORD_FILE, SEQUENCE_FILE, VersioningState, null_recovery};

/// Parameters for publishing one object version under an already-held shared-root lock.
pub(crate) struct PublishPlan<'a> {
    pub(crate) bucket: &'a str,
    pub(crate) key: &'a str,
    pub(crate) bytes: &'a [u8],
    pub(crate) e_tag: &'a ETag,
    pub(crate) attributes: &'a ObjectAttributes,
    pub(crate) conditions: Option<&'a Preconditions>,
    pub(crate) receipt: Option<&'a CompletionReceiptSpec>,
}

/// Staged version directory ready for atomic rename commit inside `RootVersionGuard::run_blocking`.
pub(super) struct StagedVersion {
    pub(super) temporary: PathBuf,
    pub(super) destination: PathBuf,
    pub(super) temp_guard: TempDirGuard,
    pub(super) version_id: String,
    pub(super) size: i64,
    pub(super) modified: i64,
}

/// Parameters for staging a new object or delete-marker version directory.
pub(super) struct StageVersion<'a> {
    pub(super) bucket: &'a str,
    pub(super) key: &'a str,
    pub(super) version_id: Option<&'a str>,
    pub(super) body: Option<&'a [u8]>,
    pub(super) e_tag: Option<&'a ETag>,
    pub(super) attributes: &'a ObjectAttributes,
    pub(super) held: &'a [VersionRecord],
    pub(super) superseded_nulls: &'a [&'a VersionRecord],
    pub(super) supersedes_legacy: bool,
    pub(super) receipt: Option<&'a CompletionReceiptSpec>,
    pub(super) report_version_id: bool,
}

impl FsBackend {
    /// Runs object publication while the caller already owns the shared-root version lock (and,
    /// for multipart completion, its `.complete-*` tombstone guard).
    pub(crate) async fn publish_object_if_locked(
        &self,
        guard: RootVersionGuard,
        plan: PublishPlan<'_>,
        tombstone_guard: Option<CompletionTombstoneGuard>,
    ) -> Result<(RootVersionGuard, Option<CompletionTombstoneGuard>, PublishedObject), HandlerError> {
        validate_attributes(plan.attributes)?;
        if let Some(conditions) = plan.conditions {
            match self.select_locked(plan.bucket, plan.key, None).await? {
                Selected::Found(current) => guard_write(Some(&current), conditions)?,
                Selected::Absent(_) => guard_write(None, conditions)?,
            }
        }
        let state = self.versioning_state(plan.bucket).await?;
        let state = state.for_write(self.excluded(plan.bucket, plan.key, state).await?);
        let mut existing = self.version_records(plan.bucket).await?;
        let now = self.clock.now().unix_seconds();
        self.reconcile_nulls_for_key_locked(plan.bucket, plan.key, &mut existing)?;
        let version_id = if matches!(state, VersioningState::Enabled) {
            None
        } else {
            Some("null")
        };
        if version_id.is_some() {
            super::super::lock_record::ensure_null_deletable(&existing, plan.key, now)?;
        }
        let legacy_object = if version_id.is_some() {
            self.preflight_legacy_object(plan.bucket, plan.key).await?
        } else {
            None
        };
        let superseded_nulls: Vec<&VersionRecord> = if version_id.is_some() {
            existing
                .iter()
                .filter(|record| record.key == plan.key && record.version_id == "null")
                .collect()
        } else {
            Vec::new()
        };
        let staged = self
            .stage_version(StageVersion {
                bucket: plan.bucket,
                key: plan.key,
                version_id,
                body: Some(plan.bytes),
                e_tag: Some(plan.e_tag),
                attributes: plan.attributes,
                held: &existing,
                superseded_nulls: &superseded_nulls,
                supersedes_legacy: legacy_object.is_some(),
                receipt: plan.receipt,
                report_version_id: matches!(state, VersioningState::Enabled),
            })
            .await?;
        let superseded_paths = superseded_nulls
            .into_iter()
            .map(|record| (record.path.clone(), record.lock.clone()))
            .collect();
        let destination = staged.destination.clone();
        let (guard, tombstone_guard) = guard
            .run_blocking(move || {
                null_recovery::commit_staged_version(null_recovery::CommitStagedVersion {
                    temporary: staged.temporary,
                    destination,
                    temp_guard: staged.temp_guard,
                    tombstone_guard,
                    superseded_nulls: superseded_paths,
                    legacy_object,
                    now,
                })
            })
            .await?;
        let published = PublishedObject {
            size: staged.size,
            // Reported only while versioning is enabled, as RustFS reports it: a suspended bucket's
            // write is the null version and answers no id (rustfs/gateway#1003).
            version_id: matches!(state, VersioningState::Enabled).then_some(staged.version_id),
            last_modified: Timestamp::from_secs(staged.modified),
        };
        Ok((guard, tombstone_guard, published))
    }

    #[cfg(test)]
    pub(super) async fn publish_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        body: Option<&[u8]>,
        e_tag: Option<&ETag>,
        attributes: &ObjectAttributes,
    ) -> Result<VersionRecord, HandlerError> {
        let held = self.version_records(bucket).await?;
        let mut staged = self
            .stage_version(StageVersion {
                bucket,
                key,
                version_id,
                body,
                e_tag,
                attributes,
                held: &held,
                superseded_nulls: &[],
                supersedes_legacy: false,
                receipt: None,
                report_version_id: false,
            })
            .await?;
        std::fs::rename(&staged.temporary, &staged.destination).map_err(|_| storage_error())?;
        staged.temp_guard.disarm();
        self.read_version_record(staged.destination).await
    }

    pub(super) async fn stage_version(&self, stage: StageVersion<'_>) -> Result<StagedVersion, HandlerError> {
        let sequence = self.next_version_sequence(stage.bucket, stage.held).await?;
        let version_id = stage
            .version_id
            .map_or_else(|| opaque_version_id(stage.bucket, stage.key, sequence), ToOwned::to_owned);
        let modified = self.clock.now().unix_seconds();
        let digest = Sha256::digest(format!("{sequence}\0{}\0{version_id}", stage.key).as_bytes());
        let versions = self.versions_path(stage.bucket);
        let destination = versions.join(format!("v-{sequence:020}-{}", hex::encode(digest)));
        let temporary = versions.join(format!(".tmp-{}-{}", std::process::id(), super::super::staging::next_temporary_id()));
        let temp_guard = TempDirGuard::create(temporary.clone())?;
        let object_metadata = match (stage.body, stage.e_tag) {
            (Some(bytes), Some(e_tag)) => {
                Some((e_tag.opaque_tag().to_owned(), i64::try_from(bytes.len()).map_err(|_| storage_error())?))
            }
            (None, None) => None,
            _ => return Err(storage_error()),
        };
        let (tag, size) = match (stage.body, object_metadata) {
            (Some(bytes), Some((tag, size))) => {
                // Open synchronously and flush to completion before renaming so neither cancellation
                // cleanup nor an immediate post-rename read can observe an in-flight write.
                super::super::staging::create_and_write_file(&temporary.join(BODY_FILE), bytes).await?;
                (tag, size)
            }
            _ => (String::new(), 0),
        };
        // Written into the temporary directory, so the tags a write carried become visible in
        // the same rename as the version itself — never a version first and its tags later.
        if !stage.attributes.tags.is_empty() {
            super::super::staging::create_and_write_file(
                &temporary.join(TAGS_FILE),
                serialize_tags(&stage.attributes.tags).as_ref(),
            )
            .await?;
        }
        null_recovery::write_supersedes_null_intent(&temporary, stage.superseded_nulls, stage.supersedes_legacy)?;
        if let Some(receipt) = stage.receipt {
            #[cfg(test)]
            super::shared_root_tests::maybe_obstruct_completion_receipt(&temporary);
            let reported = stage.report_version_id.then_some(version_id.as_str());
            write_staged_completion_receipt(&temporary, receipt, reported);
        }
        let record = encode_version_record(&VersionRecord {
            path: destination.clone(),
            sequence,
            key: stage.key.to_owned(),
            version_id: version_id.clone(),
            kind: if stage.body.is_some() {
                RecordKind::Object
            } else {
                RecordKind::DeleteMarker
            },
            modified,
            e_tag: tag,
            size,
            storage_class: stage.attributes.storage_class.clone().unwrap_or(StorageClass::STANDARD),
            metadata: stage.attributes.metadata.clone(),
            headers: stage.attributes.headers.clone(),
            checksum: stage.attributes.checksum,
            part_lengths: stage.attributes.part_lengths.clone(),
            part_metadata: stage.attributes.part_metadata.clone(),
            lock: stage.attributes.lock.clone(),
        });
        #[cfg(test)]
        {
            super::tests::block_version_record_write(&temporary);
            super::super::staging::test_hooks::maybe_pause("publish_version").await;
        }
        super::super::staging::create_and_write_file(&temporary.join(RECORD_FILE), record.as_bytes()).await?;
        Ok(StagedVersion {
            temporary,
            destination,
            temp_guard,
            version_id,
            size,
            modified,
        })
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
}

fn opaque_version_id(bucket: &str, key: &str, sequence: u64) -> String {
    hex::encode(Sha256::digest(format!("{bucket}\0{key}\0{sequence}").as_bytes()))
}
