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

//! Lifecycle eligibility and removal of durable historical versions and orphan delete markers.
//!
//! Responsible for: history preflight and a fresh eligibility check under the version lock.
//! NOT responsible for: current-object expiration, policy decoding or rewriting legacy objects.
//! Upstream: the lifecycle sweep and durable version records; downstream: version directories.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway::dto::{LifecycleRule, Status};

use super::{FsBackend, HandlerError, RecordKind, VersionRecord, storage_error};
use crate::lifecycle::rule_selects_parts;
use crate::tagging::read_persisted_tags;

impl FsBackend {
    pub(crate) async fn expiring_version_candidates(
        &self,
        bucket: &str,
        rules: &[LifecycleRule],
        now: i64,
    ) -> Result<Vec<(String, u64)>, HandlerError> {
        let _guard = self.version_lock.lock().await;
        Ok(self
            .expiring_version_records(bucket, rules, now)
            .await?
            .into_iter()
            .map(|record| (record.key, record.sequence))
            .collect())
    }

    pub(crate) async fn expire_selected_versions(
        &self,
        bucket: &str,
        rules: &[LifecycleRule],
        candidates: &[(String, u64)],
        now: i64,
    ) -> Result<(), HandlerError> {
        let _guard = self.version_lock.lock().await;
        let selected: BTreeSet<_> = candidates.iter().map(|(key, sequence)| (key.as_str(), *sequence)).collect();
        // Re-read under the same lock held through deletion: a removed successor can make a
        // historical version current again, and a new write can stop a marker being orphaned.
        for record in self.expiring_version_records(bucket, rules, now).await? {
            if selected.contains(&(record.key.as_str(), record.sequence)) {
                tokio::fs::remove_dir_all(&record.path).await.map_err(|_| storage_error())?;
            }
        }
        Ok(())
    }

    /// Caller holds the version lock; this method performs no mutation.
    async fn expiring_version_records(
        &self,
        bucket: &str,
        rules: &[LifecycleRule],
        now: i64,
    ) -> Result<Vec<VersionRecord>, HandlerError> {
        self.require_readable_versioning(bucket).await?;
        let mut keys = BTreeMap::<String, Vec<VersionRecord>>::new();
        for record in self.version_records(bucket).await? {
            keys.entry(record.key.clone()).or_default().push(record);
        }
        let mut eligible = Vec::new();
        for (key, mut versions) in keys {
            versions.sort_by_key(|record| Reverse(record.sequence));
            if versions.windows(2).any(|pair| pair[0].sequence == pair[1].sequence) {
                return Err(storage_error());
            }
            // An old null-version file is retained history too. Removing its marker would
            // make those bytes visible again; unsafe legacy paths must fail preflight.
            let legacy = self.preflight_legacy_object(bucket, &key).await?.is_some();
            for (index, record) in versions.iter().enumerate() {
                let tags = read_persisted_tags(&record.path).await?;
                let orphan = index == 0 && versions.len() == 1 && matches!(record.kind, RecordKind::DeleteMarker) && !legacy;
                let due = rules.iter().any(|rule| {
                    if rule.status.as_str() != Status::ENABLED.as_str()
                        || !rule_selects_parts(rule, &record.key, record.size, &tags)
                    {
                        return false;
                    }
                    if orphan
                        && rule
                            .expiration
                            .as_ref()
                            .is_some_and(|expiration| expiration.expired_object_delete_marker == Some(true))
                    {
                        return true;
                    }
                    let Some(successor) = index.checked_sub(1).and_then(|previous| versions.get(previous)) else {
                        return false;
                    };
                    let Some(expiration) = rule.noncurrent_version_expiration.as_ref() else { return false };
                    if expiration
                        .newer_noncurrent_versions
                        .is_some_and(|keep| usize::try_from(keep).ok().is_none_or(|keep| index - 1 < keep))
                    {
                        return false;
                    }
                    expiration
                        .noncurrent_days
                        .and_then(|days| noncurrent_due(successor.modified, days, self.lifecycle_day_seconds))
                        .is_some_and(|due| now >= due)
                });
                if due {
                    eligible.push(record.clone());
                }
            }
        }
        Ok(eligible)
    }
}

/// Standard S3 uses the successor's creation time, rounded up to UTC midnight after real days.
/// Evidence: https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html
/// Debug days keep the existing short elapsed-time contract used by the reference SUT.
fn noncurrent_due(successor: i64, days: i32, day_seconds: i64) -> Option<i64> {
    if days <= 0 {
        return None;
    }
    let due = successor.checked_add(i64::from(days).checked_mul(day_seconds)?)?;
    if day_seconds == 86400 {
        let remainder = due.rem_euclid(day_seconds);
        if remainder != 0 {
            return due.checked_add(day_seconds - remainder);
        }
    }
    Some(due)
}
