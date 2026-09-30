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

//! Persistent bucket lifecycle configuration and action selection.
//!
//! Responsible for: validating one complete lifecycle document, atomically replacing its durable
//! record, serving or deleting it after restart, selecting objects for lifecycle actions, and the
//! `x-amz-expiration` a write or read of a current version answers.
//! NOT responsible for: mutating transition state, tag persistence, or scheduling repeated sweeps.
//! Upstream: generated lifecycle DTOs and the historical persistence codec. Downstream: production handlers,
//! transition execution, and the lifecycle scheduler.

use std::io;

use rustfs_gateway::dto::{
    AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, DelMarkerExpiration, DeleteBucketLifecycle,
    DeleteBucketLifecycleOutput, GetBucketLifecycleConfiguration, GetBucketLifecycleConfigurationOutput, LifecycleExpiration,
    LifecycleRule, LifecycleRuleAndOperator, LifecycleRuleFilter, NoncurrentVersionExpiration, NoncurrentVersionTransition,
    PutBucketLifecycleConfiguration, PutBucketLifecycleConfigurationOutput, Status, StorageClass, Tag, Transition,
    TransitionDefaultMinimumObjectSize,
};
use rustfs_gateway::persistence::{
    PersistedAbortIncompleteMultipartUpload, PersistedDelMarkerExpiration, PersistedLifecycleAnd,
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
    PersistedLifecycleTag, PersistedNoncurrentVersionExpiration, PersistedNoncurrentVersionTransition, PersistedTransition,
    parse_lifecycle, serialize_lifecycle,
};
use rustfs_gateway::{
    ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, Timestamp, TimestampFormat, validate_lifecycle,
};

use super::{FsBackend, storage_error};
use crate::versioning::CurrentObjectRecord;

pub(super) const RECORD_FILE: &str = "lifecycle";
const RECORD_MAGIC: &[u8] = b"FSLC1\n";

pub(super) struct LifecycleRecord {
    pub(super) configuration: BucketLifecycleConfiguration,
    pub(super) minimum_object_size: Option<TransitionDefaultMinimumObjectSize>,
}

impl FsBackend {
    fn lifecycle_path(&self, bucket: &str) -> std::path::PathBuf {
        self.bucket_path(bucket).join(RECORD_FILE)
    }

    async fn read_lifecycle(&self, bucket: &str) -> Result<LifecycleRecord, HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.lifecycle_path(bucket);
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => return Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(no_such_lifecycle()),
            Err(_) => return Err(storage_error()),
        };
        if !metadata.is_file() {
            return Err(unsafe_record());
        }
        let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
        decode_record(&bytes).map_err(|_| storage_error())
    }

    async fn write_lifecycle(&self, bucket: &str, record: &LifecycleRecord) -> Result<(), HandlerError> {
        self.require_bucket(bucket).await?;
        let destination = self.lifecycle_path(bucket);
        match tokio::fs::symlink_metadata(&destination).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        let bytes = encode_record(record).map_err(|_| storage_error())?;
        self.write_atomic(&self.bucket_path(bucket), &destination, &bytes).await
    }

    async fn delete_lifecycle(&self, bucket: &str) -> Result<(), HandlerError> {
        self.require_bucket(bucket).await?;
        let path = self.lifecycle_path(bucket);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|_| storage_error())
            }
            Ok(_) => Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage_error()),
        }
    }

    pub(super) async fn lifecycle_buckets(&self) -> Result<Vec<String>, HandlerError> {
        let mut entries = tokio::fs::read_dir(&self.root).await.map_err(|_| storage_error())?;
        let mut buckets = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(storage_error)?;
            let encoded = name.strip_prefix("b-").ok_or_else(storage_error)?;
            let bucket = String::from_utf8(hex::decode(encoded).map_err(|_| storage_error())?).map_err(|_| storage_error())?;
            let file_type = entry.file_type().await.map_err(|_| storage_error())?;
            if !file_type.is_dir() || file_type.is_symlink() || self.bucket_path(&bucket) != entry.path() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the lifecycle bucket path is not a safe directory",
                ));
            }
            buckets.push(bucket);
        }
        buckets.sort();
        Ok(buckets)
    }

    pub(super) async fn optional_lifecycle(&self, bucket: &str) -> Result<Option<LifecycleRecord>, HandlerError> {
        let path = self.lifecycle_path(bucket);
        match tokio::fs::symlink_metadata(path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(storage_error()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                self.read_lifecycle(bucket).await.map(Some)
            }
            Ok(_) => Err(unsafe_record()),
        }
    }

    /// Runs one lifecycle-expiration sweep and returns the number of current objects expired.
    ///
    /// Every bucket policy, current-object record, and persisted tag set is validated before the
    /// first deletion. Tag selectors consume the same per-version authority as object-tagging
    /// handlers. Version-enabled buckets receive a delete marker, while never-versioned and
    /// suspended buckets apply their existing current-object deletion semantics.
    ///
    /// # Errors
    ///
    /// Returns a handler error without deleting anything when preflight encounters corrupt or
    /// unsafe bucket, lifecycle, or version authority.
    pub async fn expire_lifecycle_once(&self) -> Result<usize, HandlerError> {
        let now = self.clock.now().unix_seconds();
        let mut selected = Vec::new();
        for bucket in self.lifecycle_buckets().await? {
            let Some(record) = self.optional_lifecycle(&bucket).await? else {
                continue;
            };
            for object in self.current_object_records(&bucket).await? {
                if record
                    .configuration
                    .rules
                    .iter()
                    .any(|rule| rule_expires(rule, &object, now, self.lifecycle_day_seconds))
                {
                    selected.push((bucket.clone(), object.key.clone(), object.sequence));
                }
            }
        }

        let mut expired = 0;
        for (bucket, key, sequence) in selected {
            if self.expire_current_if_unchanged(&bucket, &key, sequence).await? {
                expired += 1;
            }
        }
        Ok(expired)
    }
}

fn rule_expires(rule: &LifecycleRule, object: &CurrentObjectRecord, now: i64, lifecycle_day_seconds: i64) -> bool {
    if rule.status.as_str() != Status::ENABLED.as_str() || !rule_selects(rule, object) {
        return false;
    }
    let Some(expiration) = rule.expiration.as_ref() else {
        return false;
    };
    let date_elapsed = expiration.date.as_ref().is_some_and(|date| now >= date.secs());
    let days_elapsed = expiration.days.is_some_and(|days| {
        let Some(required_age) = i64::from(days).checked_mul(lifecycle_day_seconds) else {
            return false;
        };
        now.checked_sub(object.modified).is_some_and(|age| age >= required_age)
    });
    date_elapsed || days_elapsed
}

pub(super) fn rule_selects(rule: &LifecycleRule, object: &CurrentObjectRecord) -> bool {
    rule_selects_parts(rule, &object.key, object.size, &object.tags)
}

/// [`rule_selects`] over the three facts it reads, for a caller that holds no census record.
fn rule_selects_parts(rule: &LifecycleRule, key: &str, size: i64, tags: &[(String, String)]) -> bool {
    if rule.prefix.as_deref().is_some_and(|prefix| !key.starts_with(prefix)) {
        return false;
    }
    let Some(filter) = rule.filter.as_ref() else {
        return true;
    };
    if filter
        .tag
        .as_ref()
        .is_some_and(|required| !tag_matches(tags, required.key.as_str(), &required.value))
        || filter.prefix.as_deref().is_some_and(|prefix| !key.starts_with(prefix))
        || filter.object_size_greater_than.is_some_and(|minimum| size <= minimum)
        || filter.object_size_less_than.is_some_and(|maximum| size >= maximum)
    {
        return false;
    }
    let Some(and) = filter.and.as_ref() else {
        return true;
    };
    and.tags
        .iter()
        .all(|required| tag_matches(tags, required.key.as_str(), &required.value))
        && and.prefix.as_deref().is_none_or(|prefix| key.starts_with(prefix))
        && and.object_size_greater_than.is_none_or(|minimum| size > minimum)
        && and.object_size_less_than.is_none_or(|maximum| size < maximum)
}

/// A real day: the unit `x-amz-expiration` counts `Days` in, whatever the debug interval.
///
/// The debug interval shortens a lifecycle day for the sweep alone. Legacy RustFS scales the
/// answered date too when its own debug day (`RUSTFS_ILM_DEBUG_DAY_SECS`) is set, and answers real
/// days when it is not (`expected_expiry_time`, `crates/lifecycle/src/core.rs:1069-1105` on
/// rustfs/rustfs 3268c42e00); the s3-tests helper measures the answer in real days.
const ANSWERED_DAY_SECONDS: i64 = 24 * 60 * 60;

/// What a rule is judged against when a response predicts a current version's expiration.
pub(super) struct ExpiringObject<'a> {
    pub(super) key: &'a str,
    pub(super) size: i64,
    pub(super) tags: &'a [(String, String)],
    /// When the version was written, in Unix seconds.
    pub(super) modified: i64,
}

impl FsBackend {
    /// The `x-amz-expiration` a `PutObject`, `HeadObject` or `GetObject` answers for the current
    /// version `object` of `bucket`, as legacy RustFS predicts it (`predict_expiration`,
    /// `crates/lifecycle/src/core.rs:654-701` on rustfs/rustfs 3268c42e00): of the enabled rules
    /// selecting it that expire current objects, the one due first — a `Date` as written, `Days`
    /// after the write rounded up to the next UTC midnight — named with its date and id, the
    /// earlier rule on a tie. A rule that expires only delete markers or noncurrent versions is
    /// not one of them.
    ///
    /// Advisory, as legacy RustFS's is: a configuration that cannot be read answers no header,
    /// never a failure of a write that has already happened.
    ///
    /// Legacy-compat (rustfs/backlog#2684): legacy RustFS answers the header on `PutObject`,
    /// `HeadObject` and `GetObject` only (`rustfs/src/app/object/put.rs:1365`, `head.rs:469`,
    /// `get.rs:3724` on rustfs/rustfs 3268c42e00; measured on `528a36814`); its `CopyObject` and
    /// `CompleteMultipartUpload` responses carry none, though the AWS model declares it on both.
    /// Kept: those two answer nothing here either. Intended: answer the written object's expiration
    /// on them too.
    pub(super) async fn expiration_header(&self, bucket: &str, object: &ExpiringObject<'_>) -> Option<String> {
        let record = self.optional_lifecycle(bucket).await.ok()??;
        let mut earliest: Option<(i64, &LifecycleRule)> = None;
        for rule in &record.configuration.rules {
            if rule.status.as_str() != Status::ENABLED.as_str() || !rule_selects_parts(rule, object.key, object.size, object.tags)
            {
                continue;
            }
            let Some(expiration) = rule.expiration.as_ref() else {
                continue;
            };
            let due = match (expiration.date.as_ref(), expiration.days) {
                (Some(date), _) => date.secs(),
                (None, Some(days)) => answered_expiry(object.modified, days),
                // A rule that expires only delete markers names neither.
                (None, None) => continue,
            };
            if earliest.is_none_or(|(held, _)| due < held) {
                earliest = Some((due, rule));
            }
        }
        let (due, rule) = earliest?;
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a due time at the epoch as no
        // expiration (`build_put_object_expiration_header`, `rustfs/src/app/object/shared.rs:665-681`
        // on rustfs/rustfs 3268c42e00), so a rule dated 1970-01-01 answers nothing while one dated
        // 2000-01-01 answers its date (measured on `528a36814`). The rule is valid and already due.
        // Intended: answer its date like any other.
        if due == 0 {
            return None;
        }
        let id = rule.id.as_deref().filter(|id| !id.is_empty())?;
        let date = Timestamp::from_secs(due).render(TimestampFormat::HttpDate).ok()?;
        Some(format!("expiry-date=\"{date}\", rule-id=\"{id}\""))
    }
}

/// `days` real days after `modified`, rounded up to the next UTC midnight.
fn answered_expiry(modified: i64, days: i32) -> i64 {
    let due = modified.saturating_add(i64::from(days).saturating_mul(ANSWERED_DAY_SECONDS));
    match due.rem_euclid(ANSWERED_DAY_SECONDS) {
        0 => due,
        remainder => due.saturating_add(ANSWERED_DAY_SECONDS - remainder),
    }
}

fn tag_matches(tags: &[(String, String)], key: &str, value: &str) -> bool {
    tags.iter()
        .any(|(held_key, held_value)| held_key == key && held_value == value)
}

impl Handler<GetBucketLifecycleConfiguration> for FsBackend {
    async fn call(&self, request: Req<GetBucketLifecycleConfiguration>) -> HandlerResult<GetBucketLifecycleConfiguration> {
        let record = self.read_lifecycle(request.input().bucket.as_str()).await?;
        Ok(Resp::new(GetBucketLifecycleConfigurationOutput {
            rules: record.configuration.rules,
            transition_default_minimum_object_size: record.minimum_object_size,
        }))
    }
}

impl Handler<PutBucketLifecycleConfiguration> for FsBackend {
    async fn call(&self, request: Req<PutBucketLifecycleConfiguration>) -> HandlerResult<PutBucketLifecycleConfiguration> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let Some(mut configuration) = input.lifecycle_configuration else {
            return Err(HandlerError::new(ErrorCode::MALFORMED_XML, "the request carries no lifecycle document"));
        };
        validate_lifecycle(&configuration).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        rustfs_write_rules(&mut configuration)?;
        let record = LifecycleRecord {
            configuration,
            minimum_object_size: input.transition_default_minimum_object_size.clone(),
        };
        self.write_lifecycle(input.bucket.as_str(), &record).await?;
        Ok(Resp::new(PutBucketLifecycleConfigurationOutput {
            transition_default_minimum_object_size: input.transition_default_minimum_object_size,
        }))
    }
}

/// RustFS's own write rules on top of the shared contract (`execute_put_bucket_lifecycle_configuration`
/// in `rustfs/src/app/bucket_usecase.rs`, rustfs/gateway#999): a rule without `ID` is given
/// `rule-<index>`, suffixed `-<n>` past an id another rule carries, and a `Status` other than
/// exactly `Enabled` or `Disabled` is `MalformedXML`. The shared contract stays lenient about
/// `Status` for documents already stored (`q-lc-0014`); this is RustFS's write path only.
fn rustfs_write_rules(configuration: &mut BucketLifecycleConfiguration) -> Result<(), HandlerError> {
    let mut taken: std::collections::HashSet<String> = configuration.rules.iter().filter_map(|rule| rule.id.clone()).collect();
    for (index, rule) in configuration.rules.iter_mut().enumerate() {
        if rule.id.is_none() {
            let mut suffix = 0usize;
            let mut generated = format!("rule-{index}");
            while taken.contains(&generated) {
                suffix += 1;
                generated = format!("rule-{index}-{suffix}");
            }
            taken.insert(generated.clone());
            rule.id = Some(generated);
        }
    }
    if configuration
        .rules
        .iter()
        .any(|rule| rule.status.as_str() != Status::ENABLED.as_str() && rule.status.as_str() != Status::DISABLED.as_str())
    {
        return Err(HandlerError::new(
            ErrorCode::MALFORMED_XML,
            "Malformed XML: Rule status must be either Enabled or Disabled",
        ));
    }
    Ok(())
}

impl Handler<DeleteBucketLifecycle> for FsBackend {
    async fn call(&self, request: Req<DeleteBucketLifecycle>) -> HandlerResult<DeleteBucketLifecycle> {
        self.delete_lifecycle(request.input().bucket.as_str()).await?;
        Ok(Resp::new(DeleteBucketLifecycleOutput::default()))
    }
}

fn encode_record(record: &LifecycleRecord) -> Result<Vec<u8>, ()> {
    let persisted = to_persisted(&record.configuration)?;
    let document = serialize_lifecycle(&persisted).map_err(|_| ())?;
    let minimum = record
        .minimum_object_size
        .as_ref()
        .map_or_else(|| "-".to_owned(), |value| hex::encode(value.as_str()));
    let mut bytes = Vec::with_capacity(RECORD_MAGIC.len() + minimum.len() + document.len() + 1);
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(minimum.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&document);
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<LifecycleRecord, ()> {
    let bytes = bytes.strip_prefix(RECORD_MAGIC).ok_or(())?;
    let newline = bytes.iter().position(|byte| *byte == b'\n').ok_or(())?;
    let minimum = match &bytes[..newline] {
        b"-" => None,
        encoded => {
            let decoded = hex::decode(encoded).map_err(|_| ())?;
            let value = String::from_utf8(decoded).map_err(|_| ())?;
            Some(TransitionDefaultMinimumObjectSize::custom(value))
        }
    };
    let persisted = parse_lifecycle(&bytes[newline + 1..]).map_err(|_| ())?;
    Ok(LifecycleRecord {
        configuration: from_persisted(persisted)?,
        minimum_object_size: minimum,
    })
}

fn to_persisted(value: &BucketLifecycleConfiguration) -> Result<PersistedLifecycleConfiguration, ()> {
    Ok(PersistedLifecycleConfiguration {
        expiry_updated_at: value
            .expiry_updated_at
            .map(|at| at.render(TimestampFormat::Iso8601).map_err(|_| ()))
            .transpose()?,
        rules: value.rules.iter().map(rule_to_persisted).collect::<Result<Vec<_>, _>>()?,
    })
}

fn rule_to_persisted(value: &LifecycleRule) -> Result<PersistedLifecycleRule, ()> {
    Ok(PersistedLifecycleRule {
        abort_incomplete_multipart_upload: value.abort_incomplete_multipart_upload.as_ref().map(|action| {
            PersistedAbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }
        }),
        del_marker_expiration: value
            .del_marker_expiration
            .as_ref()
            .map(|action| PersistedDelMarkerExpiration { days: action.days }),
        expiration: value
            .expiration
            .as_ref()
            .map(|expiration| {
                Ok(PersistedLifecycleExpiration {
                    date: expiration
                        .date
                        .map(|date| date.render(TimestampFormat::Iso8601).map_err(|_| ()))
                        .transpose()?,
                    days: expiration.days,
                    expired_object_all_versions: expiration.expired_object_all_versions,
                    expired_object_delete_marker: expiration.expired_object_delete_marker,
                })
            })
            .transpose()?,
        filter: value.filter.as_ref().map(filter_to_persisted).transpose()?,
        id: value.id.clone(),
        noncurrent_version_expiration: value.noncurrent_version_expiration.as_ref().map(|action| {
            PersistedNoncurrentVersionExpiration {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
            }
        }),
        noncurrent_version_transitions: (!value.noncurrent_version_transitions.is_empty()).then(|| {
            value
                .noncurrent_version_transitions
                .iter()
                .map(|action| PersistedNoncurrentVersionTransition {
                    newer_noncurrent_versions: action.newer_noncurrent_versions,
                    noncurrent_days: action.noncurrent_days,
                    storage_class: action.storage_class.as_ref().map(|class| class.as_str().to_owned()),
                })
                .collect()
        }),
        prefix: value.prefix.clone(),
        status: value.status.as_str().to_owned(),
        transitions: (!value.transitions.is_empty())
            .then(|| {
                value
                    .transitions
                    .iter()
                    .map(|action| {
                        Ok(PersistedTransition {
                            date: action
                                .date
                                .map(|date| date.render(TimestampFormat::Iso8601).map_err(|_| ()))
                                .transpose()?,
                            days: action.days,
                            storage_class: action.storage_class.as_ref().map(|class| class.as_str().to_owned()),
                        })
                    })
                    .collect::<Result<Vec<_>, ()>>()
            })
            .transpose()?,
    })
}

fn filter_to_persisted(value: &LifecycleRuleFilter) -> Result<PersistedLifecycleFilter, ()> {
    Ok(PersistedLifecycleFilter {
        and: value
            .and
            .as_ref()
            .map(|and| {
                Ok(PersistedLifecycleAnd {
                    object_size_greater_than: and.object_size_greater_than,
                    object_size_less_than: and.object_size_less_than,
                    prefix: and.prefix.clone(),
                    tags: (!and.tags.is_empty()).then(|| and.tags.iter().map(tag_to_persisted).collect::<Vec<_>>()),
                })
            })
            .transpose()?,
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix.clone(),
        tag: value.tag.as_ref().map(tag_to_persisted),
    })
}

fn tag_to_persisted(value: &Tag) -> PersistedLifecycleTag {
    PersistedLifecycleTag {
        key: Some(value.key.clone()),
        value: Some(value.value.clone()),
    }
}

fn from_persisted(value: PersistedLifecycleConfiguration) -> Result<BucketLifecycleConfiguration, ()> {
    Ok(BucketLifecycleConfiguration {
        expiry_updated_at: value
            .expiry_updated_at
            .map(|at| Timestamp::parse(&at, TimestampFormat::Iso8601).map_err(|_| ()))
            .transpose()?,
        rules: value
            .rules
            .into_iter()
            .map(rule_from_persisted)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn rule_from_persisted(value: PersistedLifecycleRule) -> Result<LifecycleRule, ()> {
    Ok(LifecycleRule {
        del_marker_expiration: value
            .del_marker_expiration
            .map(|action| DelMarkerExpiration { days: action.days }),
        abort_incomplete_multipart_upload: value
            .abort_incomplete_multipart_upload
            .map(|action| AbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }),
        expiration: value
            .expiration
            .map(|expiration| {
                Ok(LifecycleExpiration {
                    expired_object_all_versions: expiration.expired_object_all_versions,
                    date: expiration
                        .date
                        .map(|date| Timestamp::parse(&date, TimestampFormat::Iso8601).map_err(|_| ()))
                        .transpose()?,
                    days: expiration.days,
                    expired_object_delete_marker: expiration.expired_object_delete_marker,
                })
            })
            .transpose()?,
        filter: value.filter.map(filter_from_persisted).transpose()?,
        id: value.id,
        prefix: value.prefix,
        status: Status::custom(value.status),
        transitions: value
            .transitions
            .unwrap_or_default()
            .into_iter()
            .map(|action| {
                Ok(Transition {
                    date: action
                        .date
                        .map(|date| Timestamp::parse(&date, TimestampFormat::Iso8601).map_err(|_| ()))
                        .transpose()?,
                    days: action.days,
                    storage_class: action.storage_class.map(StorageClass::custom),
                })
            })
            .collect::<Result<Vec<_>, ()>>()?,
        noncurrent_version_transitions: value
            .noncurrent_version_transitions
            .unwrap_or_default()
            .into_iter()
            .map(|action| NoncurrentVersionTransition {
                noncurrent_days: action.noncurrent_days,
                storage_class: action.storage_class.map(StorageClass::custom),
                newer_noncurrent_versions: action.newer_noncurrent_versions,
            })
            .collect(),
        noncurrent_version_expiration: value.noncurrent_version_expiration.map(|action| NoncurrentVersionExpiration {
            noncurrent_days: action.noncurrent_days,
            newer_noncurrent_versions: action.newer_noncurrent_versions,
        }),
    })
}

fn filter_from_persisted(value: PersistedLifecycleFilter) -> Result<LifecycleRuleFilter, ()> {
    Ok(LifecycleRuleFilter {
        prefix: value.prefix,
        tag: value.tag.map(tag_from_persisted).transpose()?,
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        and: value
            .and
            .map(|and| {
                Ok(LifecycleRuleAndOperator {
                    prefix: and.prefix,
                    tags: and
                        .tags
                        .unwrap_or_default()
                        .into_iter()
                        .map(tag_from_persisted)
                        .collect::<Result<Vec<_>, _>>()?,
                    object_size_greater_than: and.object_size_greater_than,
                    object_size_less_than: and.object_size_less_than,
                })
            })
            .transpose()?,
    })
}

fn tag_from_persisted(value: PersistedLifecycleTag) -> Result<Tag, ()> {
    Ok(Tag {
        key: value.key.ok_or(())?,
        value: value.value.ok_or(())?,
    })
}

fn no_such_lifecycle() -> HandlerError {
    HandlerError::new(ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION, "The lifecycle configuration does not exist")
}

fn unsafe_record() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_REQUEST, "the lifecycle storage path is not a safe regular file")
}
