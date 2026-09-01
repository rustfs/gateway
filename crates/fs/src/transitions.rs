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

//! One-shot lifecycle transition execution for current object versions.
//!
//! Responsible for: preflighting transition policies, choosing due current-object actions, and
//! atomically changing the persisted storage-class projection. NOT responsible for: scheduling,
//! moving bytes between physical tiers, expiration, or noncurrent-version actions. Upstream:
//! lifecycle selection and version authority. Downstream: filesystem GET, HEAD, and list handlers.

use rustfs_gateway::HandlerError;
use rustfs_gateway::dto::{LifecycleRule, Status, StorageClass, Transition};

use super::lifecycle::{LifecycleRecord, rule_selects};
use super::versioning::CurrentObjectRecord;
use super::{FsBackend, storage_error};

const DEFAULT_MINIMUM_BYTES: i64 = 128 * 1024;

struct SelectedTransition {
    bucket: String,
    key: String,
    sequence: u64,
    storage_class: StorageClass,
}

impl FsBackend {
    /// Runs one lifecycle-transition sweep and returns the number of current objects changed.
    ///
    /// Every lifecycle and version record is validated before the first write. The write uses the
    /// observed current-version sequence as a compare-and-set token, so a stale sweep never
    /// rewrites a newer object.
    ///
    /// # Errors
    ///
    /// Returns a handler error without changing any storage class when preflight encounters an
    /// unsafe or corrupt authority, or a due action names an unsupported transition class.
    pub async fn transition_lifecycle_once(&self) -> Result<usize, HandlerError> {
        let now = self.clock.now().unix_seconds();
        let mut selected = Vec::new();
        for bucket in self.lifecycle_buckets().await? {
            let Some(lifecycle) = self.optional_lifecycle(&bucket).await? else {
                continue;
            };
            for object in self.current_object_records(&bucket).await? {
                if let Some(storage_class) = selected_class(&lifecycle, &object, now, self.lifecycle_day_seconds)?
                    && storage_class.as_str() != object.storage_class.as_str()
                {
                    selected.push(SelectedTransition {
                        bucket: bucket.clone(),
                        key: object.key,
                        sequence: object.sequence,
                        storage_class,
                    });
                }
            }
        }

        let mut changed = 0;
        for transition in selected {
            if self
                .transition_current_if_unchanged(
                    &transition.bucket,
                    &transition.key,
                    transition.sequence,
                    &transition.storage_class,
                )
                .await?
            {
                changed += 1;
            }
        }
        Ok(changed)
    }
}

fn selected_class(
    lifecycle: &LifecycleRecord,
    object: &CurrentObjectRecord,
    now: i64,
    day_seconds: i64,
) -> Result<Option<StorageClass>, HandlerError> {
    let mut selected = None;
    for rule in &lifecycle.configuration.rules {
        if rule.status.as_str() != Status::ENABLED.as_str() || !rule_selects(rule, object) {
            continue;
        }
        for action in &rule.transitions {
            if !is_due(action, object.modified, now, day_seconds) {
                continue;
            }
            let class = action
                .storage_class
                .as_ref()
                .and_then(|value| transition_storage_class(value.as_str()))
                .ok_or_else(storage_error)?;
            if transition_size_allows(lifecycle, rule, object.size, &class) {
                selected = Some(class);
            }
        }
    }
    Ok(selected)
}

fn is_due(action: &Transition, modified: i64, now: i64, day_seconds: i64) -> bool {
    let date_due = action.date.as_ref().is_some_and(|date| now >= date.secs());
    let days_due = action.days.is_some_and(|days| {
        i64::from(days)
            .checked_mul(day_seconds)
            .and_then(|age| modified.checked_add(age))
            .is_some_and(|due| now >= due)
    });
    date_due || days_due
}

fn transition_size_allows(lifecycle: &LifecycleRecord, rule: &LifecycleRule, size: i64, class: &StorageClass) -> bool {
    if has_explicit_size_filter(rule) {
        return true;
    }
    match lifecycle.minimum_object_size.as_ref().map(|value| value.as_str()) {
        Some("varies_by_storage_class") => size >= DEFAULT_MINIMUM_BYTES || matches!(class.as_str(), "GLACIER" | "DEEP_ARCHIVE"),
        _ => size >= DEFAULT_MINIMUM_BYTES,
    }
}

fn has_explicit_size_filter(rule: &LifecycleRule) -> bool {
    rule.filter.as_ref().is_some_and(|filter| {
        filter.object_size_greater_than.is_some()
            || filter.object_size_less_than.is_some()
            || filter
                .and
                .as_ref()
                .is_some_and(|and| and.object_size_greater_than.is_some() || and.object_size_less_than.is_some())
    })
}

pub(super) fn persisted_storage_class(value: String) -> Option<StorageClass> {
    matches!(
        value.as_str(),
        "STANDARD" | "STANDARD_IA" | "ONEZONE_IA" | "INTELLIGENT_TIERING" | "GLACIER" | "DEEP_ARCHIVE" | "GLACIER_IR"
    )
    .then(|| StorageClass::custom(value.to_owned()))
}

fn transition_storage_class(value: &str) -> Option<StorageClass> {
    matches!(
        value,
        "STANDARD_IA" | "ONEZONE_IA" | "INTELLIGENT_TIERING" | "GLACIER" | "DEEP_ARCHIVE" | "GLACIER_IR"
    )
    .then(|| StorageClass::custom(value.to_owned()))
}
