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

//! Durable bucket and per-version Object Lock configuration and handlers (rustfs/gateway#1512).
//!
//! Responsible for: atomic persistence of bucket `ObjectLockConfiguration`, default retention
//! calculation (`Days` and calendar `Years`), write-header lock validation, immutable governance
//! bypass verification against the accepted request context, and the six registered Object Lock
//! operations (`Get/PutObjectLockConfiguration`, `Get/PutObjectRetention`, `Get/PutObjectLegalHold`).
//! NOT responsible for: version record encoding (`super::lock_record` / `super::records`), wire
//! header/XML parsing (the generated codecs), or `GetObject`/`HeadObject` lock header projection
//! (intentionally omitted until independent `s3:GetObjectRetention`/`s3:GetObjectLegalHold`
//! visibility verdicts exist in `rustfs-gateway`).
//! Upstream: `rustfs_gateway` shared object-lock validators and persistence codecs, plus
//! `super::versioning`. Downstream: `super::registry`, `super::buckets`, `super::put_object`,
//! `super::copy`, `super::deletes`, `super::versioning`, and `compat-sut`.

use std::io::Write as _;
use std::path::Path;

use rustfs_gateway::dto::{
    DefaultRetention, GetObjectLegalHold, GetObjectLegalHoldOutput, GetObjectLockConfiguration, GetObjectLockConfigurationOutput,
    GetObjectRetention, GetObjectRetentionOutput, ObjectLockConfiguration, ObjectLockEnabled, ObjectLockLegalHold,
    ObjectLockRetention, PutObjectLegalHold, PutObjectLegalHoldOutput, PutObjectLockConfiguration,
    PutObjectLockConfigurationOutput, PutObjectRetention, PutObjectRetentionOutput, Status,
};
use rustfs_gateway::persistence::{parse_object_lock_dto, serialize_object_lock_dto};
use rustfs_gateway::{
    ErrorCode, Handler, HandlerError, HandlerResult, Req, RequestContextView, Resp, Timestamp,
    object_lock_requires_enabled_bucket, validate_legal_hold, validate_lock_configuration, validate_object_write_lock,
    validate_retention,
};

use super::lock_record::{LockState, RetentionMode};
use super::records::{RecordKind, VersionRecord, encode_version_record};
use super::versioning::{self, VersioningState, delete_marker_error, explicit_for_key, missing_version, newest_for_key};
use super::{FsBackend, no_such_key, storage_error};

pub(super) const OBJECT_LOCK_FILE: &str = "object-lock";

const BYPASS_GOVERNANCE_HEADER: &str = "x-amz-bypass-governance-retention";
const SECONDS_PER_DAY: i64 = 86_400;

fn object_lock_configuration_not_found() -> HandlerError {
    HandlerError::new(
        ErrorCode::OBJECT_LOCK_CONFIGURATION_NOT_FOUND,
        "Object Lock configuration does not exist for this bucket",
    )
}

fn no_such_object_lock_configuration() -> HandlerError {
    HandlerError::new(
        ErrorCode::NO_SUCH_OBJECT_LOCK_CONFIGURATION,
        "The specified object does not have an ObjectLock configuration",
    )
}

fn bucket_missing_object_lock() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_REQUEST, "Bucket is missing Object Lock Configuration")
}

fn event_hold_not_implemented() -> HandlerError {
    HandlerError::not_implemented("the filesystem backend does not support Object Lock event holds")
}

/// Stages both `versioning-status` (`Enabled`) and `object-lock` (`Enabled`) inside a newly
/// created bucket's temporary directory before the atomic bucket rename.
pub(super) fn stage_object_lock_for_new_bucket(staging: &Path) -> Result<(), HandlerError> {
    let config = ObjectLockConfiguration {
        object_lock_enabled: Some(ObjectLockEnabled::ENABLED),
        rule: None,
    };
    for (name, bytes) in [
        (versioning::STATUS_FILE, b"Enabled\n".as_slice()),
        (OBJECT_LOCK_FILE, serialize_object_lock_dto(&config).as_slice()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staging.join(name))
            .map_err(|_| storage_error())?;
        file.write_all(bytes).map_err(|_| storage_error())?;
        file.sync_all().map_err(|_| storage_error())?;
    }
    Ok(())
}

/// Returns `true` only when BOTH the decoded DTO flag and the immutable accepted wire header agree
/// on `x-amz-bypass-governance-retention: true` (case-insensitive, single occurrence).
///
/// Reading the accepted request context prevents a post-authorization `Req::input_mut` layer from
/// forging bypass intent that the framework's `GOVERNANCE_BYPASS` authorizer never checked.
pub(super) fn authorized_governance_bypass(input_flag: Option<bool>, context: &RequestContextView) -> bool {
    if input_flag != Some(true) {
        return false;
    }
    accepted_bypass_header_is_true(context)
}

/// Rejects governance bypass on batch `DeleteObjects` because per-object
/// `s3:BypassGovernanceRetention` authorization is not yet wired on `DeleteObjects`.
pub(super) fn reject_batch_governance_bypass(input_flag: Option<bool>, context: &RequestContextView) -> Result<(), HandlerError> {
    if input_flag == Some(true) || accepted_bypass_header_is_true(context) {
        return Err(HandlerError::not_implemented(
            "the filesystem backend does not support governance bypass on batch DeleteObjects",
        ));
    }
    Ok(())
}

fn accepted_bypass_header_is_true(context: &RequestContextView) -> bool {
    let name = http::HeaderName::from_static(BYPASS_GOVERNANCE_HEADER);
    let headers = context.headers();
    headers.count(&name) == 1
        && headers
            .get_bytes(&name)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

/// Write-carried Object Lock headers from `PutObject`, `CopyObject`, or `CreateMultipartUpload`.
pub(super) struct WriteLockHeaders<'a> {
    pub(super) mode: Option<&'a str>,
    pub(super) retain_until: Option<&'a Timestamp>,
    pub(super) legal_hold: Option<&'a str>,
    pub(super) has_event_hold: bool,
}

impl FsBackend {
    /// Reads the bucket's durable `ObjectLockConfiguration`, failing closed on corrupt or symlink
    /// files. Caller must hold `self.version_lock` when coordinating with mutations.
    pub(super) async fn stored_object_lock(&self, bucket: &str) -> Result<Option<ObjectLockConfiguration>, HandlerError> {
        self.require_bucket(bucket).await?;
        self.stored_object_lock_in_verified_bucket(bucket).await
    }

    async fn stored_object_lock_in_verified_bucket(&self, bucket: &str) -> Result<Option<ObjectLockConfiguration>, HandlerError> {
        let Some(bytes) = self
            .read_bucket_record(&self.bucket_path(bucket).join(OBJECT_LOCK_FILE))
            .await?
        else {
            return Ok(None);
        };
        let config = parse_object_lock_dto(&bytes).map_err(|_| storage_error())?;
        if config.object_lock_enabled.as_ref().map(ObjectLockEnabled::as_str) != Some(ObjectLockEnabled::ENABLED.as_str()) {
            return Err(storage_error());
        }
        Ok(Some(config))
    }

    /// Whether Object Lock is durably enabled on `bucket`, failing closed on corrupt/symlink state.
    pub(super) async fn bucket_has_object_lock(&self, bucket: &str) -> Result<bool, HandlerError> {
        Ok(self.stored_object_lock(bucket).await?.is_some())
    }

    async fn require_object_lock_enabled(&self, bucket: &str) -> Result<ObjectLockConfiguration, HandlerError> {
        let stored = self.stored_object_lock(bucket).await?;
        if let Some(config) = stored {
            return Ok(config);
        }
        if !object_lock_requires_enabled_bucket() {
            return Ok(ObjectLockConfiguration {
                object_lock_enabled: Some(ObjectLockEnabled::ENABLED),
                rule: None,
            });
        }
        Err(bucket_missing_object_lock())
    }

    /// Validates write-carried Object Lock headers before object or upload publication.
    ///
    /// Event-hold headers remain explicitly refused with `501 NotImplemented`. Standard headers
    /// validate against the shared contract and require Object Lock to be enabled on `bucket`.
    pub(super) async fn resolve_write_object_lock(
        &self,
        bucket: &str,
        headers: WriteLockHeaders<'_>,
    ) -> Result<Option<LockState>, HandlerError> {
        if headers.has_event_hold {
            return Err(event_hold_not_implemented());
        }
        if headers.mode.is_none() && headers.retain_until.is_none() && headers.legal_hold.is_none() {
            return Ok(None);
        }
        let now = self.clock.now().unix_seconds();
        validate_object_write_lock(headers.mode, headers.retain_until, headers.legal_hold, now)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        self.require_object_lock_enabled(bucket).await?;
        let retention = match (headers.mode, headers.retain_until) {
            (Some(mode), Some(until)) => {
                let parsed = RetentionMode::from_wire(mode).ok_or_else(storage_error)?;
                Some((parsed, *until))
            }
            (None, None) => None,
            _ => return Err(storage_error()),
        };
        let hold = match headers.legal_hold {
            Some("ON") => Some(true),
            Some("OFF") => Some(false),
            None => None,
            Some(_) => return Err(storage_error()),
        };
        Ok(Some(LockState { retention, hold }))
    }

    /// Combines explicit object lock state with the bucket's default retention (if any) at `now`.
    /// Caller holds `self.version_lock`.
    pub(super) async fn effective_object_lock(
        &self,
        bucket: &str,
        explicit: Option<&LockState>,
        now: i64,
    ) -> Result<Option<LockState>, HandlerError> {
        let Some(config) = self.stored_object_lock_in_verified_bucket(bucket).await? else {
            if explicit.is_some() && object_lock_requires_enabled_bucket() {
                return Err(bucket_missing_object_lock());
            }
            return Ok(explicit.cloned());
        };
        if explicit.is_some_and(|state| state.retention.is_some()) {
            return Ok(explicit.cloned());
        }
        let Some(default_rule) = config.rule.as_ref().and_then(|rule| rule.default_retention.as_ref()) else {
            return Ok(explicit.cloned());
        };
        let default_retention = compute_default_retention(default_rule, now)?;
        let hold = explicit.and_then(|state| state.hold);
        Ok(Some(LockState {
            retention: Some(default_retention),
            hold,
        }))
    }

    /// Selects the exact version record targeted by a retention or legal-hold operation.
    /// Caller holds `self.version_lock`.
    async fn select_version_for_lock(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<VersionRecord, HandlerError> {
        let mut records = self.version_records(bucket).await?;
        self.reconcile_nulls_for_key_locked(bucket, key, &mut records)?;
        let selected = version_id
            .and_then(|id| explicit_for_key(&records, key, id))
            .or_else(|| version_id.is_none().then(|| newest_for_key(&records, key)).flatten());
        let Some(record) = selected else {
            if version_id.is_some_and(|id| id != "null") {
                return Err(missing_version(key));
            }
            if self.read_object_if_present(bucket, key).await?.is_some() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the legacy unversioned object cannot carry Object Lock state",
                ));
            }
            return Err(no_such_key(key));
        };
        if matches!(record.kind, RecordKind::DeleteMarker) {
            return Err(delete_marker_error(record, key, version_id.is_some()));
        }
        Ok(record.clone())
    }

    /// Persists an updated lock state onto an existing version record atomically in place.
    /// Caller holds `self.version_lock`.
    async fn persist_version_lock(&self, mut record: VersionRecord, lock: Option<LockState>) -> Result<(), HandlerError> {
        record.lock = lock.filter(|state| !state.is_empty());
        let encoded = encode_version_record(&record);
        self.write_atomic(&record.path, &record.path.join(versioning::RECORD_FILE), encoded.as_bytes())
            .await
    }
}

impl Handler<GetObjectLockConfiguration> for FsBackend {
    async fn call(&self, request: Req<GetObjectLockConfiguration>) -> HandlerResult<GetObjectLockConfiguration> {
        let _guard = self.version_lock.lock().await?;
        let stored = self
            .stored_object_lock(request.input().bucket.as_str())
            .await?
            .ok_or_else(object_lock_configuration_not_found)?;
        Ok(Resp::new(GetObjectLockConfigurationOutput {
            object_lock_configuration: Some(stored),
        }))
    }
}

impl Handler<PutObjectLockConfiguration> for FsBackend {
    async fn call(&self, request: Req<PutObjectLockConfiguration>) -> HandlerResult<PutObjectLockConfiguration> {
        let input = request.input();
        let bucket = input.bucket.as_str();
        let config = &input.object_lock_configuration;
        if config
            .rule
            .as_ref()
            .and_then(|rule| rule.default_retention.as_ref())
            .is_some_and(|retention| retention.default_event_hold.is_some())
        {
            return Err(event_hold_not_implemented());
        }
        validate_lock_configuration(config).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let _guard = self.version_lock.lock().await?;
        let existing = self.stored_object_lock(bucket).await?;
        if existing.is_none() {
            if config.object_lock_enabled.as_ref().map(ObjectLockEnabled::as_str) != Some(ObjectLockEnabled::ENABLED.as_str()) {
                return Err(HandlerError::new(ErrorCode::MALFORMED_XML, "ObjectLockEnabled must be Enabled"));
            }
            let state = self.versioning_state_for_lock(bucket).await?;
            if state != VersioningState::Enabled {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_BUCKET_STATE,
                    "Versioning must be 'Enabled' on the bucket to apply an Object Lock configuration",
                ));
            }
            if self.has_versioning_exclusions(bucket).await? {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_BUCKET_STATE,
                    "Versioning exclusions cannot be combined with Object Lock",
                ));
            }
        }
        let mut normalized = config.clone();
        normalized.object_lock_enabled = Some(ObjectLockEnabled::ENABLED);
        self.write_bucket_record(bucket, OBJECT_LOCK_FILE, &serialize_object_lock_dto(&normalized))
            .await?;
        Ok(Resp::new(PutObjectLockConfigurationOutput::default()))
    }
}

impl Handler<GetObjectRetention> for FsBackend {
    async fn call(&self, request: Req<GetObjectRetention>) -> HandlerResult<GetObjectRetention> {
        let input = request.input();
        let _guard = self.version_lock.lock().await?;
        self.require_object_lock_enabled(input.bucket.as_str()).await?;
        let record = self
            .select_version_for_lock(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let (mode, until) = record
            .lock
            .and_then(|state| state.retention)
            .ok_or_else(no_such_object_lock_configuration)?;
        Ok(Resp::new(GetObjectRetentionOutput {
            retention: Some(ObjectLockRetention {
                mode: Some(mode.to_dto()),
                retain_until_date: Some(until),
                event_hold: None,
                event_hold_duration: None,
            }),
        }))
    }
}

impl Handler<PutObjectRetention> for FsBackend {
    async fn call(&self, request: Req<PutObjectRetention>) -> HandlerResult<PutObjectRetention> {
        let bypass = authorized_governance_bypass(request.input().bypass_governance_retention, request.context());
        let input = request.input();
        if input.retention.event_hold.is_some() || input.retention.event_hold_duration.is_some() {
            return Err(event_hold_not_implemented());
        }
        let _guard = self.version_lock.lock().await?;
        self.require_object_lock_enabled(input.bucket.as_str()).await?;
        let now = self.clock.now().unix_seconds();
        validate_retention(&input.retention, now).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let requested = match (input.retention.mode.as_ref(), input.retention.retain_until_date) {
            (Some(mode), Some(until)) => {
                let parsed = RetentionMode::from_wire(mode.as_str()).ok_or_else(storage_error)?;
                Some((parsed, until))
            }
            (None, None) => None,
            _ => {
                return Err(HandlerError::new(
                    ErrorCode::MALFORMED_XML,
                    "Retention must specify both Mode and RetainUntilDate",
                ));
            }
        };
        let record = self
            .select_version_for_lock(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let current_active = record.lock.as_ref().and_then(|state| state.active_retention(now));
        validate_retention_transition(current_active, requested, bypass)?;
        let updated_lock = LockState {
            retention: requested,
            hold: record.lock.as_ref().and_then(|state| state.hold),
        };
        self.persist_version_lock(record, Some(updated_lock)).await?;
        Ok(Resp::new(PutObjectRetentionOutput::default()))
    }
}

impl Handler<GetObjectLegalHold> for FsBackend {
    async fn call(&self, request: Req<GetObjectLegalHold>) -> HandlerResult<GetObjectLegalHold> {
        let input = request.input();
        let _guard = self.version_lock.lock().await?;
        self.require_object_lock_enabled(input.bucket.as_str()).await?;
        let record = self
            .select_version_for_lock(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let on = record
            .lock
            .and_then(|state| state.hold)
            .ok_or_else(no_such_object_lock_configuration)?;
        Ok(Resp::new(GetObjectLegalHoldOutput {
            legal_hold: Some(ObjectLockLegalHold {
                status: Some(if on { Status::ON } else { Status::OFF }),
            }),
        }))
    }
}

impl Handler<PutObjectLegalHold> for FsBackend {
    async fn call(&self, request: Req<PutObjectLegalHold>) -> HandlerResult<PutObjectLegalHold> {
        let input = request.input();
        let _guard = self.version_lock.lock().await?;
        self.require_object_lock_enabled(input.bucket.as_str()).await?;
        validate_legal_hold(&input.legal_hold).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let on = match input.legal_hold.status.as_ref().map(Status::as_str) {
            Some("ON") => true,
            Some("OFF") => false,
            _ => return Err(HandlerError::new(ErrorCode::MALFORMED_XML, "Status must be ON or OFF")),
        };
        let record = self
            .select_version_for_lock(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let updated_lock = LockState {
            retention: record.lock.as_ref().and_then(|state| state.retention),
            hold: Some(on),
        };
        self.persist_version_lock(record, Some(updated_lock)).await?;
        Ok(Resp::new(PutObjectLegalHoldOutput::default()))
    }
}

fn validate_retention_transition(
    current: Option<(RetentionMode, Timestamp)>,
    requested: Option<(RetentionMode, Timestamp)>,
    bypass_governance: bool,
) -> Result<(), HandlerError> {
    match (current, requested) {
        (Some((RetentionMode::Compliance, _)), None) => {
            Err(HandlerError::new(ErrorCode::ACCESS_DENIED, "COMPLIANCE retention cannot be cleared"))
        }
        (Some((RetentionMode::Compliance, current_until)), Some((new_mode, new_until))) => {
            if new_mode != RetentionMode::Compliance || new_until < current_until {
                return Err(HandlerError::new(
                    ErrorCode::ACCESS_DENIED,
                    "COMPLIANCE retention cannot be shortened or downgraded",
                ));
            }
            Ok(())
        }
        (Some((RetentionMode::Governance, _)), None) => {
            if !bypass_governance {
                return Err(HandlerError::new(
                    ErrorCode::ACCESS_DENIED,
                    "clearing active GOVERNANCE retention requires x-amz-bypass-governance-retention: true",
                ));
            }
            Ok(())
        }
        (Some((RetentionMode::Governance, current_until)), Some((_, new_until))) => {
            if new_until < current_until && !bypass_governance {
                return Err(HandlerError::new(
                    ErrorCode::ACCESS_DENIED,
                    "shortening active GOVERNANCE retention requires x-amz-bypass-governance-retention: true",
                ));
            }
            Ok(())
        }
        (None, None) => {
            if !bypass_governance {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_ARGUMENT,
                    "clearing retention requires x-amz-bypass-governance-retention: true",
                ));
            }
            Ok(())
        }
        (None, Some(_)) => Ok(()),
    }
}

fn compute_default_retention(rule: &DefaultRetention, now: i64) -> Result<(RetentionMode, Timestamp), HandlerError> {
    let mode = rule
        .mode
        .as_ref()
        .and_then(|mode| RetentionMode::from_wire(mode.as_str()))
        .ok_or_else(storage_error)?;
    let until_secs = match (rule.days, rule.years) {
        (Some(days), None) if days >= 1 => i64::from(days)
            .checked_mul(SECONDS_PER_DAY)
            .and_then(|delta| now.checked_add(delta))
            .ok_or_else(storage_error)?,
        (None, Some(years)) if years >= 1 => add_calendar_years(now, years).ok_or_else(storage_error)?,
        _ => return Err(storage_error()),
    };
    Ok((mode, Timestamp::from_secs(until_secs)))
}

/// Adds `years` proleptic Gregorian calendar years in UTC, clamping Feb 29 to Feb 28 on non-leap
/// destination years.
fn add_calendar_years(unix_secs: i64, years: i32) -> Option<i64> {
    let days = unix_secs.div_euclid(SECONDS_PER_DAY);
    let secs_of_day = unix_secs.rem_euclid(SECONDS_PER_DAY);
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year = year.checked_add(1)?;
    }

    let target_year = year.checked_add(i64::from(years))?;
    let is_leap = (target_year.rem_euclid(4) == 0 && target_year.rem_euclid(100) != 0) || target_year.rem_euclid(400) == 0;
    let target_day = if month == 2 && day == 29 && !is_leap { 28 } else { day };

    let adj_year = if month <= 2 {
        target_year.checked_sub(1)?
    } else {
        target_year
    };
    let era2 = adj_year.div_euclid(400);
    let yoe2 = adj_year - era2 * 400;
    let mp2 = if month > 2 { month - 3 } else { month + 9 };
    let doy2 = (153 * mp2 + 2) / 5 + target_day - 1;
    let doe2 = yoe2 * 365 + yoe2 / 4 - yoe2 / 100 + doy2;
    let target_days = era2.checked_mul(146_097)?.checked_add(doe2)?.checked_sub(719_468)?;
    target_days.checked_mul(SECONDS_PER_DAY)?.checked_add(secs_of_day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_years_preserve_time_of_day_and_clamp_leap_day() {
        // 2026-01-02T03:04:05Z + 1 year = 2027-01-02T03:04:05Z (+365d).
        assert_eq!(add_calendar_years(1_767_323_045, 1), Some(1_767_323_045 + 365 * SECONDS_PER_DAY));
        // 2024-02-29T12:00:00Z = 1_709_208_000 -> +1 year clamps to 2025-02-28T12:00:00Z (+365d).
        assert_eq!(add_calendar_years(1_709_208_000, 1), Some(1_709_208_000 + 365 * SECONDS_PER_DAY));
        // 2024-02-29T12:00:00Z + 4 years lands on leap day 2028-02-29T12:00:00Z (+1461d).
        assert_eq!(add_calendar_years(1_709_208_000, 4), Some(1_709_208_000 + 1_461 * SECONDS_PER_DAY));
    }

    #[test]
    fn n_retention_transitions_enforce_compliance_and_governance_bypass() {
        let t1 = Timestamp::from_secs(2_000);
        let t2 = Timestamp::from_secs(3_000);
        assert!(
            validate_retention_transition(Some((RetentionMode::Compliance, t2)), Some((RetentionMode::Compliance, t1)), true)
                .is_err()
        );
        assert!(
            validate_retention_transition(Some((RetentionMode::Compliance, t1)), Some((RetentionMode::Governance, t2)), true)
                .is_err()
        );
        assert!(validate_retention_transition(Some((RetentionMode::Compliance, t1)), None, true).is_err());
        assert!(
            validate_retention_transition(Some((RetentionMode::Compliance, t1)), Some((RetentionMode::Compliance, t2)), false)
                .is_ok()
        );

        assert!(
            validate_retention_transition(Some((RetentionMode::Governance, t2)), Some((RetentionMode::Governance, t1)), false)
                .is_err()
        );
        assert!(validate_retention_transition(Some((RetentionMode::Governance, t2)), None, false).is_err());
        assert!(
            validate_retention_transition(Some((RetentionMode::Governance, t2)), Some((RetentionMode::Governance, t1)), true)
                .is_ok()
        );
        assert!(validate_retention_transition(Some((RetentionMode::Governance, t2)), None, true).is_ok());
        assert!(
            validate_retention_transition(Some((RetentionMode::Governance, t1)), Some((RetentionMode::Compliance, t2)), false)
                .is_ok()
        );
        assert!(validate_retention_transition(None, None, false).is_err());
        assert!(validate_retention_transition(None, None, true).is_ok());
    }

    fn temp_bucket_backend(label: &str) -> (std::path::PathBuf, FsBackend) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fs-lock-unit-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let backend = FsBackend::open(&root).expect("open root");
        let bucket = backend.bucket_path("bkt");
        for sub in [
            super::super::OBJECTS_DIR,
            super::super::UPLOADS_DIR,
            super::super::VERSIONS_DIR,
        ] {
            std::fs::create_dir_all(bucket.join(sub)).expect("create bucket subdir");
        }
        (root, backend)
    }

    /// Negative — a persisted `object-lock` document missing `<ObjectLockEnabled>` fails closed.
    #[tokio::test]
    async fn n_stored_object_lock_missing_enabled_fails_closed() {
        let (root, backend) = temp_bucket_backend("missing-enabled");
        let lock_file = backend.bucket_path("bkt").join(OBJECT_LOCK_FILE);
        std::fs::write(&lock_file, b"<ObjectLockConfiguration/>").expect("write empty config");
        let err = backend
            .stored_object_lock("bkt")
            .await
            .expect_err("missing ObjectLockEnabled must fail closed");
        assert_eq!(err.code(), &ErrorCode::INTERNAL_ERROR);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Negative — `effective_object_lock` under `version_lock` refuses explicit lock headers if the
    /// bucket was recreated without Object Lock between pre-lock validation and publication.
    #[tokio::test]
    async fn n_effective_object_lock_refuses_explicit_lock_on_unlocked_bucket() {
        let (root, backend) = temp_bucket_backend("unlocked-toctou");
        let explicit = LockState {
            retention: None,
            hold: Some(true),
        };
        let err = backend
            .effective_object_lock("bkt", Some(&explicit), 1_767_323_045)
            .await
            .expect_err("explicit lock on unlocked bucket must fail closed under version_lock");
        assert_eq!(err.code(), &ErrorCode::INVALID_REQUEST);
        assert_eq!(err.message(), "Bucket is missing Object Lock Configuration");
        // Ordinary writes with no explicit lock remain allowed on unlocked buckets.
        assert_eq!(
            backend
                .effective_object_lock("bkt", None, 1_767_323_045)
                .await
                .expect("ordinary write"),
            None
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
