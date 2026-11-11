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

//! The private durable representation of one version's retention and legal hold.
//!
//! Responsible for: bounded serialization and fail-closed decoding of the lock record section.
//! NOT responsible for: authorization, bucket enablement, retention updates, or bypass grants.
//! Upstream: version records. Downstream: deletion checks under the version lock.

use rustfs_gateway::{HandlerError, Timestamp};

#[derive(Clone, Debug)]
pub(super) struct LockState {
    retention: Option<(RetentionMode, Timestamp)>,
    hold: Option<bool>,
}

#[derive(Clone, Copy, Debug)]
enum RetentionMode {
    Governance,
    Compliance,
}

impl LockState {
    pub(super) fn prevents_deletion(&self, now: i64) -> bool {
        self.hold == Some(true) || self.retention.is_some_and(|(_, until)| until > Timestamp::from_secs(now))
    }
}

pub(super) fn encode(state: Option<&LockState>) -> String {
    let Some(state) = state else { return String::new() };
    let (mode, until) = match state.retention {
        Some((RetentionMode::Governance, until)) => ("GOVERNANCE", encode_instant(until)),
        Some((RetentionMode::Compliance, until)) => ("COMPLIANCE", encode_instant(until)),
        None => ("NONE", "-".to_owned()),
    };
    let hold = match state.hold {
        Some(true) => "ON",
        Some(false) => "OFF",
        None => "-",
    };
    format!("lock/1 1\n{mode} {until} {hold}\n")
}

fn encode_instant(instant: Timestamp) -> String {
    if instant.subsec_nanos() == 0 {
        instant.secs().to_string()
    } else {
        format!("{}.{:09}", instant.secs(), instant.subsec_nanos())
    }
}

fn decode_instant(value: &str) -> Result<Timestamp, HandlerError> {
    let invalid = || HandlerError::internal_error("the persisted version protection is malformed");
    let (seconds, nanos) = match value.split_once('.') {
        Some((seconds, nanos)) if nanos.len() == 9 && nanos.bytes().all(|byte| byte.is_ascii_digit()) => {
            (seconds, nanos.parse().map_err(|_| invalid())?)
        }
        Some(_) => return Err(invalid()),
        None => (value, 0),
    };
    Timestamp::from_secs_nanos(seconds.parse().map_err(|_| invalid())?, nanos).map_err(|_| invalid())
}

pub(super) fn decode(lines: &mut std::str::Lines<'_>, count: &str) -> Result<LockState, HandlerError> {
    let invalid = || HandlerError::internal_error("the persisted version protection is malformed");
    if count != "1" {
        return Err(invalid());
    }
    let mut values = lines.next().ok_or_else(invalid)?.split(' ');
    let mode = values.next().ok_or_else(invalid)?;
    let until = values.next().ok_or_else(invalid)?;
    let hold = match values.next().ok_or_else(invalid)? {
        "ON" => Some(true),
        "OFF" => Some(false),
        "-" => None,
        _ => return Err(invalid()),
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    let retention = match (mode, until) {
        ("NONE", "-") => None,
        ("GOVERNANCE", until) => Some((RetentionMode::Governance, decode_instant(until)?)),
        ("COMPLIANCE", until) => Some((RetentionMode::Compliance, decode_instant(until)?)),
        _ => return Err(invalid()),
    };
    Ok(LockState { retention, hold })
}

/// Check null-version replacement before publishing a new object or marker.
pub(super) fn ensure_null_deletable(records: &[super::records::VersionRecord], key: &str, now: i64) -> Result<(), HandlerError> {
    for record in records
        .iter()
        .filter(|record| record.key == key && record.version_id == "null")
    {
        ensure_deletable(record.lock.as_ref(), now)?;
    }
    Ok(())
}

pub(super) fn ensure_deletable(lock: Option<&LockState>, now: i64) -> Result<(), HandlerError> {
    if lock.is_some_and(|state| state.prevents_deletion(now)) {
        return Err(HandlerError::new(
            rustfs_gateway::ErrorCode::ACCESS_DENIED,
            "the object version is protected",
        ));
    }
    Ok(())
}
