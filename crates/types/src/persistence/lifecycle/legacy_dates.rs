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

//! Historical Lifecycle date parsing and persistence formatting.
//!
//! Responsible for: RFC3339 validation, lossless reads, and the local-field legacy writer.
//! NOT responsible for: XML structure, Lifecycle policy, or canonical protocol timestamps.
//! Upstream: the explicit legacy-date Lifecycle codec. Downstream: stored date strings.

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::PersistenceCodecError;

pub(super) fn read(value: &str) -> Result<String, PersistenceCodecError> {
    parse(value)?;
    Ok(value.to_owned())
}

pub(super) fn write(value: &str) -> Result<String, PersistenceCodecError> {
    let date = parse(value)?;
    if !(0..=9999).contains(&date.year()) {
        return Err(PersistenceCodecError::InvalidLifecycleTimestamp);
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second(),
        date.millisecond(),
    ))
}

fn parse(value: &str) -> Result<OffsetDateTime, PersistenceCodecError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| PersistenceCodecError::InvalidLifecycleTimestamp)
}
