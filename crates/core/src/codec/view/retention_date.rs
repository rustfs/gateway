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

//! The source UTC offset of a validated object retention date.
//!
//! Responsible for: capturing the Retention XML date and the PutObject retention-date header.
//! NOT responsible for: timestamp grammar, retention policy or persistence.
//! Upstream: the strict document reader and operation codec. Downstream: typed dispatch.

use std::sync::Mutex;

use rustfs_gateway_xml::XmlNode;

use super::MetaView;
use crate::CodecError;

const CAPTURE_FAILED: CodecError = CodecError::internal("retention date offset capture failed");

impl MetaView<'_> {
    pub(crate) fn with_retention_date_capture(&self) -> Self {
        let mut scoped = self.derive_with_framed_length(self.framed_content_length);
        scoped.retention_date_capture = Some(Mutex::new(None));
        scoped
    }

    pub(crate) const fn captures_retention_date(&self) -> bool {
        self.retention_date_capture.is_some()
    }

    pub(crate) fn capture_retention_date(&self, root: &XmlNode) -> Result<(), CodecError> {
        if let Some(slot) = &self.retention_date_capture {
            let offset = root.child_text("RetainUntilDate").map(validated_offset_seconds).transpose()?;
            *slot.lock().map_err(|_| CAPTURE_FAILED)? = offset;
        }
        Ok(())
    }

    pub(crate) fn into_retention_date_offset_seconds(self) -> Result<Option<i32>, CodecError> {
        self.retention_date_capture
            .map(Mutex::into_inner)
            .transpose()
            .map(Option::flatten)
            .map_err(|_| CAPTURE_FAILED)
    }

    pub(crate) fn put_object_retention_date_offset_seconds(&self) -> Result<Option<i32>, CodecError> {
        self.header("x-amz-object-lock-retain-until-date")
            .as_deref()
            .map(validated_offset_seconds)
            .transpose()
    }
}

/// Both callers have already validated the date. The header codec accepts compact offsets,
/// and the strict XML reader supplies the normalized extended spelling.
fn validated_offset_seconds(date: &str) -> Result<i32, CodecError> {
    if date.ends_with(['Z', 'z']) {
        return Ok(0);
    }
    let zone_start = date.rfind(['+', '-']).ok_or(CAPTURE_FAILED)?;
    let (sign, offset) = date[zone_start..].split_at(1);
    let (hours, minutes) = offset.split_at_checked(2).ok_or(CAPTURE_FAILED)?;
    let hours = hours.parse::<u8>().map_err(|_| CAPTURE_FAILED)?;
    let minutes = minutes
        .strip_prefix(':')
        .unwrap_or(minutes)
        .parse::<u8>()
        .map_err(|_| CAPTURE_FAILED)?;
    let seconds = i32::from(hours) * 3600 + i32::from(minutes) * 60;
    Ok(if sign == "-" { -seconds } else { seconds })
}
