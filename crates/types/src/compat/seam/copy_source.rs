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

//! Lossless decoded copy-source conversion for the enclosing legacy revision.
//!
//! Responsible for: moving every source identity field and preserving version presence.
//! NOT responsible for: parsing, choosing name policy, validating fields or authorizing a source.
//! Upstream: legacy and owned decoded values. Downstream: application migration at its existing checks.

use super::s3s::dto::CopySource as Legacy;
use crate::CopySourceValue;

/// Moves a legacy source into owned fields without parsing or validating it.
///
/// This preserves decoded text and version presence; it does not authorize a copy.
#[must_use]
pub fn from_s3s(source: Legacy) -> CopySourceValue {
    match source {
        Legacy::Bucket { bucket, key, version_id } => CopySourceValue::Bucket {
            bucket: String::from(bucket),
            key: String::from(key),
            version_id: version_id.map(String::from),
        },
        Legacy::AccessPoint {
            partition,
            region,
            account_id,
            access_point_name,
            key,
            version_id,
        } => CopySourceValue::AccessPoint {
            partition: String::from(partition),
            region: String::from(region),
            account_id: String::from(account_id),
            access_point_name: String::from(access_point_name),
            key: String::from(key),
            version_id: version_id.map(String::from),
        },
        Legacy::Outpost {
            partition,
            region,
            account_id,
            outpost_id,
            key,
            version_id,
        } => CopySourceValue::Outpost {
            partition: String::from(partition),
            region: String::from(region),
            account_id: String::from(account_id),
            outpost_id: String::from(outpost_id),
            key: String::from(key),
            version_id: version_id.map(String::from),
        },
    }
}

/// Moves owned fields back to a legacy source without parsing or validating them.
///
/// This preserves decoded text and version presence; it does not authorize a copy.
#[must_use]
pub fn to_s3s(source: CopySourceValue) -> Legacy {
    match source {
        CopySourceValue::Bucket { bucket, key, version_id } => Legacy::Bucket {
            bucket: bucket.into_boxed_str(),
            key: key.into_boxed_str(),
            version_id: version_id.map(String::into_boxed_str),
        },
        CopySourceValue::AccessPoint {
            partition,
            region,
            account_id,
            access_point_name,
            key,
            version_id,
        } => Legacy::AccessPoint {
            partition: partition.into_boxed_str(),
            region: region.into_boxed_str(),
            account_id: account_id.into_boxed_str(),
            access_point_name: access_point_name.into_boxed_str(),
            key: key.into_boxed_str(),
            version_id: version_id.map(String::into_boxed_str),
        },
        CopySourceValue::Outpost {
            partition,
            region,
            account_id,
            outpost_id,
            key,
            version_id,
        } => Legacy::Outpost {
            partition: partition.into_boxed_str(),
            region: region.into_boxed_str(),
            account_id: account_id.into_boxed_str(),
            outpost_id: outpost_id.into_boxed_str(),
            key: key.into_boxed_str(),
            version_id: version_id.map(String::into_boxed_str),
        },
    }
}
