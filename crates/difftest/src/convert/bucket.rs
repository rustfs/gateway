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

//! Bucket output conversions: CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation (the
//! production seam), GetBucketVersioning, PutBucketVersioning.
//!
//! Responsible for: destructuring each pinned s3s output with no `..` and building the gateway
//! output, refusing by name an s3s-only member that is set. GetBucketLocation's seam conversion
//! is total: every location converts.
//! NOT responsible for: encoding, or object outputs.
//! Upstream: `convert/mod.rs` helpers. Downstream: the operation table.

use rustfs_gateway_types::dto;

use super::{Converted, absent, enumeration, required};
use crate::s3s::dto as oracle;

/// CreateBucket.
pub(crate) fn create_bucket(output: oracle::CreateBucketOutput) -> Converted<dto::CreateBucketOutput> {
    let oracle::CreateBucketOutput { bucket_arn, location } = output;
    absent("bucket_arn", bucket_arn.as_ref())?;
    Ok(dto::CreateBucketOutput { location })
}

/// DeleteBucket.
pub(crate) fn delete_bucket(output: oracle::DeleteBucketOutput) -> Converted<dto::DeleteBucketOutput> {
    let oracle::DeleteBucketOutput {} = output;
    Ok(dto::DeleteBucketOutput {})
}

/// HeadBucket.
pub(crate) fn head_bucket(output: oracle::HeadBucketOutput) -> Converted<dto::HeadBucketOutput> {
    let oracle::HeadBucketOutput {
        access_point_alias,
        bucket_arn,
        bucket_location_name,
        bucket_location_type,
        bucket_region,
    } = output;
    absent("access_point_alias", access_point_alias.as_ref())?;
    absent("bucket_arn", bucket_arn.as_ref())?;
    absent("bucket_location_name", bucket_location_name.as_ref())?;
    absent("bucket_location_type", bucket_location_type.as_ref())?;
    Ok(dto::HeadBucketOutput {
        bucket_region: required("bucket_region", bucket_region)?,
    })
}

/// GetBucketLocation: the production seam RustFS will run.
pub(crate) fn get_bucket_location(output: oracle::GetBucketLocationOutput) -> Converted<dto::GetBucketLocationOutput> {
    Ok(rustfs_gateway_types::compat::s3s_0_17_0::get_bucket_location::output_from_s3s(output))
}

/// GetBucketVersioning.
pub(crate) fn get_bucket_versioning(output: oracle::GetBucketVersioningOutput) -> Converted<dto::GetBucketVersioningOutput> {
    let oracle::GetBucketVersioningOutput { mfa_delete, status } = output;
    Ok(dto::GetBucketVersioningOutput {
        status: enumeration(status),
        mfa_delete: enumeration(mfa_delete),
    })
}

/// PutBucketVersioning.
pub(crate) fn put_bucket_versioning(output: oracle::PutBucketVersioningOutput) -> Converted<dto::PutBucketVersioningOutput> {
    let oracle::PutBucketVersioningOutput {} = output;
    Ok(dto::PutBucketVersioningOutput {})
}
