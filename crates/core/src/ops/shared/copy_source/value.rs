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

//! Decoded Copy input values at the existing resource and proof boundary.
//!
//! Responsible for: decoding caller-owned text, binding decoded fields and erasing the input.
//! NOT responsible for: exposing stored resources without a proof or deciding authorization.
//! Upstream: generated Copy codecs and operation inputs. Downstream: source-resource derivation.

use rustfs_gateway_types::{CopySourceValue, ErrorCode, NamePolicy, PathSplit};

use super::{
    CopySource, CopySourceForm, CopySourceRejection, SourceResource, bucket_of, decoded_key, non_empty, path_bucket_of,
    unknown_arn,
};
use crate::{CodecError, ResourceIdentity};

pub(crate) fn decode_value(raw: &str, names: &NamePolicy) -> Result<CopySourceValue, CodecError> {
    super::parse_value_under(raw, names).map_err(|error| CodecError::new(error.code().clone(), error.reason()))
}

pub(super) fn bind_value(value: &CopySourceValue, names: &NamePolicy) -> Result<CopySource, CopySourceRejection> {
    let version_id = match value {
        CopySourceValue::Bucket { version_id, .. }
        | CopySourceValue::AccessPoint { version_id, .. }
        | CopySourceValue::Outpost { version_id, .. } => version_id,
    };
    if names.path_split() != PathSplit::RustfsLegacy && version_id.as_deref() == Some("") {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the versionId of x-amz-copy-source must not be empty",
        ));
    }
    let resource = match value {
        CopySourceValue::Bucket { bucket, key, .. } => SourceResource {
            form: CopySourceForm::Path,
            container: None,
            identity: ResourceIdentity::Path,
            bucket: Some(path_bucket_of(bucket, names)?),
            key: decoded_key(key, names)?,
            version_id: version_id.clone(),
        },
        CopySourceValue::AccessPoint {
            partition,
            region,
            account_id,
            access_point_name,
            key,
            ..
        } => {
            check_arn_head(partition, region, account_id)?;
            SourceResource {
                form: CopySourceForm::AccessPointArn,
                container: Some(non_empty(access_point_name)?.to_owned()),
                identity: ResourceIdentity::AccessPoint {
                    partition: non_empty(partition)?.to_owned(),
                    region: non_empty(region)?.to_owned(),
                    account: non_empty(account_id)?.to_owned(),
                    name: non_empty(access_point_name)?.to_owned(),
                },
                bucket: Some(bucket_of(access_point_name)?),
                key: decoded_key(key, names)?,
                version_id: version_id.clone(),
            }
        }
        CopySourceValue::Outpost {
            partition,
            region,
            account_id,
            outpost_id,
            key,
            ..
        } => {
            check_arn_head(partition, region, account_id)?;
            // The carrier retains the legacy Outpost component, including its optional bucket.
            let (outpost, bucket) = match outpost_id.split_once('/') {
                None => (outpost_id.as_str(), None),
                Some((outpost, suffix)) => {
                    let bucket = suffix.strip_prefix("bucket/").ok_or_else(unknown_arn)?;
                    (outpost, Some(bucket_of(bucket)?))
                }
            };
            SourceResource {
                form: CopySourceForm::OutpostsArn,
                container: Some(non_empty(outpost)?.to_owned()),
                identity: ResourceIdentity::Outposts {
                    partition: non_empty(partition)?.to_owned(),
                    region: non_empty(region)?.to_owned(),
                    account: non_empty(account_id)?.to_owned(),
                    outpost_id: non_empty(outpost)?.to_owned(),
                },
                bucket,
                key: decoded_key(key, names)?,
                version_id: version_id.clone(),
            }
        }
    };
    Ok(CopySource { resource })
}

// AWS account IDs are twelve ASCII decimal digits, including leading zeroes.
// https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html
fn check_arn_head(partition: &str, region: &str, account: &str) -> Result<(), CopySourceRejection> {
    if !partition.contains(':')
        && !region.contains(':')
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(unknown_arn())
    }
}

pub(crate) fn seal_value(value: &mut CopySourceValue) {
    match value {
        CopySourceValue::Bucket { bucket, key, version_id } => {
            bucket.clear();
            key.clear();
            *version_id = None;
        }
        CopySourceValue::AccessPoint {
            partition,
            region,
            account_id,
            access_point_name,
            key,
            version_id,
        } => {
            partition.clear();
            region.clear();
            account_id.clear();
            access_point_name.clear();
            key.clear();
            *version_id = None;
        }
        CopySourceValue::Outpost {
            partition,
            region,
            account_id,
            outpost_id,
            key,
            version_id,
        } => {
            partition.clear();
            region.clear();
            account_id.clear();
            outpost_id.clear();
            key.clear();
            *version_id = None;
        }
    }
}

#[cfg(test)]
fn prepare_wire<O: crate::Operation>(
    raw: &str,
    names: &NamePolicy,
    make_input: impl FnOnce(CopySourceValue) -> O::Input,
) -> Result<crate::authz::Decoded<O>, crate::DerivedResourceError> {
    let value =
        decode_value(raw, names).map_err(|error| crate::DerivedResourceError::new(error.code().clone(), error.message()))?;
    crate::authz::prepare_input_under::<O>(make_input(value), names)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn prepare_copy(
    raw: &str,
    names: &NamePolicy,
) -> Result<crate::authz::Decoded<rustfs_gateway_types::dto::CopyObject>, crate::DerivedResourceError> {
    prepare_wire(raw, names, |source| rustfs_gateway_types::dto::CopyObjectInput::builder(source).build())
}

#[cfg(test)]
pub(super) fn prepare_part_copy(
    raw: &str,
    names: &NamePolicy,
) -> Result<crate::authz::Decoded<rustfs_gateway_types::dto::UploadPartCopy>, crate::DerivedResourceError> {
    prepare_wire(raw, names, |source| {
        rustfs_gateway_types::dto::UploadPartCopyInput::builder(source).build()
    })
}

#[cfg(test)]
pub(super) fn source_erased(value: &CopySourceValue) -> bool {
    match value {
        CopySourceValue::Bucket { bucket, key, version_id } => bucket.is_empty() && key.is_empty() && version_id.is_none(),
        CopySourceValue::AccessPoint {
            partition,
            region,
            account_id,
            access_point_name,
            key,
            version_id,
        } => {
            [partition, region, account_id, access_point_name, key]
                .into_iter()
                .all(String::is_empty)
                && version_id.is_none()
        }
        CopySourceValue::Outpost {
            partition,
            region,
            account_id,
            outpost_id,
            key,
            version_id,
        } => {
            [partition, region, account_id, outpost_id, key]
                .into_iter()
                .all(String::is_empty)
                && version_id.is_none()
        }
    }
}
