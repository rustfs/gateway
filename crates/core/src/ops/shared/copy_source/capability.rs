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

//! The copy-source capability's syntax floor and bounded classification.
//!
//! Responsible for: validating the ARN parser floor and returning only a source class.
//! NOT responsible for: deployment name policy, resource binding, or authorization.
//! Upstream: decoded Copy input. Downstream: the dispatch capability check.

use rustfs_gateway_types::{CopySourceValue, ErrorCode};

use super::CopySourceRejection;
use crate::op::CopySourceKind;

/// Classifies a codec-decoded source, checking the ARN grammar floor first.
/// Deployment name checks remain at resource binding.
pub(crate) fn classify(value: &CopySourceValue) -> Result<CopySourceKind, CopySourceRejection> {
    let (partition, region, account, key, valid_resource) = match value {
        CopySourceValue::Bucket { .. } => return Ok(CopySourceKind::Bucket),
        CopySourceValue::AccessPoint {
            partition,
            region,
            account_id,
            access_point_name,
            key,
            ..
        } => (partition, region, account_id, key, valid_access_point(access_point_name)),
        CopySourceValue::Outpost {
            partition,
            region,
            account_id,
            outpost_id,
            key,
            ..
        } => (partition, region, account_id, key, !outpost_id.is_empty()),
    };
    super::value::check_arn_head(partition, region, account)?;
    if !matches!(partition.as_str(), "aws" | "aws-cn" | "aws-us-gov") || region.is_empty() || !valid_resource {
        return Err(super::unknown_arn());
    }
    if key.is_empty() || key.len() > 1024 {
        return Err(CopySourceRejection::new(
            ErrorCode::INVALID_ARGUMENT,
            "the key named by x-amz-copy-source is not a valid object key",
        ));
    }
    Ok(CopySourceKind::Arn)
}

// The legacy header parser validates the access point independently of deployment name policy.
fn valid_access_point(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfs_gateway_types::ErrorCode;

    fn access_point(account: &str, name: &str, key: &str) -> CopySourceValue {
        CopySourceValue::AccessPoint {
            partition: "aws".into(),
            region: "us-east-1".into(),
            account_id: account.into(),
            access_point_name: name.into(),
            key: key.into(),
            version_id: None,
        }
    }

    fn outpost(account: &str, id: &str, key: &str) -> CopySourceValue {
        CopySourceValue::Outpost {
            partition: "aws".into(),
            region: "us-east-1".into(),
            account_id: account.into(),
            outpost_id: id.into(),
            key: key.into(),
            version_id: Some(String::new()),
        }
    }

    #[test]
    fn classifies_arns_without_applying_deployment_name_policy() {
        for value in [
            access_point("012345678901", "valid", "key"),
            outpost("012345678901", "/accesspoint/", "key"),
        ] {
            assert_eq!(classify(&value), Ok(CopySourceKind::Arn));
        }
        let bucket = CopySourceValue::Bucket {
            bucket: "".into(),
            key: "".into(),
            version_id: None,
        };
        assert_eq!(classify(&bucket), Ok(CopySourceKind::Bucket));
    }

    #[test]
    fn n_invalid_account_is_rejected_before_arn_classification() {
        for account in ["", "123", "12345678901x", "١٢٣٤٥٦", "1234567890123"] {
            for value in [
                access_point(account, "valid", "key"),
                outpost(account, "op/accesspoint/ap", "key"),
            ] {
                assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
            }
        }
    }

    #[test]
    fn n_empty_arn_object_key_is_rejected_before_classification() {
        for value in [
            access_point("123456789012", "valid", ""),
            outpost("123456789012", "op/accesspoint/ap", ""),
        ] {
            assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
        }
    }

    #[test]
    fn n_colons_in_arn_partition_or_region_are_rejected() {
        let mut value = access_point("123456789012", "valid", "key");
        if let CopySourceValue::AccessPoint { partition, .. } = &mut value {
            *partition = "aws:bad".into();
        }
        assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
        let mut value = outpost("123456789012", "op/accesspoint/ap", "key");
        if let CopySourceValue::Outpost { region, .. } = &mut value {
            *region = "us:bad".into();
        }
        assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
    }

    #[test]
    fn n_arn_header_parser_rejects_invalid_partition_or_empty_region() {
        for partition in ["", "other", "AWS", "aws-gov"] {
            let mut value = access_point("123456789012", "valid", "key");
            if let CopySourceValue::AccessPoint { partition: actual, .. } = &mut value {
                *actual = partition.into();
            }
            assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
        }
        let mut value = outpost("123456789012", "op", "key");
        if let CopySourceValue::Outpost { region, .. } = &mut value {
            region.clear();
        }
        assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
    }

    #[test]
    fn n_access_point_parser_rejects_invalid_names() {
        for name in ["", "ab", "Invalid", "-start", "end-", "two--hyphens", "bad.name"] {
            assert!(
                matches!(classify(&access_point("123456789012", name, "key")), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT),
                "{name:?}"
            );
        }
        let long = "a".repeat(64);
        assert!(
            matches!(classify(&access_point("123456789012", &long, "key")), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT)
        );
    }

    #[test]
    fn n_outpost_parser_rejects_empty_id_and_oversized_keys() {
        assert!(
            matches!(classify(&outpost("123456789012", "", "key")), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT)
        );
        for key in ["a".repeat(1025), "é".repeat(513)] {
            for value in [
                access_point("123456789012", "valid", &key),
                outpost("123456789012", "op", &key),
            ] {
                assert!(matches!(classify(&value), Err(error) if error.code() == &ErrorCode::INVALID_ARGUMENT));
            }
        }
    }

    #[test]
    fn arn_head_rejects_colons_directly() {
        assert!(super::super::value::check_arn_head("aws", "us-east-1", "123456789012").is_ok());
        assert!(super::super::value::check_arn_head("aws:bad", "us-east-1", "123456789012").is_err());
        assert!(super::super::value::check_arn_head("aws", "us:east-1", "123456789012").is_err());
    }

    #[test]
    fn access_point_name_boundaries_are_checked() {
        assert!(valid_access_point(&"a".repeat(63)));
        assert!(!valid_access_point(&"a".repeat(64)));
        assert!(!valid_access_point("-abc"));
        assert!(!valid_access_point("abc-"));
        assert!(!valid_access_point("ab--cd"));
    }

    #[test]
    fn valid_legacy_arn_parser_boundaries_are_classified() {
        for partition in ["aws", "aws-cn", "aws-us-gov"] {
            let mut value = access_point("123456789012", "a-b", &"é".repeat(512));
            if let CopySourceValue::AccessPoint { partition: actual, .. } = &mut value {
                *actual = partition.into();
            }
            assert_eq!(classify(&value), Ok(CopySourceKind::Arn));
        }
        assert_eq!(classify(&outpost("123456789012", "/accesspoint/", "key")), Ok(CopySourceKind::Arn));
    }
}
