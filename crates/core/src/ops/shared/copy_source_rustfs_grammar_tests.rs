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

//! A copy source's bucket and version under the RustFS profile's path addressing
//! (rustfs/gateway#1115): legacy RustFS's bucket rules, and its split at the first `?versionId=`.
//!
//! Responsible for: pinning, to legacy RustFS's answers on a legacy build, a source in a bucket
//! the AWS rules reserve, a source key holding a `?`, and the version after the first
//! `?versionId=`; and the default grammar being untouched.
//! NOT responsible for: the source key's floor (`copy_source_rustfs_tests.rs`) or the default
//! grammar's own cases (`copy_source_tests.rs`).
//! Upstream: `super`. Downstream: nothing.

use std::sync::Arc;

use rustfs_gateway_types::dto::{CopyObject, CopyObjectInput};
use rustfs_gateway_types::{LegacyRustfsNameValidator, NamePolicy, SlashPolicy};

use super::*;
use crate::Decision;
use crate::authz::{authorize_input, prepare_input_under};

/// The RustFS profile's naming: the slash rule, the key floor and the path addressing.
fn rustfs() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
        .with_legacy_rustfs_path_split()
        .with_validator(Arc::new(LegacyRustfsNameValidator))
}

/// The bucket, key and version `CopyObject` resolves for `raw` under `names`, or the code.
fn source(raw: &str, names: &NamePolicy) -> Result<(String, String, Option<String>), ErrorCode> {
    let input = CopyObjectInput {
        copy_source: raw.to_owned(),
        ..Default::default()
    };
    let decoded = prepare_input_under::<CopyObject>(input, names).map_err(|error| error.code().clone())?;
    let authorized = authorize_input(decoded, |_| Decision::Allow).expect("authorized");
    let source = authorized
        .resources()
        .source()
        .resolve(authorized.read_proof())
        .expect("the proof covers it");
    Ok((
        source.bucket().as_str().to_owned(),
        source.key().as_str().to_owned(),
        source.version_id().map(str::to_owned),
    ))
}

fn found(bucket: &str, key: &str, version: Option<&str>) -> Result<(String, String, Option<String>), ErrorCode> {
    Ok((bucket.to_owned(), key.to_owned(), version.map(str::to_owned)))
}

/// Positive — a source in a bucket legacy RustFS created under a reserved prefix or suffix.
#[test]
fn a_bucket_the_aws_rules_reserve_is_a_copy_source() {
    assert_eq!(source("sthree-x/obj", &rustfs()), found("sthree-x", "obj", None));
    assert_eq!(source("/abc-s3alias/obj", &rustfs()), found("abc-s3alias", "obj", None));
}

/// Positive — a `?` that does not begin `versionId=` is key bytes, and the version is what follows
/// the first `?versionId=`.
#[test]
fn a_question_mark_is_key_bytes_until_the_first_version() {
    assert_eq!(source("src/obj?partNumber=1", &rustfs()), found("src", "obj?partNumber=1", None));
    assert_eq!(source("src/a?b?versionId=v1", &rustfs()), found("src", "a?b", Some("v1")));
    assert_eq!(source("src/a?versionId=v?x", &rustfs()), found("src", "a", Some("v?x")));
    assert_eq!(source("src/a?versionId=a%2Fb", &rustfs()), found("src", "a", Some("a/b")));
}

/// Negative — what legacy RustFS refuses as a copy source is still refused, `InvalidArgument`.
#[test]
fn n_a_source_legacy_rustfs_refuses_is_refused() {
    for raw in [
        "Bad_Bucket/obj",
        "1.2.3.4/obj",
        "xn--abc/obj",
        "src",
        "/src",
        "//src/obj",
        "src/obj?versionId=",
    ] {
        assert_eq!(source(raw, &rustfs()), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
    }
}

/// Negative — without the path addressing the grammar is the default one, exactly.
#[test]
fn n_the_default_grammar_is_untouched() {
    let default = NamePolicy::default();
    assert_eq!(source("sthree-x/obj", &default), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(source("src/obj?partNumber=1", &default), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(source("src/a?b?versionId=v1", &default), found("src", "a?b", Some("v1")));
    assert_eq!(source("src/a?versionId=v?x", &default), Err(ErrorCode::INVALID_ARGUMENT));
}

/// AWS account identifiers are twelve ASCII decimal digits in either ARN form.
/// Evidence: <https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html>.
fn arn_account_sources(account: &str) -> [String; 2] {
    [
        format!("arn:aws:s3:us-east-1:{account}:accesspoint/my-ap/object/key"),
        format!("arn:aws:s3-outposts:us-east-1:{account}:outpost/op-1/bucket/src-bucket/object/key"),
    ]
}

fn assert_account_refused(account: &str) {
    use rustfs_gateway_types::dto::{UploadPartCopy, UploadPartCopyInput};

    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources(account) {
            for suffix in ["", "?versionId=v1"] {
                let raw = format!("{raw}{suffix}");
                assert_eq!(source(&raw, &names), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
                let input = UploadPartCopyInput {
                    copy_source: raw.clone(),
                    ..Default::default()
                };
                let error = prepare_input_under::<UploadPartCopy>(input, &names)
                    .err()
                    .expect("an invalid account cannot reach source authorization or a handler");
                assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT, "{raw}");
            }
        }
    }
}

#[test]
fn n_arn_accounts_must_have_twelve_digits() {
    for account in ["", "1", "12345", "12345678901", "1234567890123"] {
        assert_account_refused(account);
    }
}

#[test]
fn n_arn_accounts_refuse_non_decimal_ascii() {
    for account in ["a23456789012", "12345678901z", "+23456789012", "12345678901 ", "12345-789012"] {
        assert_account_refused(account);
    }
}

#[test]
fn n_arn_accounts_refuse_unicode_digits() {
    // Six two-byte digits have the expected byte length but are not ASCII account digits.
    for account in ["١٢٣٤٥٦", "١٢٣٤٥٦٧٨٩٠١٢", "１２３４５６７８９０１２"] {
        assert_account_refused(account);
    }
}

#[test]
fn arn_accounts_keep_leading_zeroes_and_full_identity() {
    for names in [NamePolicy::default(), rustfs()] {
        for account in ["012345678901", "123456789012"] {
            for raw in arn_account_sources(account) {
                let parsed = CopySource::parse_under(&raw, &names).expect("a twelve-digit account");
                let actual = match &parsed.resource.identity {
                    crate::ResourceIdentity::AccessPoint { account: actual, .. }
                    | crate::ResourceIdentity::Outposts { account: actual, .. } => Some(actual.as_str()),
                    _ => None,
                };
                assert_eq!(actual, Some(account));
                assert!(source(&raw, &names).is_ok());
            }
        }
    }
}
