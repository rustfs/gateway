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
//! `?versionId=`; the unchanged default path grammar; and one leading slash before either ARN
//! form under both naming profiles, with the full source authorization identity preserved.
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
    for account in [
        "١٢٣٤٥٦",
        "١٢٣٤٥٦٧٨٩٠١٢",
        "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}\u{ff18}\u{ff19}\u{ff10}\u{ff11}\u{ff12}",
    ] {
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

/// The optional leading slash also applies to ARN sources, not only bucket/key sources.
/// Evidence: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html.
#[test]
fn arn_leading_slash_preserves_the_authorized_resource_for_both_operations() {
    use rustfs_gateway_types::dto::{UploadPartCopy, UploadPartCopyInput};

    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources("012345678901") {
            let raw = raw.replace("/object/key", "/object/literal%252Fkey");
            for suffix in ["", "?versionId=v%252F1"] {
                let raw = format!("{raw}{suffix}");
                let bare = CopySource::parse_under(&raw, &names).expect("bare ARN");
                let prefixed = format!("/{raw}");
                let parsed = CopySource::parse_under(&prefixed, &names).expect("one leading slash");
                assert_eq!(parsed.resource, bare.resource);
                let identity = match parsed.resource.form {
                    CopySourceForm::AccessPointArn => crate::ResourceIdentity::AccessPoint {
                        partition: "aws".to_owned(),
                        region: "us-east-1".to_owned(),
                        account: "012345678901".to_owned(),
                        name: "my-ap".to_owned(),
                    },
                    CopySourceForm::OutpostsArn => crate::ResourceIdentity::Outposts {
                        partition: "aws".to_owned(),
                        region: "us-east-1".to_owned(),
                        account: "012345678901".to_owned(),
                        outpost_id: "op-1".to_owned(),
                    },
                    CopySourceForm::Path => crate::ResourceIdentity::Path,
                };
                assert_eq!(parsed.resource.identity, identity);
                assert_eq!(parsed.resource.key.as_str(), "literal%2Fkey");
                assert_eq!(parsed.resource.version_id.as_deref(), (!suffix.is_empty()).then_some("v%2F1"));
                assert_eq!(source(&prefixed, &names), source(&raw, &names));
                let input = UploadPartCopyInput {
                    copy_source: prefixed,
                    ..Default::default()
                };
                let decoded = prepare_input_under::<UploadPartCopy>(input, &names).expect("part-copy source");
                let authorized = authorize_input(decoded, |_| Decision::Allow).expect("authorized part-copy source");
                let resolved = authorized
                    .resources()
                    .source()
                    .resolve(authorized.read_proof())
                    .expect("matching proof");
                assert_eq!(resolved.resource, bare.resource);
            }
        }
    }
}

#[test]
fn n_arn_leading_slash_does_not_accept_two_or_more_slashes() {
    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources("123456789012")
            .into_iter()
            .chain(["bucket/key".to_owned()])
        {
            for prefix in ["//", "///"] {
                let error = CopySource::parse_under(&format!("{prefix}{raw}"), &names)
                    .err()
                    .expect("multiple leading slashes");
                assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
            }
        }
    }
}

#[test]
fn n_arn_leading_slash_keeps_malformed_arns_and_versions_refused() {
    for names in [NamePolicy::default(), rustfs()] {
        for raw in [
            "/arn:aws:iam:us-east-1:123456789012:user/name",
            "/arn:aws:s3:us-east-1:12345:accesspoint/my-ap/object/key",
            "/arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/",
            "/arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/key?versionId=",
            "/arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/object/key",
        ] {
            assert_eq!(source(raw, &names), Err(ErrorCode::INVALID_ARGUMENT), "{raw}");
        }
    }
}

#[test]
fn n_arn_leading_slash_cannot_use_a_path_source_proof() {
    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources("123456789012") {
            let bare = CopySource::parse_under(&raw, &names).expect("ARN");
            let path = CopyObjectInput {
                copy_source: format!("{}/key", bare.resource.bucket.as_str()),
                ..Default::default()
            };
            let authorized = authorize_input(prepare_input_under::<CopyObject>(path, &names).expect("path"), |_| Decision::Allow)
                .expect("path proof");
            let arn = CopyObjectInput {
                copy_source: format!("/{raw}"),
                ..Default::default()
            };
            let decoded = prepare_input_under::<CopyObject>(arn, &names).expect("prefixed ARN");
            assert!(decoded.resources().source().resolve(authorized.read_proof()).is_none());
        }
    }
}

#[test]
fn n_arn_leading_slash_does_not_reuse_another_arn_identity_proof() {
    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources("123456789012") {
            let input = CopyObjectInput {
                copy_source: raw.clone(),
                ..Default::default()
            };
            let authorized =
                authorize_input(prepare_input_under::<CopyObject>(input, &names).expect("bare ARN"), |_| Decision::Allow)
                    .expect("source proof");
            for changed in [
                raw.replace("arn:aws:", "arn:aws-cn:"),
                raw.replace("us-east-1", "us-west-2"),
                raw.replace("123456789012", "012345678901"),
                raw.replace("my-ap", "other-ap").replace("op-1", "op-2"),
            ] {
                let input = CopyObjectInput {
                    copy_source: format!("/{changed}"),
                    ..Default::default()
                };
                let decoded = prepare_input_under::<CopyObject>(input, &names).expect("other ARN");
                assert!(decoded.resources().source().resolve(authorized.read_proof()).is_none());
            }
        }
    }
}

#[test]
fn n_arn_leading_slash_does_not_reuse_another_version_proof() {
    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources("123456789012") {
            let input = CopyObjectInput {
                copy_source: format!("{raw}?versionId=v1"),
                ..Default::default()
            };
            let authorized = authorize_input(prepare_input_under::<CopyObject>(input, &names).expect("version one"), |_| {
                Decision::Allow
            })
            .expect("source proof");
            let input = CopyObjectInput {
                copy_source: format!("/{raw}?versionId=v2"),
                ..Default::default()
            };
            let decoded = prepare_input_under::<CopyObject>(input, &names).expect("version two");
            assert!(decoded.resources().source().resolve(authorized.read_proof()).is_none());
        }
    }
}

#[test]
fn n_arn_leading_slash_cannot_skip_source_denial() {
    for names in [NamePolicy::default(), rustfs()] {
        for raw in arn_account_sources("123456789012") {
            for suffix in ["", "?versionId=v1"] {
                let input = CopyObjectInput {
                    copy_source: format!("/{raw}{suffix}"),
                    ..Default::default()
                };
                let decoded = prepare_input_under::<CopyObject>(input, &names).expect("prefixed ARN");
                let mut reads = 0;
                let error = authorize_input(decoded, |resource| {
                    if resource.action() == "s3:GetObject" || resource.action() == "s3:GetObjectVersion" {
                        reads += 1;
                        Decision::Deny
                    } else {
                        Decision::Allow
                    }
                })
                .err()
                .expect("source denied");
                assert_eq!(reads, 1);
                assert_eq!(error.decision(), Decision::Deny);
            }
        }
    }
}
