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

//! IfExists equality operators in the reference bucket-policy evaluator.
//!
//! Responsible for: missing/present key semantics, deny precedence and invalid-block fences.
//! NOT responsible for: adding condition keys or native RustFS policy validation.
//! Upstream: `super::BucketPolicy`; downstream: the served policy authorizer.

use super::{BucketPolicy, PolicyRequest, RequestFacts};
use serde_json::{Value, json};

fn verdict(effect: &str, condition: Value, facts: RequestFacts<'_>) -> bool {
    let document = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": effect, "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::policy-test/*", "Condition": condition
    }]})
    .to_string();
    let policy = BucketPolicy::parse(&document).expect("a policy with a valid statement shape");
    policy.allows_with_facts(
        PolicyRequest {
            account: if effect == "Deny" { Some("owner") } else { None },
            is_owner: effect == "Deny",
            action: "s3:GetObject",
            bucket: "policy-test",
            key: Some("object"),
        },
        facts,
    )
}

fn facts<'a>(key: &str, value: Option<&'a str>) -> RequestFacts<'a> {
    if key == "s3:x-amz-acl" {
        RequestFacts {
            acl: value,
            ..Default::default()
        }
    } else {
        RequestFacts {
            server_side_encryption: value,
            ..Default::default()
        }
    }
}

const KEYS: [(&str, &str, &str); 2] = [
    ("s3:x-amz-acl", "private", "public-read"),
    ("s3:x-amz-server-side-encryption", "AES256", "aws:kms"),
];

/// Positive: either equality operator with IfExists matches an absent key for an Allow.
#[test]
fn missing_keys_satisfy_ifexists_allows() {
    for operator in ["StringEqualsIfExists", "StringNotEqualsIfExists"] {
        for (key, wanted, _) in KEYS {
            assert!(verdict("Allow", json!({operator: {key: wanted}}), facts(key, None)), "{operator} {key}");
        }
    }
}

/// Negative: the same missing keys must not bypass an explicit Deny, even for the owner.
#[test]
fn n_missing_keys_satisfy_ifexists_denies() {
    for operator in ["StringEqualsIfExists", "StringNotEqualsIfExists"] {
        for (key, wanted, _) in KEYS {
            assert!(!verdict("Deny", json!({operator: {key: wanted}}), facts(key, None)), "{operator} {key}");
        }
    }
}

/// Negative: present keys still compare values; IfExists cannot become an unconditional match.
#[test]
fn n_present_values_keep_equality_and_negation() {
    for (operator, equal_matches) in [("StringEqualsIfExists", true), ("StringNotEqualsIfExists", false)] {
        for (key, wanted, different) in KEYS {
            for (value, matches) in [(wanted, equal_matches), (different, !equal_matches)] {
                let condition = json!({operator: {key: wanted}});
                assert_eq!(
                    verdict("Allow", condition.clone(), facts(key, Some(value))),
                    matches,
                    "{operator} {key} {value}"
                );
                assert_eq!(verdict("Deny", condition, facts(key, Some(value))), !matches, "{operator} {key} {value}");
            }
        }
    }
}

/// Positive: a list remains OR for equality and NOR for its negation.
#[test]
fn list_values_keep_the_existing_string_operator_rules() {
    for (operator, matches) in [("StringEqualsIfExists", true), ("StringNotEqualsIfExists", false)] {
        for value in ["private", "public-read"] {
            assert_eq!(
                verdict(
                    "Allow",
                    json!({operator: {"s3:x-amz-acl": ["private", "public-read"]}}),
                    facts("s3:x-amz-acl", Some(value))
                ),
                matches
            );
        }
    }
}

/// Negative: empty, wildcard-looking and differently cased strings are values, not missing keys.
#[test]
fn n_present_strings_are_compared_literally() {
    for value in ["", "PRIVATE", "priv*", "priv?te"] {
        assert!(
            !verdict(
                "Allow",
                json!({"StringEqualsIfExists": {"s3:x-amz-acl": "private"}}),
                facts("s3:x-amz-acl", Some(value))
            ),
            "{value}"
        );
    }
    assert!(verdict(
        "Allow",
        json!({"StringEqualsIfExists": {"s3:x-amz-acl": ""}}),
        facts("s3:x-amz-acl", Some(""))
    ));
}

/// Negative: satisfying one absent key cannot discard another clause in the same block.
#[test]
fn n_ifexists_clauses_still_combine_with_and() {
    let condition = json!({"StringEqualsIfExists": {"s3:x-amz-acl": "private", "s3:x-amz-server-side-encryption": "AES256"}});
    for effect in ["Allow", "Deny"] {
        assert_eq!(
            verdict(
                effect,
                condition.clone(),
                RequestFacts {
                    server_side_encryption: Some("aws:kms"),
                    ..Default::default()
                }
            ),
            effect == "Deny"
        );
        assert_eq!(
            verdict(
                effect,
                condition.clone(),
                RequestFacts {
                    server_side_encryption: Some("AES256"),
                    ..Default::default()
                }
            ),
            effect == "Allow"
        );
    }
}

/// Negative: unsupported keys, bad operands and unimplemented spellings keep the entire fence.
#[test]
fn n_unsupported_ifexists_blocks_remain_unsupported() {
    let mut conditions = vec![
        json!({"NullIfExists": {"s3:x-amz-acl": true}}),
        json!({"stringequalsifexists": {"s3:x-amz-acl": "private"}}),
        json!({"StringLikeIfExists": {"s3:x-amz-acl": "priv*"}}),
        json!({"StringEqualsIfExists": {"s3:x-amz-acl": "private", "s3:unknown": "value"}}),
    ];
    for operator in ["StringEqualsIfExists", "StringNotEqualsIfExists"] {
        for value in [
            json!([]),
            json!(["private", 1]),
            json!(false),
            json!(1),
            Value::Null,
            json!({}),
        ] {
            conditions.push(json!({operator: {"s3:x-amz-acl": value}}));
        }
        conditions.push(json!({operator: {}}));
    }
    for condition in conditions {
        for value in [None, Some("private")] {
            assert!(!verdict("Allow", condition.clone(), facts("s3:x-amz-acl", value)), "{condition}");
            assert!(verdict("Deny", condition.clone(), facts("s3:x-amz-acl", value)), "{condition}");
        }
    }
}

/// Negative: adding IfExists must not change the existing non-suffixed operators' missing case.
#[test]
fn n_ordinary_equality_still_distinguishes_a_missing_key() {
    assert!(!verdict(
        "Allow",
        json!({"StringEquals": {"s3:x-amz-acl": "private"}}),
        RequestFacts::default()
    ));
    assert!(verdict(
        "Allow",
        json!({"StringNotEquals": {"s3:x-amz-acl": "private"}}),
        RequestFacts::default()
    ));
}
