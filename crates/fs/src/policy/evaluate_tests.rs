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

//! The evaluator's rules, one at a time.
//!
//! Responsible for: the statement validity rules, the `Deny`-then-owner-then-`Allow` order, the
//! principal, action and resource matching, the condition fence and the wildcard grammar.
//! NOT responsible for: the storage handlers, which `tests/crud/bucket_policy.rs` drives.
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used)]

use super::{BucketPolicy, PolicyRequest, PolicyShapeError, RequestFacts, glob};

const PUBLIC_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::pub/*"}]}"#;

fn read(account: Option<&'static str>, is_owner: bool, key: &'static str) -> PolicyRequest<'static> {
    PolicyRequest {
        account,
        is_owner,
        action: "s3:GetObject",
        bucket: "pub",
        key: Some(key),
    }
}

/// Positive — the public-read shape every suite writes: anyone may read an object under the bucket.
#[test]
fn a_public_read_statement_grants_an_anonymous_object_read() {
    let policy = BucketPolicy::parse(PUBLIC_READ).expect("a valid policy");
    assert!(policy.allows(read(None, false, "any")));
    assert!(policy.allows(read(Some("alt"), false, "any")));
    assert!(policy.grants_everyone());
}

/// Negative — the same statement grants nothing outside its action or resource: a write, a
/// bucket-level action and another bucket's object are all refused to the anonymous caller.
#[test]
fn n_a_grant_is_bounded_by_its_action_and_resource() {
    let policy = BucketPolicy::parse(PUBLIC_READ).expect("a valid policy");
    assert!(!policy.allows(PolicyRequest {
        action: "s3:PutObject",
        ..read(None, false, "any")
    }));
    assert!(!policy.allows(PolicyRequest {
        action: "s3:ListBucket",
        key: None,
        ..read(None, false, "")
    }));
    assert!(!policy.allows(PolicyRequest {
        bucket: "other",
        ..read(None, false, "any")
    }));
}

/// Negative — a `Deny` is consulted first and binds the owner too; the owner is otherwise allowed
/// with no `Allow` at all, and a stranger is not (RustFS's `BucketPolicy::is_allowed`).
#[test]
fn n_deny_binds_the_owner_and_the_owner_needs_no_allow() {
    let deny = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::pub/*"},
        {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/secret"}]}"#;
    let policy = BucketPolicy::parse(deny).expect("a valid policy");
    assert!(
        !policy.allows(read(Some("owner"), true, "secret")),
        "the owner is denied what a Deny names"
    );
    assert!(policy.allows(read(Some("owner"), true, "open")));
    assert!(!policy.allows(read(None, false, "secret")));
    assert!(policy.allows(read(None, false, "open")));

    let empty = r#"{"Version":"2012-10-17","Statement":[]}"#;
    let policy = BucketPolicy::parse(empty).expect("a valid policy");
    assert!(policy.allows(read(Some("owner"), true, "any")), "the owner needs no Allow");
    assert!(!policy.allows(read(Some("alt"), false, "any")));
    assert!(!policy.allows(read(None, false, "any")));
}

/// Negative — a named principal matches its account and nobody else; the anonymous caller
/// matches only `*`, in either spelling.
#[test]
fn n_a_named_principal_is_the_account_and_not_the_public() {
    let named = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["alt-account"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;
    let policy = BucketPolicy::parse(named).expect("a valid policy");
    assert!(policy.allows(read(Some("alt-account"), false, "k")));
    assert!(!policy.allows(read(Some("other-account"), false, "k")));
    assert!(!policy.allows(read(None, false, "k")));
    assert!(!policy.grants_everyone());

    let aws_star = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;
    let policy = BucketPolicy::parse(aws_star).expect("a valid policy");
    assert!(policy.allows(read(None, false, "k")));
    assert!(policy.grants_everyone());

    let deny_everyone = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;
    assert!(
        !BucketPolicy::parse(deny_everyone).expect("a valid policy").grants_everyone(),
        "a Deny naming everyone grants nobody anything; the block has nothing to refuse"
    );
}

/// Negative — a conditioned statement neither grants nor denies: the condition language is not
/// evaluated here, and the fence is written down rather than guessed.
#[test]
fn n_a_conditioned_statement_grants_and_denies_nothing() {
    let conditioned = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*",
         "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},
        {"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*",
         "Condition":{"StringNotEquals":{"s3:x-amz-grant-read":"id=owner"}}}]}"#;
    let policy = BucketPolicy::parse(conditioned).expect("a valid policy");
    assert!(!policy.allows(read(None, false, "k")), "a conditioned Allow grants nothing");
    assert!(policy.allows(read(Some("owner"), true, "k")), "a conditioned Deny denies nothing");
    let empty_condition = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*","Condition":{}}]}"#;
    assert!(
        BucketPolicy::parse(empty_condition)
            .expect("valid")
            .allows(read(None, false, "k")),
        "an empty Condition is no condition"
    );
}

/// Negative — RustFS's `is_valid` rules, each refused by name: a foreign version, a missing
/// statement array, an effect outside the pair, a missing principal, both or neither of
/// Action/NotAction, both or neither of Resource/NotResource, and a member of the wrong type.
#[test]
fn n_the_statement_rules_are_rustfs_own() {
    let cases: [(&str, PolicyShapeError); 9] = [
        (r#"{"Version":"2008-10-17","Statement":[]}"#, PolicyShapeError::Version),
        (r#"{"Version":"2012-10-17"}"#, PolicyShapeError::Statements),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":"*","Action":"s3:*","Resource":"*"}]}"#,
            PolicyShapeError::Effect,
        ),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
            PolicyShapeError::Principal,
        ),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"x"},"Action":"s3:*","Resource":"*"}]}"#,
            PolicyShapeError::Principal,
        ),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Resource":"*"}]}"#,
            PolicyShapeError::Action,
        ),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","NotAction":"s3:GetObject","Resource":"*"}]}"#,
            PolicyShapeError::Action,
        ),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*"}]}"#,
            PolicyShapeError::Resource,
        ),
        (
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":42,"Resource":"*"}]}"#,
            PolicyShapeError::Member,
        ),
    ];
    for (document, expected) in cases {
        assert_eq!(BucketPolicy::parse(document).err(), Some(expected), "{document}");
    }
    let single_statement_object = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}}"#;
    assert!(
        BucketPolicy::parse(single_statement_object).is_ok(),
        "one statement may be an object rather than a list"
    );
    let versionless =
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;
    assert!(
        BucketPolicy::parse(versionless).is_ok(),
        "an absent Version is accepted, as RustFS accepts an empty one"
    );
}

/// Negative — `NotAction` and `NotResource` are complements, not aliases: they match what the
/// named patterns do not.
#[test]
fn n_not_action_and_not_resource_are_complements() {
    let policy = BucketPolicy::parse(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:Delete*","NotResource":"arn:aws:s3:::pub/private/*"}]}"#,
    )
    .expect("a valid policy");
    assert!(policy.allows(read(None, false, "open")));
    assert!(!policy.allows(PolicyRequest {
        action: "s3:DeleteObject",
        ..read(None, false, "open")
    }));
    assert!(!policy.allows(read(None, false, "private/x")));
}

/// The wildcard grammar at its edges: `*` any run including none, `?` exactly one, literals
/// exact, and a trailing `*` matching the empty tail.
#[test]
fn n_the_wildcard_grammar_holds_its_edges() {
    for (pattern, text, expected) in [
        ("s3:*", "s3:GetObject", true),
        ("s3:Get*", "s3:GetObject", true),
        ("s3:Get*", "s3:PutObject", false),
        ("s3:GetObjec?", "s3:GetObject", true),
        ("s3:GetObjec?", "s3:GetObjects", false),
        ("arn:aws:s3:::pub/*", "arn:aws:s3:::pub/", true),
        ("arn:aws:s3:::pub/*", "arn:aws:s3:::pub", false),
        ("arn:aws:s3:::pub", "arn:aws:s3:::pub", true),
        ("arn:aws:s3:::pub", "arn:aws:s3:::public", false),
        ("*", "", true),
        ("a*b*c", "axxbyyc", true),
        ("a*b*c", "axxbyy", false),
    ] {
        assert_eq!(glob(pattern, text), expected, "{pattern} vs {text}");
    }
}

const PUT_DENY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::pub/*","Condition":CONDITION}]}"#;

fn put_verdict(condition: &str, sse: Option<&str>) -> bool {
    let policy = BucketPolicy::parse(&PUT_DENY.replace("CONDITION", condition)).expect("a valid policy");
    policy.allows_with_facts(
        PolicyRequest {
            action: "s3:PutObject",
            ..read(Some("owner"), true, "k")
        },
        RequestFacts {
            acl: None,
            server_side_encryption: sse,
        },
    )
}

/// Negative — `Null` on the encryption key: `true` denies only an absent header, `false` only a
/// present one; `"true"` and `true` are the same value (rustfs/gateway#979).
#[test]
fn n_null_matches_absence_or_presence() {
    for spelled in [
        r#"{"Null":{"s3:x-amz-server-side-encryption":"true"}}"#,
        r#"{"Null":{"s3:x-amz-server-side-encryption":true}}"#,
    ] {
        assert!(!put_verdict(spelled, None), "{spelled}");
        assert!(put_verdict(spelled, Some("AES256")), "{spelled}");
    }
    let present = r#"{"Null":{"s3:x-amz-server-side-encryption":"false"}}"#;
    assert!(put_verdict(present, None));
    assert!(!put_verdict(present, Some("aws:kms")));
}

/// Negative — `StringNotEquals` matches another value and an absent header; `StringEquals` only
/// the named value.
#[test]
fn n_string_operators_on_the_encryption_key() {
    let not_aes = r#"{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}}"#;
    assert!(!put_verdict(not_aes, Some("aws:kms")));
    assert!(!put_verdict(not_aes, None));
    assert!(put_verdict(not_aes, Some("AES256")));
    let kms = r#"{"StringEquals":{"s3:x-amz-server-side-encryption":["aws:kms","aws:kms:dsse"]}}"#;
    assert!(!put_verdict(kms, Some("aws:kms")));
    assert!(put_verdict(kms, Some("AES256")));
    assert!(put_verdict(kms, None));
}

/// Negative — an unreadable value keeps the whole block unsupported, so the Deny denies nothing.
#[test]
fn n_unreadable_condition_values_stay_unsupported() {
    for block in [
        r#"{"Null":{"s3:x-amz-server-side-encryption":"maybe"}}"#,
        r#"{"StringEquals":{"s3:x-amz-server-side-encryption":[]}}"#,
        r#"{"StringEquals":{}}"#,
        r#"{"StringLike":{"s3:x-amz-server-side-encryption":"AES*"}}"#,
        r#"{"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms"},"Null":{"s3:x-amz-grant-read":"false"}}"#,
    ] {
        assert!(put_verdict(block, Some("aws:kms")), "{block}");
        assert!(put_verdict(block, None), "{block}");
    }
}
