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

//! The shared ACL contract: two wire channels, one grammar, one derivation of `xsi:type`.
//!
//! Responsible for: every observable behaviour of `ops::shared::acl` — the mutual exclusion of
//! the body and header channels, the two canned-ACL sets and the difference between them, the
//! `x-amz-grant-*` grammar and its ceilings, the closed `Permission` set, and the derivation of
//! the `<Grantee>` discriminator. 10 positive / 12 negative.
//! NOT responsible for: the XML wire form (generated codecs), what a backend stores, or whether
//! any of the grants below actually permit anything — this family deliberately evaluates nothing.
//! Upstream: `rustfs_gateway_core::ops::shared::acl`. Downstream: nothing.
//!
//! Held out of the module itself only because the two together are over the 800-line ceiling, and
//! the tests are the half a reader can skip; `tagging_contract.rs` is the same arrangement.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_core::ops::shared::acl::{
    ALL_USERS_GROUP, AclHeaders, AclInput, AclRejection, AclTarget, BUCKET_CANNED_ACLS, GranteeType, MAX_GRANT_HEADER_BYTES,
    MAX_GRANTEES_PER_HEADER, OBJECT_CANNED_ACLS, PERMISSIONS, canonicalize_policy, parse_canned, parse_grant_header,
    resolve_grantee_type, resolve_input,
};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{AccessControlPolicy, Grant, Grantee, Owner, Permission, Type};

/// A plausible identity for the negative cases; asserted absent from every reason.
const CANONICAL_ID: &str = "3f6e2b1c4a8d90e7b5c31f2a6d80e4c97b1a3d5f8e206c4b7a9d1e3f5c7b9a0d";
const EMAIL: &str = "grantee@example.com";

fn canonical_grantee() -> Grantee {
    Grantee {
        id: Some(CANONICAL_ID.to_owned()),
        r#type: Some(Type::CANONICALUSER),
        ..Grantee::default()
    }
}

fn policy(grants: Vec<Grant>) -> AccessControlPolicy {
    AccessControlPolicy {
        grants,
        owner: Some(Owner {
            id: Some(CANONICAL_ID.to_owned()),
            display_name: Some("owner".to_owned()),
        }),
    }
}

fn grant(grantee: Grantee, permission: &str) -> Grant {
    Grant {
        grantee: Some(grantee),
        permission: Some(Permission::custom(permission.to_owned())),
    }
}

// ── positive ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_canned_acl_of_each_target_is_accepted_by_that_target() {
    for value in BUCKET_CANNED_ACLS {
        assert_eq!(parse_canned(value, AclTarget::Bucket), Ok(*value), "bucket rejected {value}");
    }
    for value in OBJECT_CANNED_ACLS {
        assert_eq!(parse_canned(value, AclTarget::Object), Ok(*value), "object rejected {value}");
    }
}

#[test]
fn the_two_canned_sets_differ_in_exactly_the_three_documented_places() {
    // The whole point of two sets: a set comparison that came out equal would make every
    // wrong-target case below unreachable while every one of them still passed.
    assert!(BUCKET_CANNED_ACLS.contains(&"log-delivery-write"));
    assert!(!OBJECT_CANNED_ACLS.contains(&"log-delivery-write"));
    assert!(OBJECT_CANNED_ACLS.contains(&"bucket-owner-read"));
    assert!(OBJECT_CANNED_ACLS.contains(&"bucket-owner-full-control"));
    assert!(!BUCKET_CANNED_ACLS.contains(&"bucket-owner-read"));
    assert!(!BUCKET_CANNED_ACLS.contains(&"bucket-owner-full-control"));
    // And the five they share, so a set that lost one is not read as a target difference.
    for shared in [
        "private",
        "public-read",
        "public-read-write",
        "aws-exec-read",
        "authenticated-read",
    ] {
        assert!(BUCKET_CANNED_ACLS.contains(&shared));
        assert!(OBJECT_CANNED_ACLS.contains(&shared));
    }
}

#[test]
fn a_grant_header_names_one_grantee_of_each_kind() {
    let parsed = parse_grant_header(&format!("id=\"{CANONICAL_ID}\", uri=\"{ALL_USERS_GROUP}\", emailAddress=\"{EMAIL}\""))
        .expect("a well-formed grant header");
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0].r#type, Some(Type::CANONICALUSER));
    assert_eq!(parsed[0].id.as_deref(), Some(CANONICAL_ID));
    assert_eq!(parsed[1].r#type, Some(Type::GROUP));
    assert_eq!(parsed[1].uri.as_deref(), Some(ALL_USERS_GROUP));
    assert_eq!(parsed[2].r#type, Some(Type::AMAZONCUSTOMERBYEMAIL));
    assert_eq!(parsed[2].email_address.as_deref(), Some(EMAIL));
}

#[test]
fn grant_header_keys_are_case_insensitive_and_whitespace_tolerant() {
    let parsed = parse_grant_header("  ID = \"a\" ,   URI=\"b\"  ,\tEmailAddress =\"c\"").expect("a tolerated spelling");
    let kinds: Vec<Option<Type>> = parsed.iter().map(|g| g.r#type.clone()).collect();
    assert_eq!(
        kinds,
        vec![
            Some(Type::CANONICALUSER),
            Some(Type::GROUP),
            Some(Type::AMAZONCUSTOMERBYEMAIL)
        ]
    );
}

#[test]
fn a_value_containing_a_comma_stays_one_grantee() {
    // The quotes are what make this decidable, which is why they are required.
    let parsed = parse_grant_header("id=\"a,b\"").expect("a quoted comma");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].id.as_deref(), Some("a,b"));
}

#[test]
fn the_header_channel_alone_resolves_to_its_canned_value_and_grants() {
    let headers = AclHeaders {
        canned: Some("public-read"),
        read: Some(&format!("uri=\"{ALL_USERS_GROUP}\"")),
        ..AclHeaders::default()
    };
    let resolved = resolve_input(headers, None, AclTarget::Bucket).expect("the header channel alone");
    let AclInput::Headers { canned, grants } = resolved else {
        panic!("the header channel resolved to a document");
    };
    assert_eq!(canned, Some("public-read"));
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].permission.as_ref().map(Permission::as_str), Some("READ"));
}

#[test]
fn the_body_channel_alone_resolves_to_a_canonicalised_document() {
    let grantee = Grantee {
        uri: Some(ALL_USERS_GROUP.to_owned()),
        ..Grantee::default()
    };
    let document = policy(vec![grant(grantee, "READ")]);
    let resolved = resolve_input(AclHeaders::default(), Some(document), AclTarget::Bucket).expect("the body channel");
    let AclInput::Document(document) = resolved else {
        panic!("the body channel resolved to headers");
    };
    // The discriminator the reader could not see, filled in by the derivation.
    assert_eq!(document.grants[0].grantee.as_ref().and_then(|g| g.r#type.clone()), Some(Type::GROUP));
}

#[test]
fn each_identifying_member_derives_its_own_discriminator() {
    let by_id = Grantee {
        id: Some(CANONICAL_ID.to_owned()),
        ..Grantee::default()
    };
    let by_uri = Grantee {
        uri: Some(ALL_USERS_GROUP.to_owned()),
        ..Grantee::default()
    };
    let by_email = Grantee {
        email_address: Some(EMAIL.to_owned()),
        ..Grantee::default()
    };
    assert_eq!(resolve_grantee_type(&by_id), Ok(GranteeType::CanonicalUser));
    assert_eq!(resolve_grantee_type(&by_uri), Ok(GranteeType::Group));
    assert_eq!(resolve_grantee_type(&by_email), Ok(GranteeType::AmazonCustomerByEmail));
    // And the three wire spellings, so a mapping swapped between two kinds is visible.
    assert_eq!(GranteeType::CanonicalUser.as_str(), "CanonicalUser");
    assert_eq!(GranteeType::Group.as_str(), "Group");
    assert_eq!(GranteeType::AmazonCustomerByEmail.as_str(), "AmazonCustomerByEmail");
}

#[test]
fn a_display_name_beside_an_id_is_not_a_second_identity() {
    let grantee = Grantee {
        id: Some(CANONICAL_ID.to_owned()),
        display_name: Some("somebody".to_owned()),
        ..Grantee::default()
    };
    assert_eq!(resolve_grantee_type(&grantee), Ok(GranteeType::CanonicalUser));
}

#[test]
fn every_permission_of_the_closed_set_is_accepted() {
    let documented = ["FULL_CONTROL", "WRITE", "WRITE_ACP", "READ", "READ_ACP"];
    assert_eq!(PERMISSIONS, documented);
    for permission in documented {
        let mut document = policy(vec![grant(canonical_grantee(), permission)]);
        assert_eq!(canonicalize_policy(&mut document), Ok(()), "{permission} was refused");
    }
}

#[test]
fn an_empty_document_carries_no_grants_and_is_still_a_document() {
    // Clearing every grant is a legal ACL write; it is the header channel's absence that is
    // refused, never an empty grant list.
    let mut document = policy(Vec::new());
    assert_eq!(canonicalize_policy(&mut document), Ok(()));
    let resolved = resolve_input(AclHeaders::default(), Some(policy(Vec::new())), AclTarget::Bucket)
        .expect("an ACL that grants nobody anything");
    let AclInput::Document(document) = resolved else {
        panic!("an empty document resolved to headers");
    };
    assert!(document.grants.is_empty());
    assert!(document.owner.is_some());
}

// ── negative ─────────────────────────────────────────────────────────────────────────────

#[test]
fn n_both_channels_at_once_is_refused_as_invalid_request() {
    let headers = AclHeaders {
        canned: Some("private"),
        ..AclHeaders::default()
    };
    assert_eq!(
        resolve_input(headers, Some(policy(Vec::new())), AclTarget::Bucket).err(),
        Some(AclRejection::BothChannels)
    );
    assert_eq!(AclRejection::BothChannels.code(), ErrorCode::INVALID_REQUEST);
}

#[test]
fn n_a_grant_header_beside_a_body_is_the_same_refusal() {
    // The exclusion is against the *channel*, not against `x-amz-acl` alone: a rule written
    // for the canned header only would let every grant header through beside a document.
    for headers in [
        AclHeaders {
            full_control: Some("id=\"a\""),
            ..AclHeaders::default()
        },
        AclHeaders {
            read: Some("id=\"a\""),
            ..AclHeaders::default()
        },
        AclHeaders {
            write: Some("id=\"a\""),
            ..AclHeaders::default()
        },
        AclHeaders {
            read_acp: Some("id=\"a\""),
            ..AclHeaders::default()
        },
        AclHeaders {
            write_acp: Some("id=\"a\""),
            ..AclHeaders::default()
        },
    ] {
        assert_eq!(
            resolve_input(headers, Some(policy(Vec::new())), AclTarget::Bucket).err(),
            Some(AclRejection::BothChannels)
        );
    }
}

#[test]
fn n_neither_channel_is_refused_as_malformed_xml() {
    assert_eq!(
        resolve_input(AclHeaders::default(), None, AclTarget::Bucket).err(),
        Some(AclRejection::NoChannel)
    );
    assert_eq!(AclRejection::NoChannel.code(), ErrorCode::MALFORMED_XML);
}

#[test]
fn n_a_canned_acl_of_the_other_target_is_refused() {
    assert_eq!(
        parse_canned("log-delivery-write", AclTarget::Object),
        Err(AclRejection::CannedWrongTarget)
    );
    assert_eq!(
        parse_canned("bucket-owner-full-control", AclTarget::Bucket),
        Err(AclRejection::CannedWrongTarget)
    );
    assert_eq!(parse_canned("bucket-owner-read", AclTarget::Bucket), Err(AclRejection::CannedWrongTarget));
    assert_eq!(AclRejection::CannedWrongTarget.code(), ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn n_a_near_miss_spelling_is_not_a_canned_acl() {
    // Every one of these is one edit away from a member of the set, which is the shape a
    // prefix or contains comparison would let through.
    for value in [
        "Private",
        "private ",
        " private",
        "public_read",
        "publicread",
        "public-read-writ",
        "public-read-write-all",
        "authenticated_read",
        "log-delivery-writes",
        "not-a-canned-acl",
    ] {
        assert_eq!(parse_canned(value, AclTarget::Bucket), Err(AclRejection::CannedUnknown), "{value}");
        assert_eq!(parse_canned(value, AclTarget::Object), Err(AclRejection::CannedUnknown), "{value}");
    }
}

#[test]
fn n_an_empty_canned_acl_is_refused_rather_than_read_as_private() {
    assert_eq!(parse_canned("", AclTarget::Bucket), Err(AclRejection::CannedUnknown));
    assert_eq!(AclRejection::CannedUnknown.code(), ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn n_a_malformed_grant_header_never_parses_as_an_empty_list() {
    // The failure this exists for: a parser that split on commas and skipped what it could
    // not read would answer `Ok(vec![])` here, and the caller would store an ACL granting
    // nothing while answering 200.
    for value in [
        "id=noquotes",
        "id=\"unterminated",
        "id=\"\"",
        "id",
        "",
        "   ",
        "id=\"a\",",
        ",id=\"a\"",
        "id=\"a\" uri=\"b\"",
        "=\"a\"",
        "id=\"a\"trailing",
    ] {
        assert_eq!(parse_grant_header(value).err(), Some(AclRejection::GrantSyntax), "{value:?} parsed");
    }
    assert_eq!(AclRejection::GrantSyntax.code(), ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn n_an_unknown_grant_key_is_refused() {
    for value in ["badtype=\"x\"", "canonicaluser=\"x\"", "email=\"x\"", "group=\"x\""] {
        assert_eq!(parse_grant_header(value).err(), Some(AclRejection::GrantUnknownKey), "{value}");
    }
    assert_eq!(AclRejection::GrantUnknownKey.code(), ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn n_a_grant_header_is_refused_at_both_of_its_ceilings() {
    let long = format!("id=\"{}\"", "a".repeat(MAX_GRANT_HEADER_BYTES));
    assert_eq!(parse_grant_header(&long).err(), Some(AclRejection::GrantTooLarge));
    let many: Vec<String> = (0..=MAX_GRANTEES_PER_HEADER).map(|n| format!("id=\"u{n}\"")).collect();
    assert_eq!(parse_grant_header(&many.join(",")).err(), Some(AclRejection::GrantTooLarge));
    assert_eq!(AclRejection::GrantTooLarge.code(), ErrorCode::INVALID_ARGUMENT);
    // The ceilings are inclusive: the last accepted list is one short of the refusal.
    let at_cap: Vec<String> = (0..MAX_GRANTEES_PER_HEADER).map(|n| format!("id=\"u{n}\"")).collect();
    assert_eq!(parse_grant_header(&at_cap.join(",")).map(|g| g.len()), Ok(MAX_GRANTEES_PER_HEADER));
}

#[test]
fn n_a_grantee_naming_nothing_has_no_discriminator() {
    assert_eq!(resolve_grantee_type(&Grantee::default()), Err(AclRejection::GranteeUnidentified));
    let empty_text = Grantee {
        id: Some(String::new()),
        ..Grantee::default()
    };
    assert_eq!(resolve_grantee_type(&empty_text), Err(AclRejection::GranteeUnidentified));
    assert_eq!(AclRejection::GranteeUnidentified.code(), ErrorCode::MALFORMED_XML);
}

#[test]
fn n_a_grantee_naming_two_identities_is_ambiguous() {
    for grantee in [
        Grantee {
            id: Some(CANONICAL_ID.to_owned()),
            uri: Some(ALL_USERS_GROUP.to_owned()),
            ..Grantee::default()
        },
        Grantee {
            id: Some(CANONICAL_ID.to_owned()),
            email_address: Some(EMAIL.to_owned()),
            ..Grantee::default()
        },
        Grantee {
            uri: Some(ALL_USERS_GROUP.to_owned()),
            email_address: Some(EMAIL.to_owned()),
            ..Grantee::default()
        },
    ] {
        assert_eq!(resolve_grantee_type(&grantee), Err(AclRejection::GranteeAmbiguous));
    }
    assert_eq!(AclRejection::GranteeAmbiguous.code(), ErrorCode::MALFORMED_XML);
}

#[test]
fn n_a_grant_without_a_grantee_is_refused() {
    let mut document = policy(vec![Grant {
        grantee: None,
        permission: Some(Permission::FULL_CONTROL),
    }]);
    assert_eq!(canonicalize_policy(&mut document), Err(AclRejection::GrantWithoutGrantee));
    assert_eq!(AclRejection::GrantWithoutGrantee.code(), ErrorCode::MALFORMED_XML);
}

#[test]
fn n_a_permission_outside_the_closed_set_is_refused() {
    for permission in ["full_control", "FULLCONTROL", "READ_WRITE", "read", "", "OWNER"] {
        let mut document = policy(vec![grant(canonical_grantee(), permission)]);
        assert_eq!(canonicalize_policy(&mut document), Err(AclRejection::PermissionUnknown), "{permission}");
    }
    let mut none = policy(vec![Grant {
        grantee: Some(canonical_grantee()),
        permission: None,
    }]);
    assert_eq!(canonicalize_policy(&mut none), Err(AclRejection::PermissionUnknown));
    assert_eq!(AclRejection::PermissionUnknown.code(), ErrorCode::MALFORMED_XML);
}

#[test]
fn n_the_first_broken_grant_decides_the_refusal() {
    let mut document = policy(vec![
        grant(canonical_grantee(), "READ"),
        grant(Grantee::default(), "READ"),
        grant(canonical_grantee(), "nonsense"),
    ]);
    assert_eq!(canonicalize_policy(&mut document), Err(AclRejection::GranteeUnidentified));
}

#[test]
fn n_no_reason_carries_an_id_an_email_a_uri_or_any_request_bytes() {
    // `q-acl-0010`: a refusal must never copy an identity into an error body or a log line.
    for rejection in [
        AclRejection::BothChannels,
        AclRejection::NoChannel,
        AclRejection::CannedUnknown,
        AclRejection::CannedWrongTarget,
        AclRejection::GrantSyntax,
        AclRejection::GrantUnknownKey,
        AclRejection::GrantTooLarge,
        AclRejection::GranteeUnidentified,
        AclRejection::GranteeAmbiguous,
        AclRejection::GrantWithoutGrantee,
        AclRejection::PermissionUnknown,
    ] {
        let reason = rejection.reason();
        assert!(!reason.contains(CANONICAL_ID), "{reason}");
        assert!(!reason.contains(EMAIL), "{reason}");
        assert!(!reason.contains('@'), "{reason}");
        assert!(!reason.contains("http://acs."), "{reason}");
    }
    for raw in [
        format!("id={CANONICAL_ID}"),
        format!("account=\"{EMAIL}\""),
        format!("id=\"{}\"", "u".repeat(MAX_GRANT_HEADER_BYTES)),
    ] {
        let rejection = parse_grant_header(&raw).expect_err("the malformed or over-limit header is refused");
        let reason = rejection.reason();
        assert!(!reason.contains(CANONICAL_ID), "{reason}");
        assert!(!reason.contains(EMAIL), "{reason}");
        assert!(!reason.contains("uuuuuuuuuuuuuuuu"), "{reason}");
    }
}

#[test]
fn n_the_status_side_of_each_code_is_the_one_aws_answers() {
    assert_eq!(ErrorCode::INVALID_REQUEST.default_status().as_u16(), 400);
    assert_eq!(ErrorCode::INVALID_ARGUMENT.default_status().as_u16(), 400);
    assert_eq!(ErrorCode::MALFORMED_XML.default_status().as_u16(), 400);
}
