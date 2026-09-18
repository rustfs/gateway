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

//! Every argument of the bucket-policy and ACL contracts, built out of a decoded request and
//! nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call*
//! [`validate_policy`], [`validate_public_access_block`] and [`resolve_input`] from what
//! `Req<PutBucketPolicy>`, `Req<PutPublicAccessBlock>`, `Req<PutBucketAcl>` and
//! `Req<PutObjectAcl>` hand a handler: the policy document as the decoded `policy` string, the
//! public-access block as its decoded configuration, and the ACL write as the six header members
//! plus the optional document, on both targets.
//! NOT responsible for: what the rules decide, which is `rustfs-gateway-core`'s
//! `ops/shared/bucket_policy.rs` and `ops/shared/acl.rs` inline tests, or the wire shape of the
//! documents, which `conformance/cases/{policy,acl}/` pin.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15 found `evaluate_range` exported and uncallable, and left the rest of the exported
//! surface open with the acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** The policy and ACL contracts are called today by the fs
//! reference backend, which lives in this workspace; this file is the same call made with the
//! facade alone, so that a backend that is not the reference one is proven to reach them, and so
//! that the shape of the bridge — `AclHeaders` from six `Option<String>` members, `AclTarget`
//! from which operation was decoded — is written down where a backend author will find it.

use rustfs_gateway::{
    AclHeaders, AclInput, AclRejection, AclTarget, MetaView, OperationCodec, PolicyRejection, RequestBody, TargetKind, dto,
    resolve_input, validate_policy, validate_public_access_block,
};

use super::tagging_reachability::{accepted, content_md5};

const POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::conf-policy/*"}]}"#;
const PUBLIC_ACCESS_BLOCK: &str =
    "<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>";
const ACL_DOCUMENT: &str = concat!(
    "<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList><Grant>",
    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>o</ID></Grantee>",
    "<Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>"
);

/// The two integrity headers every write below declares `httpChecksumRequired` for, with the
/// digest leaked once per case — test-data generation, six cases, nothing to reclaim.
fn integrity(body: &[u8]) -> [(&'static str, &'static str); 2] {
    let digest: &'static str = Box::leak(content_md5(body).into_boxed_str());
    [("content-type", "application/xml"), ("content-md5", digest)]
}

/// What a backend has after decoding a `PutBucketPolicy` write: the document as one string.
fn decoded_policy(document: &'static str) -> dto::PutBucketPolicyInput {
    let request = accepted("PUT", "http://host.invalid/conf-policy?policy", &integrity(document.as_bytes()));
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has one label");
    dto::PutBucketPolicy::decode(&view, RequestBody::Buffered(document.as_bytes().into()))
        .expect("a policy write with any body is not the decoder's refusal")
}

/// What a backend has after decoding a `PutPublicAccessBlock` write.
fn decoded_public_access_block() -> dto::PutPublicAccessBlockInput {
    let request = accepted(
        "PUT",
        "http://host.invalid/conf-policy?publicAccessBlock",
        &integrity(PUBLIC_ACCESS_BLOCK.as_bytes()),
    );
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has one label");
    dto::PutPublicAccessBlock::decode(&view, RequestBody::Buffered(PUBLIC_ACCESS_BLOCK.as_bytes().into()))
        .expect("a well-formed block is not a refusal")
}

/// What a backend has after decoding a `PutBucketAcl` write: six optional header members and an
/// optional document, which is exactly what the contract asks for.
fn decoded_bucket_acl(headers: &[(&'static str, &'static str)], document: Option<&'static str>) -> dto::PutBucketAclInput {
    let body = document.map_or(b"" as &[u8], str::as_bytes);
    let mut all = integrity(body).to_vec();
    all.extend_from_slice(headers);
    let request = accepted("PUT", "http://host.invalid/conf-policy?acl", &all);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has one label");
    let body = if body.is_empty() {
        RequestBody::None
    } else {
        RequestBody::Buffered(body.into())
    };
    dto::PutBucketAcl::decode(&view, body).expect("an ACL write on either channel is not the decoder's refusal")
}

/// The bridge a backend writes once: the six `Option<String>` members of an ACL write input,
/// borrowed into the contract's header view. `PutObjectAcl` has the same six members.
fn bucket_acl_headers(input: &dto::PutBucketAclInput) -> AclHeaders<'_> {
    AclHeaders {
        canned: input.acl.as_ref().map(|acl| acl.as_str()),
        full_control: input.grant_full_control.as_deref(),
        read: input.grant_read.as_deref(),
        write: input.grant_write.as_deref(),
        read_acp: input.grant_read_acp.as_deref(),
        write_acp: input.grant_write_acp.as_deref(),
    }
}

// ---------------------------------------------------------------------------------------------
// Bucket policy: PutBucketPolicy's document and PutPublicAccessBlock's configuration
// ---------------------------------------------------------------------------------------------

/// Positive — the decoded `policy` string is the contract's whole argument, and a well-formed
/// document passes it.
#[test]
fn a_well_formed_policy_document_reaches_the_contract() {
    let input = decoded_policy(POLICY);
    assert_eq!(input.policy, POLICY, "the decoder hands the handler the document verbatim");
    validate_policy(&input.policy).expect("a JSON object under both ceilings");
}

/// Negative — the decoder does not pre-empt the contract: a body that is not JSON, and one that is
/// JSON but not an object, both reach the handler and are the contract's refusals, each with the
/// single `MalformedPolicy` code and a constant reason.
#[test]
fn n_a_bad_document_is_the_contracts_refusal_not_the_decoders() {
    for (document, expected) in [
        ("{not json", PolicyRejection::NotJson),
        ("[1,2]", PolicyRejection::NotAnObject),
    ] {
        let input = decoded_policy(document);
        let rejection = validate_policy(&input.policy).expect_err("the contract refuses it");
        assert_eq!(rejection, expected, "{document}");
        assert_eq!(rejection.code(), rustfs_gateway::ErrorCode::MALFORMED_POLICY);
        assert!(!rejection.reason().contains(document), "no excerpt of the document in the reason");
    }
}

/// Positive — the decoded configuration is the contract's argument; the omitted switches decode
/// as `None`, which is the backend's to default and not the decoder's.
#[test]
fn a_public_access_block_reaches_the_contract_with_its_omitted_switches_absent() {
    let input = decoded_public_access_block();
    let configuration = &input.public_access_block_configuration;
    validate_public_access_block(configuration).expect("the contract accepts every well-formed block");
    assert_eq!(configuration.block_public_policy, Some(true));
    assert_eq!(configuration.block_public_acls, None, "an omitted switch is None, not false");
}

// ---------------------------------------------------------------------------------------------
// ACL: PutBucketAcl's header channel and document channel
// ---------------------------------------------------------------------------------------------

/// Positive — a canned ACL and a grant header on the header channel reach the contract through
/// the six-member bridge, and the contract answers the canonical canned spelling plus one grant
/// per grantee.
#[test]
fn a_header_channel_acl_write_reaches_the_contract() {
    let input = decoded_bucket_acl(
        &[
            ("x-amz-acl", "public-read"),
            ("x-amz-grant-read", "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\""),
        ],
        None,
    );
    assert!(input.access_control_policy.is_none(), "no document was sent");
    match resolve_input(bucket_acl_headers(&input), input.access_control_policy.clone(), AclTarget::Bucket)
        .expect("the header channel is well formed")
    {
        AclInput::Headers { canned, grants } => {
            assert_eq!(canned, Some("public-read"));
            assert_eq!(grants.len(), 1);
        }
        AclInput::Document(_) => panic!("no document was sent"),
    }
}

/// Positive — a document on the body channel decodes into the contract's `Option` argument and
/// comes back canonicalised, every grantee typed.
#[test]
fn a_document_channel_acl_write_reaches_the_contract() {
    let input = decoded_bucket_acl(&[], Some(ACL_DOCUMENT));
    assert!(input.acl.is_none() && input.grant_read.is_none(), "no header was sent");
    match resolve_input(bucket_acl_headers(&input), input.access_control_policy.clone(), AclTarget::Bucket)
        .expect("the document channel is well formed")
    {
        AclInput::Document(policy) => {
            let grantee = policy.grants[0].grantee.as_ref().expect("one grantee");
            assert!(grantee.r#type.is_some(), "canonicalised: the grantee carries its xsi:type");
        }
        AclInput::Headers { .. } => panic!("a document was sent"),
    }
}

/// Negative — the two combinations the contract refuses are reachable as refusals: both channels
/// at once, and neither. The decoder accepts each; the contract, given the decoded input, says
/// which rule broke. An object-only canned value is refused for the bucket target and accepted
/// for the object one, so the target argument is load-bearing and comes from which operation
/// the backend decoded.
#[test]
fn n_the_channel_refusals_and_the_target_are_reachable() {
    let both = decoded_bucket_acl(&[("x-amz-acl", "private")], Some(ACL_DOCUMENT));
    assert_eq!(
        resolve_input(bucket_acl_headers(&both), both.access_control_policy.clone(), AclTarget::Bucket).unwrap_err(),
        AclRejection::BothChannels
    );
    let neither = decoded_bucket_acl(&[], None);
    assert_eq!(
        resolve_input(bucket_acl_headers(&neither), neither.access_control_policy.clone(), AclTarget::Bucket).unwrap_err(),
        AclRejection::NoChannel
    );
    let object_only = decoded_bucket_acl(&[("x-amz-acl", "bucket-owner-read")], None);
    assert!(matches!(
        resolve_input(bucket_acl_headers(&object_only), None, AclTarget::Bucket),
        Err(AclRejection::CannedWrongTarget)
    ));
    assert!(resolve_input(bucket_acl_headers(&object_only), None, AclTarget::Object).is_ok());
}
