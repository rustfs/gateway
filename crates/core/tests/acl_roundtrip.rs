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

//! Whether an arbitrary access control policy survives the trip out and back, and on which wire.
//!
//! Responsible for: the `decode ∘ encode` identity over `AccessControlPolicy` — `GetBucketAcl`
//! writes a document, `PutBucketAcl` reads one, and a stored policy has to come back the same
//! grants in the same order — together with the wire shape that identity is only worth anything
//! against. This family is the one where the shape assertion has to run in **both** directions:
//! the grant list is genuinely wrapped, in `<AccessControlList>`, so here a missing wrapper is
//! the defect and a `<Grants>` wrapper is still one; and the `<Grantee>` discriminator is an XML
//! **attribute** rather than an element, with the `xmlns:xsi` declaration AWS puts on that same
//! element and `aws-java-sdk` refuses the document without (`q-acl-0003`).
//! NOT responsible for: the semantics of `ops::shared::acl` — the two wire channels, the canned
//! sets, the `x-amz-grant-*` grammar, the closed `Permission` set and the derivation of the
//! discriminator — every one of which `acl_contract.rs` owns end to end, and which that file
//! declares it holds *without* the XML wire form. This file is the other half of that split.
//! Also not the bytes of any one fixed document, which the `acl/` goldens pin.
//! Upstream: the generated codecs for `GetBucketAcl` and `PutBucketAcl`, and `ops::shared::acl`.
//! Downstream: nothing.
//!
//! # Why an attribute is worth a property of its own
//!
//! Every other configuration family in this workspace carries its whole meaning in elements. This
//! one puts the union discriminator in `xsi:type`, so there are two ways for the round trip to
//! lose it that no element-only family has: the writer can omit the `xmlns:xsi` declaration that
//! makes the prefix resolvable, and the reader can fail to resolve the prefix and hand back
//! `None`. Neither shows up as a parse error. The second is the more dangerous, because
//! `check_grantee_type` treats an absent attribute as legal on purpose — AWS's own SDKs omit it —
//! so a reader that silently saw nothing would be indistinguishable from a client that sent
//! nothing, and the identity is the only thing that can tell them apart.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on: element order inside a grant, and
//! the `xmlns` on the root. Both are pinned by the `acl/` goldens, which is the complementary
//! guard — a golden pins one document exactly, a property pins every document approximately.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::acl::{
    ALL_USERS_GROUP, AUTHENTICATED_USERS_GROUP, AclRejection, LOG_DELIVERY_GROUP, XSI_NAMESPACE, canonicalize_policy,
};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketAcl` is `httpChecksumRequired`, so every read fixture has to make an integrity claim
/// before the body is looked at. The claim's *value* is settled below this layer, and this
/// fixture hands the decoder an already-buffered body, so neither the wire-layer check nor
/// `value::verify_body_digest` runs. That is deliberate: what is under test here is the document.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The root element both directions must name.
const ROOT: &str = "<AccessControlPolicy";

/// The wrapper this family's grant list **must** carry. Unlike every sibling property in this
/// workspace, where the assertion is that no wrapper appears, `Grants` is genuinely wrapped here:
/// AWS spells the list `<AccessControlList><Grant>…</Grant></AccessControlList>`, and a document
/// that repeated `<Grant>` directly under the root is the one every SDK reads as zero grants.
const REQUIRED_WRAPPER: &str = "<AccessControlList>";

/// Every wrapper element name that must never appear. The model member is called `Grants` and the
/// wire element is `AccessControlList`; a writer keyed on the model name produces a document no
/// client reads, and an encoder and a decoder that both used it would round-trip perfectly.
const FORBIDDEN_WRAPPERS: &[&str] = &["<Grants>", "<Grantees>", "<Permissions>"];

/// The declaration `xsi:type` needs to resolve, on the element AWS puts it on. `q-acl-0003`
/// records that `aws-java-sdk` cannot parse a `<Grantee>` without it.
const XSI_DECLARATION: &str = "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";

const CANONICAL_ID: &str = "3f6e2b1c4a8d90e7b5c31f2a6d80e4c97b1a3d5f8e206c4b7a9d1e3f5c7b9a0d";

fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// Serialises the policy the way `GetBucketAcl` answers a read.
fn encode_read(policy: dto::AccessControlPolicy) -> String {
    let request = accepted("GET", "/photos?acl", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketAclOutput {
        owner: policy.owner,
        grants: policy.grants,
    };
    let response = dto::GetBucketAcl::encode(output, &view, 200).expect("a policy always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way `PutBucketAcl` reads a write.
fn decode_write(document: &str) -> Result<Option<dto::AccessControlPolicy>, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?acl", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketAcl::decode(&view, body).map(|input| input.access_control_policy)
}

/// Decodes and canonicalises, which is the pair a write actually performs: the decoder answers
/// syntax and `canonicalize_policy` fills in the discriminator, and a backend never sees one
/// without the other. A round trip that skipped the canonicalisation would be comparing against a
/// document no read would ever write back.
fn store(document: &str) -> dto::AccessControlPolicy {
    let mut policy = decode_write(document)
        .expect("a document this codec wrote is one it must read")
        .expect("the body carries a policy");
    canonicalize_policy(&mut policy).expect("a document this codec wrote is one this family accepts");
    policy
}

// ── the comparable projection ────────────────────────────────────────────────────────────────

/// The comparable projection of a policy. The ACL DTOs carry no `PartialEq` — ADR-0004 keeps
/// derived equality off the DTOs — so equality is spelled here, over every member, in order,
/// including the `xsi:type` discriminator that lives in an attribute rather than an element.
/// A member left out of this projection is a member the identity would stop covering.
type GranteeProjection = (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);

type PolicyProjection = (Option<(Option<String>, Option<String>)>, Vec<(Option<GranteeProjection>, Option<String>)>);

fn grantee_projection(grantee: &dto::Grantee) -> GranteeProjection {
    (
        grantee.id.clone(),
        grantee.display_name.clone(),
        grantee.email_address.clone(),
        grantee.uri.clone(),
        grantee.r#type.as_ref().map(|kind| kind.as_str().to_owned()),
    )
}

fn projection(policy: &dto::AccessControlPolicy) -> PolicyProjection {
    (
        policy
            .owner
            .as_ref()
            .map(|owner| (owner.id.clone(), owner.display_name.clone())),
        policy
            .grants
            .iter()
            .map(|grant| {
                (
                    grant.grantee.as_ref().map(grantee_projection),
                    grant.permission.as_ref().map(|permission| permission.as_str().to_owned()),
                )
            })
            .collect(),
    )
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// The closed permission set. A generated document is a *legal* one, so the property never leans
/// on a value `canonicalize_policy` would refuse; `acl_contract.rs` owns that direction.
fn permission() -> impl Strategy<Value = dto::Permission> {
    prop_oneof![
        Just(dto::Permission::FULL_CONTROL),
        Just(dto::Permission::WRITE),
        Just(dto::Permission::WRITE_ACP),
        Just(dto::Permission::READ),
        Just(dto::Permission::READ_ACP),
    ]
}

/// Opaque display text. The alphabet includes the five characters XML has to escape plus two
/// outside ASCII: a display name is text an operator chose, and a writer that emitted `&` raw
/// would produce a document its own reader could not parse, while one that escaped on the way out
/// and forgot to unescape on the way in would hand the caller back `&amp;`. It also carries tab,
/// line feed and **carriage return**, because XML 1.0 §2.11 normalises a literal CR in content
/// away: a writer that emitted the byte raw would hand the caller back a line feed, so the only
/// spelling that survives is the numeric reference `&#13;`, and this identity is what says so.
///
/// **Nothing is excluded, and that is deliberate.** An earlier draft of this file dropped the
/// empty string and trimmed the edges, on the grounds that `DisplayName` was `omit`-on-empty and
/// so not an identity. That is a generator shaped around a defect, which is the one shape that
/// cannot find the defect next door: rustfs/gateway#272 made the empty string an identity for
/// every optional member, and a generator still avoiding it would have gone on reading green
/// whether the fix held or was reverted. The empty string and the whitespace edges are back in,
/// and [`an_empty_member_comes_back_as_itself`] pins the same claim by name.
fn display_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü \t\n\r_-]{0,30}"
}

/// A grantee naming exactly one identity, which is what `resolve_grantee_type` requires: none
/// leaves it nameless and two leave it ambiguous, and both are refusals `acl_contract.rs` owns.
/// `Type` is left unset here on purpose — a client is not obliged to send the attribute, and
/// `canonicalize_policy` is what fills it in, so generating it would test the writer against a
/// value the writer itself chose.
fn grantee() -> impl Strategy<Value = dto::Grantee> {
    prop_oneof![
        (prop::option::of(display_text()), "[0-9a-f]{64}").prop_map(|(display_name, id)| dto::Grantee {
            id: Some(id),
            display_name,
            ..dto::Grantee::default()
        }),
        prop_oneof![
            Just(ALL_USERS_GROUP.to_owned()),
            Just(AUTHENTICATED_USERS_GROUP.to_owned()),
            Just(LOG_DELIVERY_GROUP.to_owned()),
        ]
        .prop_map(|uri| dto::Grantee {
            uri: Some(uri),
            ..dto::Grantee::default()
        }),
        "[a-z]{1,8}@example\\.com".prop_map(|email| dto::Grantee {
            email_address: Some(email),
            ..dto::Grantee::default()
        }),
    ]
}

fn grant() -> impl Strategy<Value = dto::Grant> {
    (grantee(), permission()).prop_map(|(grantee, permission)| dto::Grant {
        grantee: Some(grantee),
        permission: Some(permission),
    })
}

/// A policy with an owner and one to four grants. The owner is generated with and without a
/// display name because `ACL_OWNER_POLICY` is `PreserveAsSent`: what arrived is what a read must
/// write back, so an owner half-filled in has to survive as a half-filled-in owner.
fn access_control_policy() -> impl Strategy<Value = dto::AccessControlPolicy> {
    (
        prop::option::of((prop::option::of(display_text()), Just(CANONICAL_ID.to_owned()))),
        prop::collection::vec(grant(), 1..5),
    )
        .prop_map(|(owner, grants)| dto::AccessControlPolicy {
            owner: owner.map(|(display_name, id)| dto::Owner {
                display_name,
                id: Some(id),
            }),
            grants,
        })
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the policy says, writing it and reading it back yields the same owner and the
    /// same grants in the same order — including each grantee's `xsi:type`, which lives in an
    /// attribute — and the document that carried them named the root the wire uses, wrapped the
    /// grant list the way AWS wraps it, declared the namespace the attribute resolves against,
    /// and named no wrapper the model invented.
    ///
    /// The halves are one test on purpose. Identity alone is satisfied by any encoder and decoder
    /// that agree with each other, including a pair that agreed to drop the attribute entirely;
    /// the shape assertions are what stop the property from being self-fulfilling.
    ///
    /// The read side deliberately does **not** canonicalise before comparing, and that is the
    /// difference between an assertion and a decoration here. `canonicalize_policy` re-derives
    /// `xsi:type` from the identifying member, so a codec pair that dropped the attribute on the
    /// way out and read `None` on the way back would be repaired by the canonicaliser and the
    /// identity would still hold — which is exactly what a mutation deleting the attribute from
    /// the writer proved. Comparing the raw decode is what makes the attribute part of the claim.
    /// The canonicaliser is still run afterwards, on the value that came back, because a stored
    /// document has to be one the family accepts as well as one it can read.
    #[test]
    fn an_access_control_policy_survives_encode_then_decode(policy in access_control_policy()) {
        // What a backend stores is the canonicalised document, so that is what a read writes.
        let mut stored = policy;
        prop_assert_eq!(
            canonicalize_policy(&mut stored),
            Ok(()),
            "the generator produced a policy the family refuses"
        );

        let document = encode_read(stored.clone());

        prop_assert!(
            document.contains(ROOT),
            "the written document does not name the root element every SDK looks for: {document}"
        );
        prop_assert!(
            document.contains(REQUIRED_WRAPPER),
            "the grant list lost the wrapper AWS spells it with, so every SDK reads zero grants: {document}"
        );
        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(
                !document.contains(wrapper),
                "the written document carries the wrapper {wrapper}, which no client knows: {document}"
            );
        }
        prop_assert!(
            document.contains(XSI_DECLARATION),
            "the Grantee carries xsi:type with no declaration to resolve it, which q-acl-0003 records aws-java-sdk refusing: {document}"
        );

        let mut read_back = decode_write(&document)
            .map_err(|error| {
                TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
            })?
            .ok_or_else(|| TestCaseError::fail(format!("the body carried no policy: {document}")))?;

        prop_assert_eq!(projection(&read_back), projection(&stored), "document: {}", document);
        prop_assert_eq!(canonicalize_policy(&mut read_back), Ok(()), "document: {}", document);
        prop_assert_eq!(projection(&read_back), projection(&stored), "canonicalising twice moved it: {}", document);
    }
}

// ── the boundaries and the members the property does not sample ──────────────────────────────

/// The discriminator, one grantee kind at a time, asserted on the wire and after the read.
///
/// The property covers this too, but a shrunk counterexample would name a whole policy; this
/// names the kind. It is the assertion that separates "the reader resolved the prefix" from "the
/// reader saw nothing and `check_grantee_type` let it pass", which are the same green line
/// otherwise — an absent attribute is legal on purpose, because AWS's own SDKs omit it.
#[test]
fn each_grantee_kind_carries_its_discriminator_out_and_back() {
    let cases = [
        (
            dto::Grantee {
                id: Some(CANONICAL_ID.to_owned()),
                ..dto::Grantee::default()
            },
            "CanonicalUser",
        ),
        (
            dto::Grantee {
                uri: Some(ALL_USERS_GROUP.to_owned()),
                ..dto::Grantee::default()
            },
            "Group",
        ),
        (
            dto::Grantee {
                email_address: Some("grantee@example.com".to_owned()),
                ..dto::Grantee::default()
            },
            "AmazonCustomerByEmail",
        ),
    ];

    for (grantee, expected) in cases {
        let mut policy = dto::AccessControlPolicy {
            owner: None,
            grants: vec![dto::Grant {
                grantee: Some(grantee),
                permission: Some(dto::Permission::READ),
            }],
        };
        canonicalize_policy(&mut policy).expect("one identity, one discriminator");

        let document = encode_read(policy.clone());
        assert!(
            document.contains(&format!("xsi:type=\"{expected}\"")),
            "the attribute never reached the wire: {document}"
        );
        assert!(document.contains(XSI_NAMESPACE), "and nothing declares the prefix: {document}");

        let read_back = store(&document);
        assert_eq!(
            read_back.grants[0]
                .grantee
                .as_ref()
                .and_then(|grantee| grantee.r#type.as_ref())
                .map(dto::Type::as_str),
            Some(expected),
            "the reader did not resolve the prefix, and an absent attribute is legal so nothing else would say so"
        );
    }
}

/// Text the writer has to escape, in the one member that is free text. A writer that emitted `&`
/// raw would produce a document its own reader could not parse; one that escaped on the way out
/// and forgot to unescape on the way back would hand the caller `&amp;`; and a reader that
/// collapsed the run of spaces would hand back a name the operator never wrote.
#[test]
fn a_display_name_of_awkward_text_comes_back_unchanged() {
    let awkward = "a & b < c > d \" e ' f  g";
    let policy = dto::AccessControlPolicy {
        owner: Some(dto::Owner {
            display_name: Some(awkward.to_owned()),
            id: Some(CANONICAL_ID.to_owned()),
        }),
        grants: vec![dto::Grant {
            grantee: Some(dto::Grantee {
                id: Some(CANONICAL_ID.to_owned()),
                display_name: Some(awkward.to_owned()),
                r#type: Some(dto::Type::CANONICALUSER),
                ..dto::Grantee::default()
            }),
            permission: Some(dto::Permission::FULL_CONTROL),
        }],
    };

    let document = encode_read(policy.clone());
    assert!(!document.contains("a & b"), "the ampersand reached the document unescaped: {document}");

    let read_back = store(&document);

    assert_eq!(projection(&read_back), projection(&policy));
}

/// Reading is order-insensitive while writing is not. The element order inside a grant is pinned
/// by the `acl/` goldens; a *sender* is under no such obligation.
#[test]
fn a_policy_whose_members_arrive_in_another_order_is_the_same_policy() {
    let canonical = "<AccessControlPolicy><Owner><ID>o</ID><DisplayName>d</DisplayName></Owner>\
                     <AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
                     xsi:type=\"CanonicalUser\"><ID>g</ID></Grantee><Permission>READ</Permission></Grant>\
                     </AccessControlList></AccessControlPolicy>";
    let shuffled = "<AccessControlPolicy><AccessControlList><Grant><Permission>READ</Permission>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                    <ID>g</ID></Grantee></Grant></AccessControlList>\
                    <Owner><DisplayName>d</DisplayName><ID>o</ID></Owner></AccessControlPolicy>";

    let first = store(canonical);
    let second = store(shuffled);

    assert_eq!(projection(&second), projection(&first));
}

/// A policy with no grants at all: a bucket whose ACL grants nobody anything. The wrapper is
/// still written, because a document that dropped it would be one an SDK reads as a parse
/// failure rather than as an empty list, and the empty list has to survive as an empty list
/// rather than coming back as a policy with no `<AccessControlList>` member at all.
#[test]
fn a_policy_with_no_grants_keeps_its_empty_wrapper() {
    let policy = dto::AccessControlPolicy {
        owner: Some(dto::Owner {
            display_name: None,
            id: Some(CANONICAL_ID.to_owned()),
        }),
        grants: Vec::new(),
    };

    let document = encode_read(policy.clone());
    assert!(
        document.contains(REQUIRED_WRAPPER),
        "an empty grant list is still a grant list: {document}"
    );

    let read_back = store(&document);

    assert!(read_back.grants.is_empty());
    assert_eq!(projection(&read_back), projection(&policy));
}

/// The ACL instance of the empty-element class, named rather than sampled: an empty `<DisplayName>`
/// and an empty `<ID>` beside a `<URI>`, which is the document rustfs/gateway#221's comment thread
/// reported for this family and which nothing has asserted until now. It was repaired by
/// rustfs/gateway#272 — `empty_value_policy` defaulted to dropping `Some("")` for an optional
/// member, collapsing two values the decoder tells apart — and the repair was never pinned here.
///
/// This family is where that mattered most, because it says the opposite in writing:
/// `ACL_OWNER_POLICY` is `PreserveAsSent` and `canonicalize_policy` names the promise — what a
/// backend stores is what a read writes back. Before #272 that sentence was prose nothing checked.
///
/// The grantee half is the one with teeth. `resolve_grantee_type` counts an empty `<ID>` as **no**
/// identity, so this grantee is a `Group` either way and no refusal ever fires; the only thing
/// that can tell "the empty id survived" from "the empty id was dropped" is the identity itself.
/// Asserted at two removes — the document out, and the read after it — because a re-encode that
/// dropped the element would change the stored document once, silently, and then hold.
#[test]
fn an_empty_member_comes_back_as_itself() {
    let document = "<AccessControlPolicy><Owner><ID>o</ID><DisplayName></DisplayName></Owner>\
                    <AccessControlList><Grant><Grantee><ID></ID>\
                    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>\
                    <Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";

    let once = store(document);
    let grantee = once.grants[0].grantee.as_ref().expect("the grantee is read");
    assert_eq!(grantee.id.as_deref(), Some(""), "ingress keeps the empty element");
    assert_eq!(
        once.owner.as_ref().and_then(|owner| owner.display_name.as_deref()),
        Some(""),
        "and keeps it in the owner too"
    );

    let reserialised = encode_read(once.clone());
    assert!(
        reserialised.contains("<ID></ID>"),
        "the encoder dropped the empty id the decoder kept: {reserialised}"
    );
    assert!(
        reserialised.contains("<DisplayName></DisplayName>"),
        "and the empty display name with it: {reserialised}"
    );

    let twice = store(&reserialised);
    assert_eq!(
        projection(&twice),
        projection(&once),
        "a read-modify-write cycle changed the stored policy: {reserialised}"
    );
}

/// One shape, four generated codecs. `AccessControlPolicy` is written by `GetBucketAcl` and
/// `GetObjectAcl` and read by `PutBucketAcl` and `PutObjectAcl`, and each of those is a separate
/// `impl OperationCodec` — which is exactly the arrangement `ops::shared::acl` exists to keep
/// honest, because "two parsers for one grammar drift" is the argument its module docs open with.
/// The bucket and object writers must produce the same bytes for the same policy, and the object
/// reader must read what the object writer wrote; otherwise a policy means one thing on a bucket
/// and another on an object while both answer `200`.
#[test]
fn the_bucket_and_object_codecs_agree_on_one_policy() {
    let policy = dto::AccessControlPolicy {
        owner: Some(dto::Owner {
            display_name: Some("owner".to_owned()),
            id: Some(CANONICAL_ID.to_owned()),
        }),
        grants: vec![dto::Grant {
            grantee: Some(dto::Grantee {
                id: Some(CANONICAL_ID.to_owned()),
                r#type: Some(dto::Type::CANONICALUSER),
                ..dto::Grantee::default()
            }),
            permission: Some(dto::Permission::READ),
        }],
    };

    let bucket_document = encode_read(policy.clone());

    let request = accepted("GET", "/photos/key?acl", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectAclOutput {
        owner: policy.owner.clone(),
        grants: policy.grants.clone(),
        request_charged: None,
    };
    let response = dto::GetObjectAcl::encode(output, &view, 200).expect("a policy always encodes");
    let object_document = match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    };

    assert_eq!(
        object_document, bucket_document,
        "the two writers of one shape disagree, which is the drift ops::shared::acl exists to prevent"
    );

    let request = accepted("PUT", "/photos/key?acl", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(object_document.as_bytes()));
    let mut read_back = dto::PutObjectAcl::decode(&view, body)
        .expect("a document this codec wrote is one it must read")
        .access_control_policy
        .expect("the body carries a policy");
    canonicalize_policy(&mut read_back).expect("and one this family accepts");

    assert_eq!(projection(&read_back), projection(&policy));
}

// ── negative: the shapes that must never be stored ───────────────────────────────────────────

/// The grant list without its wrapper: `<Grant>` repeated directly under the root, which is what
/// a writer that treated the list as flattened would produce. The decoder looks for the wrapper
/// and finds none, so every grant is out of reach and the policy is stored as granting nothing —
/// the read side of the defect the `REQUIRED_WRAPPER` assertion exists to catch on the write
/// side, and the reason that assertion is not decoration.
#[test]
fn n_an_unwrapped_grant_list_hides_every_grant_from_the_decoder() {
    let document = "<AccessControlPolicy><Owner><ID>o</ID></Owner>\
                    <Grant><Grantee><ID>g</ID></Grantee><Permission>READ</Permission></Grant>\
                    </AccessControlPolicy>";

    let policy = decode_write(document)
        .expect("an unknown element is skipped, not refused")
        .expect("the body still carries a policy");

    assert!(policy.grants.is_empty(), "the missing wrapper took every grant with it");
}

/// The model's own name for the list, which the wire never uses. A decoder keyed on it would read
/// this document and an encoder keyed on it would write one; the pair would round-trip perfectly
/// and no SDK would read a grant.
#[test]
fn n_the_model_name_for_the_grant_list_is_not_a_wire_element() {
    let document = "<AccessControlPolicy><Owner><ID>o</ID></Owner>\
                    <Grants><Grant><Grantee><ID>g</ID></Grantee><Permission>READ</Permission></Grant></Grants>\
                    </AccessControlPolicy>";

    let policy = decode_write(document)
        .expect("an unknown element is skipped, not refused")
        .expect("the body still carries a policy");

    assert!(policy.grants.is_empty());
}

/// A grantee naming no identity. The decoder accepts it — a missing optional element is not a
/// parse error — and `canonicalize_policy` is the layer that refuses, which is what makes the
/// `store` helper above the honest model of a write rather than a convenience.
#[test]
fn n_a_grantee_naming_nothing_is_refused_by_the_canonicaliser_not_the_decoder() {
    let document = "<AccessControlPolicy><AccessControlList><Grant><Grantee></Grantee>\
                    <Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";

    let mut policy = decode_write(document)
        .expect("an empty Grantee is well-formed XML")
        .expect("the body carries a policy");

    assert_eq!(canonicalize_policy(&mut policy), Err(AclRejection::GranteeUnidentified));
}

/// A `<Grantee>` whose `xsi:type` names a value this union does not have. The attribute is
/// readable — that is what makes the refusal possible at all — and an unknown discriminator is
/// refused rather than ignored, because a document nothing on this side understood, stored and
/// echoed back is a grant no two implementations would agree about.
#[test]
fn n_a_grantee_whose_discriminator_is_unknown_is_refused() {
    let document = "<AccessControlPolicy><AccessControlList><Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ServiceAccount\">\
                    <ID>g</ID></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";

    let mut policy = decode_write(document)
        .expect("an unknown attribute value is not a parse failure")
        .expect("the body carries a policy");

    assert_eq!(canonicalize_policy(&mut policy), Err(AclRejection::GranteeTypeUnknown));
}

/// A document whose root is some other element. The decoder must not read a policy out of it: a
/// body that named the wrong root and was read anyway would let a document written for one
/// operation be stored as another, and the refusal has to name the element it wanted so a client
/// can tell "wrong document" from "malformed document".
#[test]
fn n_a_document_whose_root_is_another_element_is_refused_by_name() {
    let document = "<Policy><Owner><ID>o</ID></Owner><AccessControlList>\
                    <Grant><Grantee><ID>g</ID></Grantee><Permission>READ</Permission></Grant>\
                    </AccessControlList></Policy>";

    let error = decode_write(document).expect_err("the wrong root is not a policy");

    assert_eq!(error.member(), Some("AccessControlPolicy"), "{error:?}");
}

/// The discriminator is case-sensitive, which is the half of `check_grantee_type` that a
/// tolerant reader would give away. `canonicaluser` is not `CanonicalUser`; accepting it would
/// widen a set this family closes at three, and the identity would then carry a spelling no
/// other implementation writes.
#[test]
fn n_a_discriminator_spelled_in_another_case_is_not_the_attribute() {
    let document = "<AccessControlPolicy><AccessControlList><Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"canonicaluser\">\
                    <ID>g</ID></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";

    let mut policy = decode_write(document)
        .expect("an attribute value is never a parse failure")
        .expect("the body carries a policy");

    assert_eq!(
        policy.grants[0]
            .grantee
            .as_ref()
            .and_then(|grantee| grantee.r#type.as_ref())
            .map(dto::Type::as_str),
        Some("canonicaluser"),
        "the decoder hands back what arrived, byte for byte"
    );
    assert_eq!(canonicalize_policy(&mut policy), Err(AclRejection::GranteeTypeUnknown));
}

/// The discriminator belongs to `<Grantee>` and is not inherited from an enclosing element.
/// `xsi:type` means something only on that one element; a reader that walked up from the grantee
/// looking for the attribute would read a type the sender put somewhere it says nothing, store
/// it, and write it back out — and the round trip would then agree with itself about a grant no
/// namespace-aware client agrees it sent.
#[test]
fn n_a_discriminator_on_an_enclosing_element_is_not_the_grantees() {
    let declaration = "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";
    let inner = "<Grantee><ID>g</ID></Grantee><Permission>READ</Permission>";
    let on_the_grant = format!(
        "<AccessControlPolicy><AccessControlList><Grant {declaration} xsi:type=\"Group\">{inner}</Grant></AccessControlList></AccessControlPolicy>"
    );
    let on_the_list = format!(
        "<AccessControlPolicy><AccessControlList {declaration} xsi:type=\"Group\"><Grant>{inner}</Grant></AccessControlList></AccessControlPolicy>"
    );

    for document in [on_the_grant, on_the_list] {
        let policy = decode_write(&document)
            .expect("an attribute on any element is not a parse failure")
            .expect("the body carries a policy");

        assert_eq!(
            policy.grants[0]
                .grantee
                .as_ref()
                .and_then(|grantee| grantee.r#type.as_ref())
                .map(dto::Type::as_str),
            None,
            "the grantee named no type and one was read for it anyway: {document}"
        );
    }
}

/// Two `<AccessControlList>` elements. Only the first is read and the second's grants are
/// **silently dropped** — pinned in the direction it has, because the alternative readings
/// (append, or refuse) are both defensible and the one thing that must not happen quietly is a
/// change of mind. A document that granted twice and came back granting once is a permission the
/// caller believes it set and the gateway never stored.
#[test]
fn n_a_second_grant_list_is_dropped_rather_than_appended() {
    let grant = "<Grant><Grantee><ID>g</ID></Grantee><Permission>READ</Permission></Grant>";
    let document = format!(
        "<AccessControlPolicy><AccessControlList>{grant}</AccessControlList>\
         <AccessControlList>{grant}</AccessControlList></AccessControlPolicy>"
    );

    let policy = decode_write(&document)
        .expect("a repeated element is not a parse failure")
        .expect("the body carries a policy");

    assert_eq!(policy.grants.len(), 1, "the second list was appended rather than dropped");
}

/// The discriminator is resolved by **namespace**, not by the spelling of the prefix — and that
/// is three separate claims, none of which the other two imply.
///
/// A document whose `xsi:` prefix is declared is read. A document that binds *another* prefix to
/// the same XML Schema instance namespace is also read, because the prefix is a local choice the
/// sender makes and two documents that bind differently say the same thing. A document that binds
/// `xsi:` itself to some *other* namespace is not read, because matching on the raw name would
/// store a discriminator no namespace-aware client agrees it sent. And an undeclared prefix
/// resolves against nothing — the document `q-acl-0003` records `aws-java-sdk` refusing, and the
/// reason the property asserts the declaration on the way out rather than only the attribute.
#[test]
fn a_discriminator_is_read_by_namespace_and_not_by_the_prefix_spelling() {
    let grantee = |attributes: &str| {
        format!(
            "<AccessControlPolicy><AccessControlList><Grant><Grantee {attributes}><ID>g</ID></Grantee>\
             <Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>"
        )
    };
    let read = |document: &str| {
        decode_write(document)
            .expect("an attribute is never a parse failure here")
            .expect("the body carries a policy")
            .grants[0]
            .grantee
            .as_ref()
            .and_then(|grantee| grantee.r#type.as_ref())
            .map(|kind| kind.as_str().to_owned())
    };

    assert_eq!(
        read(&grantee("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\"")),
        Some("Group".to_owned()),
        "the form AWS itself writes is read"
    );
    assert_eq!(
        read(&grantee("xmlns:q=\"http://www.w3.org/2001/XMLSchema-instance\" q:type=\"Group\"")),
        Some("Group".to_owned()),
        "and so is the same namespace under another prefix, because the prefix is the sender's choice"
    );
    assert_eq!(
        read(&grantee("xmlns:xsi=\"http://example.invalid/other\" xsi:type=\"Group\"")),
        None,
        "while the familiar spelling bound to another namespace is not the attribute and must not be read as it"
    );
    assert_eq!(
        read(&grantee("xsi:type=\"Group\"")),
        None,
        "nor is an undeclared prefix, which resolves against nothing"
    );
}

/// The one thing this identity samples and cannot judge: a **raw** carriage return in text.
///
/// The generator emits `\r` — nothing is excluded — and the round trip holds, which is precisely
/// why the identity is not enough here. The writer escapes it as `&#13;` and
/// `crates/xml/src/write.rs` says why: an XML processor normalises a literal CR to a line feed on
/// the way in (XML 1.0 §2.11), so the byte would not survive otherwise. **This reader does not
/// normalise**, so the pair agrees with itself and disagrees with every processor an AWS SDK uses
/// — the rustfs/gateway#206 shape moved from element names onto text. A mutation that made the
/// writer emit the raw byte survived the property at 1024 cases for exactly this reason.
///
/// Pinned in the direction it has, naming rustfs/gateway#283, so this assertion goes red the day
/// the reader is repaired rather than the repair going unnoticed.
#[test]
fn n_a_raw_carriage_return_is_not_normalised_on_the_way_in() {
    let document = "<AccessControlPolicy><Owner><ID>o</ID><DisplayName>a\rb</DisplayName></Owner>\
                    <AccessControlList><Grant><Grantee><ID>g</ID></Grantee>\
                    <Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";

    let stored = store(document);

    assert_eq!(
        stored.owner.as_ref().and_then(|owner| owner.display_name.as_deref()),
        Some("a\rb"),
        "rustfs/gateway#283: XML 1.0 §2.11 requires this to read back as a line feed, and it does not"
    );

    // And the writer's half is right on its own terms: what it emits is the one spelling that
    // would survive a conformant reader, which is what makes the divergence the reader's.
    let reserialised = encode_read(stored);
    assert!(
        reserialised.contains("<DisplayName>a&#13;b</DisplayName>"),
        "the writer must not emit a bare CR, whatever the reader does with one: {reserialised}"
    );
}

/// A permission outside the closed set. `acl_contract.rs` owns the refusal itself; what this adds
/// is that it is the *canonicaliser* and not the decoder that produces it, so a refactor moving
/// the check would have to move this assertion too.
#[test]
fn n_a_permission_outside_the_closed_set_survives_the_decoder_and_is_refused_after() {
    let document = "<AccessControlPolicy><AccessControlList><Grant><Grantee><ID>g</ID></Grantee>\
                    <Permission>OWNER</Permission></Grant></AccessControlList></AccessControlPolicy>";

    let mut policy = decode_write(document)
        .expect("Permission is an open string enum on the wire")
        .expect("the body carries a policy");

    assert_eq!(
        policy.grants[0].permission.as_ref().map(dto::Permission::as_str),
        Some("OWNER"),
        "the decoder is not the layer that closes the set"
    );
    assert_eq!(canonicalize_policy(&mut policy), Err(AclRejection::PermissionUnknown));
}
