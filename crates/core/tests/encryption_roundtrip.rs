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

//! Whether an arbitrary default-encryption configuration survives the trip out and back, and on
//! which wire.
//!
//! Responsible for: the `decode ∘ encode` identity over `ServerSideEncryptionConfiguration` —
//! `GetBucketEncryption` writes a document, `PutBucketEncryption` reads one, and a stored
//! configuration has to come back the same rules in the same order — together with the wire
//! shape that identity is only worth anything against, because an encoder and a decoder that
//! agreed on a *wrapped* rule list would round-trip perfectly and be unreadable by every SDK.
//! It also holds the seam between the two layers that together decide whether a document is
//! stored: the generated decoder answers syntax (`q-enc-0006` leniency on unknown elements,
//! `q-enc-0008`'s unbounded rule count) and `ops::shared::encryption::validate_encryption`
//! answers semantics (the closed `SSEAlgorithm` set, the KMS-key/algorithm agreement). A test
//! that expected the decoder to refuse a semantic violation would be asserting against the
//! wrong layer.
//! NOT responsible for: the enumeration of every semantic rule, which `ops::shared::encryption`'s
//! own unit tests own end to end; applying the configuration to an object write, which is task
//! P6-06's; and the bytes of any one fixed document, which a future `encryption/` conformance
//! corpus would pin.
//! Upstream: the generated codecs for `GetBucketEncryption` and `PutBucketEncryption`, and
//! `ops::shared::encryption`. Downstream: nothing.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on. Element *order* inside a rule is
//! the clearest instance: the reader is order-insensitive by design (`XmlNode::child`/
//! `children_named` match by local name, not position), so an encoder that emitted
//! `BucketKeyEnabled` before `ApplyServerSideEncryptionByDefault` would round-trip perfectly
//! here. `a_rule_whose_members_arrive_in_another_order_is_the_same_rule` below covers that
//! directly instead of leaving it to the property.
//!
//! # Why a property and not another table row
//!
//! A table pins particular documents. It cannot say what happens to the *combinations* it does
//! not list — a rule with no `ApplyServerSideEncryptionByDefault` at all next to one that names a
//! KMS key, an `AES256` rule beside an `aws:kms:dsse` one, a `BlockedEncryptionTypes` list with a
//! duplicate entry. Each generated case here is a document nobody wrote by hand, and the
//! identity has to hold for all of them — this is exactly the shape rustfs/gateway#231 asked
//! every configuration family to have one of.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::encryption::validate_encryption;
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketEncryption` is `httpChecksumRequired`, so every read fixture has to make an
/// integrity claim before the body is looked at. As in the CORS sibling, the claim's *value* is
/// settled below this layer, and this fixture hands the decoder an already-buffered body, so
/// neither the wire-layer digest check nor `value::verify_body_digest` runs against it.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The wrapper element the rule list must never carry. `Rule` is flattened directly under the
/// document root; a `<Rules>` wrapper is the defect the flattened quirk exists for, and an
/// encoder and a decoder that both used one would satisfy the round-trip identity while shipping
/// a document no client can read.
const FORBIDDEN_WRAPPER: &str = "<Rules>";

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

/// Serialises the rules the way `GetBucketEncryption` answers a read.
fn encode_read(rules: Vec<dto::ServerSideEncryptionRule>) -> String {
    let request = accepted("GET", "/photos?encryption", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketEncryptionOutput {
        server_side_encryption_configuration: Some(dto::ServerSideEncryptionConfiguration { rules }),
    };
    let response = dto::GetBucketEncryption::encode(output, &view, 200).expect("a configuration always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way `PutBucketEncryption` reads a write.
fn decode_write(document: &str) -> Result<dto::ServerSideEncryptionConfiguration, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?encryption", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketEncryption::decode(&view, body).map(|input| input.server_side_encryption_configuration)
}

/// The comparable projection of a `ByDefault` action: algorithm spelling and key id.
type ByDefaultProjection = Option<(String, Option<String>)>;

/// The comparable projection of a rule list. `ServerSideEncryptionRule` carries no `PartialEq` —
/// ADR-0004 keeps derived equality off the DTOs — so equality is spelled here, over every member,
/// in order. A member left out of this tuple is a member the identity would stop covering.
type Projection = Vec<(ByDefaultProjection, Option<bool>, Vec<String>)>;

fn projection(rules: &[dto::ServerSideEncryptionRule]) -> Projection {
    rules
        .iter()
        .map(|rule| {
            let by_default = rule
                .apply_server_side_encryption_by_default
                .as_ref()
                .map(|action| (action.sse_algorithm.as_str().to_owned(), action.kms_master_key_id.clone()));
            let blocked = rule
                .blocked_encryption_types
                .as_ref()
                .map(|types| types.encryption_type.iter().map(|t| t.as_str().to_owned()).collect())
                .unwrap_or_default();
            (by_default, rule.bucket_key_enabled, blocked)
        })
        .collect()
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// A KMS master key id: a plausible ARN. Only ever paired with a KMS algorithm, so the generator
/// never has to lean on `EncryptionRejection::KmsKeyWithoutKmsAlgorithm` — `ops::shared::
/// encryption`'s own unit tests own that refusal.
fn kms_key_id() -> impl Strategy<Value = String> {
    "arn:aws:kms:us-east-1:[0-9]{12}:key/[a-f0-9-]{8,36}"
}

/// A closed-set algorithm together with a key id that is legal beside it: `None` for the two
/// non-KMS algorithms, `Some`-or-`None` for the two KMS ones.
fn by_default() -> impl Strategy<Value = dto::ServerSideEncryptionByDefault> {
    prop_oneof![
        Just(dto::SseAlgorithm::AES256).prop_map(|algorithm| (algorithm, None)),
        Just(dto::SseAlgorithm::AWS_FSX).prop_map(|algorithm| (algorithm, None)),
        (Just(dto::SseAlgorithm::AWS_KMS), prop::option::of(kms_key_id())),
        (Just(dto::SseAlgorithm::AWS_KMS_DSSE), prop::option::of(kms_key_id())),
    ]
    .prop_map(|(sse_algorithm, kms_master_key_id)| dto::ServerSideEncryptionByDefault {
        sse_algorithm,
        kms_master_key_id,
    })
}

/// One of the documented blocked-encryption-type spellings. The list is a plain member, not a
/// closed set the codec enforces, so a repeated entry is exercised too (`blocked_encryption_types`
/// below allows duplicates).
fn encryption_type() -> impl Strategy<Value = dto::EncryptionType> {
    prop_oneof![
        Just(dto::EncryptionType::NONE),
        Just(dto::EncryptionType::SSE_C),
        Just(dto::EncryptionType::AES256),
        Just(dto::EncryptionType::AWS_KMS),
    ]
}

fn blocked_encryption_types() -> impl Strategy<Value = dto::BlockedEncryptionTypes> {
    prop::collection::vec(encryption_type(), 0..4).prop_map(|encryption_type| dto::BlockedEncryptionTypes { encryption_type })
}

fn encryption_rule() -> impl Strategy<Value = dto::ServerSideEncryptionRule> {
    (
        prop::option::of(by_default()),
        prop::option::of(any::<bool>()),
        prop::option::of(blocked_encryption_types()),
    )
        .prop_map(
            |(apply_server_side_encryption_by_default, bucket_key_enabled, blocked_encryption_types)| {
                dto::ServerSideEncryptionRule {
                    apply_server_side_encryption_by_default,
                    bucket_key_enabled,
                    blocked_encryption_types,
                }
            },
        )
}

/// One to four rules. `q-enc-0008`: nothing published bounds the rule list (`ENCRYPTION_RULE_MAX`
/// is `None`), so there is no ceiling to pin as a boundary the way CORS's hundred-rule cap is.
fn encryption_rules() -> impl Strategy<Value = Vec<dto::ServerSideEncryptionRule>> {
    prop::collection::vec(encryption_rule(), 1..5)
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the rules say, writing them and reading them back yields the same rules in the
    /// same order — and the document that carried them named no `Rules` wrapper.
    ///
    /// The three halves are one test on purpose. Identity alone is satisfied by any encoder and
    /// decoder that agree with each other, including a pair that agrees on a shape no SDK reads;
    /// the wrapper assertion is what stops the property from being self-fulfilling, and the
    /// legality assertion is what stops the generator from drifting into documents that would
    /// never reach a decoder in production anyway.
    #[test]
    fn a_configuration_survives_encode_then_decode(rules in encryption_rules()) {
        let generated = dto::ServerSideEncryptionConfiguration { rules: rules.clone() };
        prop_assert_eq!(validate_encryption(&generated), Ok(()), "the generator produced a document the family refuses");

        let document = encode_read(rules.clone());

        prop_assert!(
            !document.contains(FORBIDDEN_WRAPPER),
            "the written document carries the wrapper {FORBIDDEN_WRAPPER}, which makes every SDK read zero rules: {document}"
        );

        let decoded = decode_write(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(projection(&decoded.rules), projection(&rules), "document: {}", document);
    }
}

// ── the boundaries the property does not sample ──────────────────────────────────────────────

/// Reading is order-insensitive while writing is not: `XmlNode::child`/`children_named` match by
/// local name, so a sender that emits `BlockedEncryptionTypes` before `ApplyServerSideEncryption
/// ByDefault` is sending the same rule.
#[test]
fn a_rule_whose_members_arrive_in_another_order_is_the_same_rule() {
    let canonical = "<ServerSideEncryptionConfiguration><Rule>\
                     <ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>\
                     <KMSMasterKeyID>key-1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault>\
                     <BucketKeyEnabled>true</BucketKeyEnabled>\
                     <BlockedEncryptionTypes><EncryptionType>NONE</EncryptionType></BlockedEncryptionTypes>\
                     </Rule></ServerSideEncryptionConfiguration>";
    let shuffled = "<ServerSideEncryptionConfiguration><Rule>\
                    <BlockedEncryptionTypes><EncryptionType>NONE</EncryptionType></BlockedEncryptionTypes>\
                    <BucketKeyEnabled>true</BucketKeyEnabled>\
                    <ApplyServerSideEncryptionByDefault><KMSMasterKeyID>key-1</KMSMasterKeyID>\
                    <SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault>\
                    </Rule></ServerSideEncryptionConfiguration>";

    let first = decode_write(canonical).expect("the canonical order decodes");
    let second = decode_write(shuffled).expect("so does any other order");

    assert_eq!(projection(&second.rules), projection(&first.rules));
}

/// Text the writer has to escape, and text a reader is tempted to normalise. A `KMSMasterKeyID`
/// is opaque: a writer that emitted `&` raw would produce a document its own reader could not
/// parse, one that escaped on the way out and forgot to unescape on the way back would hand the
/// caller `&amp;`.
#[test]
fn a_key_id_of_awkward_text_comes_back_unchanged() {
    let awkward = "arn:aws:kms:us-east-1:111122223333:key/a & b < c > d \" e ' f";
    let rules = vec![dto::ServerSideEncryptionRule {
        apply_server_side_encryption_by_default: Some(dto::ServerSideEncryptionByDefault {
            sse_algorithm: dto::SseAlgorithm::AWS_KMS,
            kms_master_key_id: Some(awkward.to_owned()),
        }),
        ..dto::ServerSideEncryptionRule::default()
    }];

    let document = encode_read(rules.clone());
    assert!(!document.contains("a & b"), "the ampersand reached the document unescaped: {document}");

    let decoded = decode_write(&document).expect("a document this codec wrote is one it must read");

    assert_eq!(
        decoded.rules[0]
            .apply_server_side_encryption_by_default
            .as_ref()
            .and_then(|action| action.kms_master_key_id.as_deref()),
        Some(awkward)
    );
}

/// An element this release does not know is refused, not skipped (`q-enc-0006`). This is request
/// XML for a security configuration, so ADR-0007's `allow-registered` policy applies: a skipped
/// setting would be a 200 for a protection the gateway never stored. Stored bytes are a separate
/// boundary — the persistence codec still reads them (`security_request_policy.rs`).
#[test]
fn n_an_unknown_element_beside_a_known_rule_is_refused() {
    let document = "<ServerSideEncryptionConfiguration><Rule>\
                    <ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
                    </ApplyServerSideEncryptionByDefault><FutureMember>x</FutureMember></Rule>\
                    </ServerSideEncryptionConfiguration>";

    let error = decode_write(document).expect_err("an unknown security setting never reaches the handler");

    assert_eq!(error.code().as_str(), "MalformedXML");
}

// ── negative: the shapes that must never be stored ───────────────────────────────────────────

/// A wrapped rule list is the defect the flattened quirk exists for, seen from the read side. If
/// it survived, the round-trip property could be satisfied by a codec pair that had agreed on the
/// wrapper and nothing would stand between the wrapper and a release.
///
/// The wrapper is not an element the schema knows, so the `allow-registered` policy
/// (`q-enc-0006`) refuses it at the root, before the rule list is consulted. Under a skipping
/// policy the wrapper would take the only rule with it and the refusal would instead name the
/// empty `Rules` member; the `None` below is what separates the two layers.
#[test]
fn n_a_wrapped_rule_list_hides_every_rule_from_the_decoder() {
    let document = "<ServerSideEncryptionConfiguration><Rules><Rule>\
                    <ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
                    </ApplyServerSideEncryptionByDefault></Rule></Rules></ServerSideEncryptionConfiguration>";

    let error = decode_write(document).expect_err("a wrapper puts every rule out of the decoder's reach");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(
        error.member(),
        None,
        "the unknown-element guard refuses the wrapper before any member is read"
    );
}

/// The root with no rule at all. `PutBucketEncryption`'s `Rules` member is required, so clearing
/// the configuration is spelled `DeleteBucketEncryption`, never an empty document.
#[test]
fn n_a_configuration_with_no_rules_is_refused_by_the_decoder() {
    let error = decode_write("<ServerSideEncryptionConfiguration></ServerSideEncryptionConfiguration>")
        .expect_err("a rule-less document is not a policy");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(error.member(), Some("Rules"));
}

/// The decoder accepts an out-of-set algorithm — a schema violation is `ops::shared::encryption`'s
/// to catch, not the decoder's — so this pins which layer produces the refusal, the same way the
/// CORS sibling pins its own required-member refusals to the validator rather than the decoder.
#[test]
fn n_an_out_of_set_algorithm_decodes_and_is_refused_by_the_validator_not_the_decoder() {
    let document = "<ServerSideEncryptionConfiguration><Rule>\
                    <ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES512</SSEAlgorithm>\
                    </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";

    let decoded = decode_write(document).expect("an unrecognised algorithm spelling is a value, not a parse error");

    assert_eq!(
        decoded.rules[0]
            .apply_server_side_encryption_by_default
            .as_ref()
            .map(|action| action.sse_algorithm.as_str()),
        Some("AES512")
    );
    assert!(
        validate_encryption(&decoded).is_err(),
        "the semantic layer has to refuse what the decoder let through"
    );
}

/// The companion cross-member refusal: a `KMSMasterKeyID` beside `AES256` decodes — the decoder
/// checks no relationship between two present members — and is refused by the validator.
#[test]
fn n_a_kms_key_beside_a_non_kms_algorithm_decodes_and_is_refused_by_the_validator_not_the_decoder() {
    let document = "<ServerSideEncryptionConfiguration><Rule>\
                    <ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
                    <KMSMasterKeyID>key-1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault>\
                    </Rule></ServerSideEncryptionConfiguration>";

    let decoded = decode_write(document).expect("the decoder does not cross-check members against each other");

    assert!(
        validate_encryption(&decoded).is_err(),
        "the semantic layer has to refuse what the decoder let through"
    );
}
