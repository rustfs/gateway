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

//! Responsible for: security XML request decoders rejecting unregistered children, and the
//! boundary beside them — the same bytes stay readable through the persisted-metadata codecs.
//! NOT responsible for: the persisted codecs' own rules, signature validation, or storage
//! enforcement.
//! Upstream: generated operation codecs and `rustfs_gateway_types::persistence`. Downstream:
//! security configuration handlers and metadata consumers.

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

const DOCUMENTS: &[(&str, &str)] = &[
    (
        "object-lock",
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
    ),
    (
        "retention",
        "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>",
    ),
    ("legal-hold", "<LegalHold><Status>ON</Status></LegalHold>"),
    (
        "encryption",
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
    ),
    (
        "publicAccessBlock",
        "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>",
    ),
];

fn decode(operation: &str, document: &str) -> Result<(), CodecError> {
    let object = matches!(operation, "retention" | "legal-hold");
    let path = if object { "/photos/key" } else { "/photos" };
    let request = Request::builder()
        .method("PUT")
        .uri(format!("http://host.invalid{path}?{operation}"))
        .header("host", "host.invalid")
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .body(())
        .expect("the fixture request is valid");
    let request = WireRequest::accept(request, &Limits::default()).expect("the fixture head is valid");
    let kind = if object { TargetKind::Object } else { TargetKind::Bucket };
    let view = MetaView::of(&request, kind).expect("the fixture target is valid");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    match operation {
        "object-lock" => dto::PutObjectLockConfiguration::decode(&view, body).map(|_| ()),
        "retention" => dto::PutObjectRetention::decode(&view, body).map(|_| ()),
        "legal-hold" => dto::PutObjectLegalHold::decode(&view, body).map(|_| ()),
        "encryption" => dto::PutBucketEncryption::decode(&view, body).map(|_| ()),
        "publicAccessBlock" => dto::PutPublicAccessBlock::decode(&view, body).map(|_| ()),
        _ => panic!("unknown test operation"),
    }
}

#[test]
fn n_a_security_requests_accept_known_fields() {
    for &(operation, document) in DOCUMENTS {
        assert!(decode(operation, document).is_ok(), "known {operation} fixture");
    }
}

fn refuses_unknown(operation: &str, element: Option<&str>) {
    let document = DOCUMENTS
        .iter()
        .find(|(name, _)| *name == operation)
        .expect("known fixture")
        .1;
    let end = match element {
        Some(element) => document.find(&format!("</{element}>")).expect("known nested fixture element"),
        None => document.rfind("</").expect("known fixture root"),
    };
    let document = format!("{}<FutureSetting>true</FutureSetting>{}", &document[..end], &document[end..]);
    let error = decode(operation, &document).expect_err("unregistered security fields must not reach the handler");
    assert_eq!(error.code().as_str(), "MalformedXML", "{operation}");
}

#[test]
fn n_a_security_request_refuses_unknown_lock_root() {
    refuses_unknown("object-lock", None);
}

#[test]
fn n_a_security_request_refuses_unknown_retention_root() {
    refuses_unknown("retention", None);
}

#[test]
fn n_a_security_request_refuses_unknown_legal_hold_root() {
    refuses_unknown("legal-hold", None);
}

#[test]
fn n_a_security_request_refuses_unknown_encryption_root() {
    refuses_unknown("encryption", None);
}

#[test]
fn n_a_security_request_refuses_unknown_public_access_root() {
    refuses_unknown("publicAccessBlock", None);
}

#[test]
fn n_a_security_request_refuses_unknown_lock_rule() {
    refuses_unknown("object-lock", Some("Rule"));
}

#[test]
fn n_a_security_request_refuses_unknown_lock_default() {
    refuses_unknown("object-lock", Some("DefaultRetention"));
}

#[test]
fn n_a_security_request_refuses_unknown_encryption_rule() {
    refuses_unknown("encryption", Some("Rule"));
}

#[test]
fn n_a_security_request_refuses_unknown_encryption_default() {
    refuses_unknown("encryption", Some("ApplyServerSideEncryptionByDefault"));
}

/// The request refusal must not leak into the persisted boundary (ADR-0007): a document already
/// stored with an element this release does not know is still read, with every known field, by
/// the metadata codec — a stricter reader there would turn WORM, default encryption or the public
/// access block off. Each document is first shown to be refused on the request path, so the pair
/// proves the two policies differ on the same bytes.
fn with_unknown_root(operation: &str) -> String {
    let document = DOCUMENTS
        .iter()
        .find(|(name, _)| *name == operation)
        .expect("known fixture")
        .1;
    let end = document.rfind("</").expect("known fixture root");
    let document = format!("{}<FutureSetting>true</FutureSetting>{}", &document[..end], &document[end..]);
    assert!(decode(operation, &document).is_err(), "{operation} is refused on the request path");
    document
}

#[test]
fn persisted_lock_bytes_with_an_unknown_root_element_stay_readable() {
    let stored = rustfs_gateway_types::persistence::parse_object_lock_dto(with_unknown_root("object-lock").as_bytes())
        .expect("stored WORM metadata stays readable");
    assert_eq!(stored.object_lock_enabled.as_ref().map(dto::ObjectLockEnabled::as_str), Some("Enabled"));
    let retention = stored
        .rule
        .and_then(|rule| rule.default_retention)
        .expect("the rule survives");
    assert_eq!(retention.mode.as_ref().map(dto::Mode::as_str), Some("GOVERNANCE"));
    assert_eq!(retention.days, Some(1));
}

#[test]
fn persisted_encryption_bytes_with_an_unknown_root_element_stay_readable() {
    let stored = rustfs_gateway_types::persistence::parse_bucket_encryption_dto(with_unknown_root("encryption").as_bytes())
        .expect("stored default encryption stays readable");
    let algorithm = stored.rules[0]
        .apply_server_side_encryption_by_default
        .as_ref()
        .map(|default| default.sse_algorithm.as_str().to_owned());
    assert_eq!(algorithm.as_deref(), Some("AES256"));
}

#[test]
fn persisted_public_access_bytes_with_an_unknown_root_element_stay_readable() {
    let stored =
        rustfs_gateway_types::persistence::parse_public_access_block_dto(with_unknown_root("publicAccessBlock").as_bytes())
            .expect("stored public access block stays readable");
    assert_eq!(stored.block_public_acls, Some(true));
}
