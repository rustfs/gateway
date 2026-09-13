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

//! Responsible for: security XML request decoders rejecting unregistered children.
//! NOT responsible for: persisted metadata reads, signature validation, or storage enforcement.
//! Upstream: generated operation codecs. Downstream: security configuration handlers.

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
