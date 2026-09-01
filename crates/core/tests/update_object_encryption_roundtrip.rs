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

//! Runtime request-codec coverage for `UpdateObjectEncryption`.
//!
//! Responsible for: proving that the required `ObjectEncryption` structural union selects exactly
//! one modeled XML child and reaches the typed input as that enum variant.
//! NOT responsible for: KMS authorization or applying the encryption change to stored data; those
//! are backend semantics after the gateway has preserved the request.
//! Upstream: generated UpdateObjectEncryption DTO and codec. Downstream: handler implementations.

#![allow(clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

fn decode(document: &str) -> Result<dto::UpdateObjectEncryptionInput, CodecError> {
    let request = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket/key?encryption&versionId=v1")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    let request = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    dto::UpdateObjectEncryption::decode(&view, RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes())))
}

fn assert_malformed(document: &str, message: &str) {
    let error = decode(document).expect_err("the structural union must fail closed");
    assert_eq!(error.code().as_str(), "MalformedXML", "{error:?}");
    assert!(error.message().contains(message), "{error:?}");
}

#[test]
fn one_ssekms_child_decodes_to_the_real_required_union_variant() {
    let input = decode(
        "<ObjectEncryption><SSE-KMS><KMSKeyArn>arn:aws:kms:region:123456789012:key/id</KMSKeyArn><BucketKeyEnabled>true</BucketKeyEnabled></SSE-KMS></ObjectEncryption>",
    )
    .expect("one modeled variant is a complete encryption selection");

    match input.object_encryption {
        dto::ObjectEncryption::Ssekms(value) => {
            assert_eq!(value.kms_key_arn, "arn:aws:kms:region:123456789012:key/id");
            assert_eq!(value.bucket_key_enabled, Some(true));
        }
        _ => panic!("the current modeled child must select SSEKMS"),
    }
    assert_eq!(input.version_id.as_deref(), Some("v1"));
}

#[test]
fn n_an_empty_union_root_is_refused() {
    assert_malformed("<ObjectEncryption/>", "selects no modeled variant");
}

#[test]
fn n_an_unknown_union_child_is_refused() {
    assert_malformed("<ObjectEncryption><FutureMode/></ObjectEncryption>", "contains an unknown variant");
}

#[test]
fn n_two_known_union_children_are_refused_as_ambiguous() {
    assert_malformed(
        "<ObjectEncryption><SSE-KMS><KMSKeyArn>a</KMSKeyArn></SSE-KMS><SSE-KMS><KMSKeyArn>b</KMSKeyArn></SSE-KMS></ObjectEncryption>",
        "selects more than one variant",
    );
}

#[test]
fn n_a_known_child_plus_an_unknown_child_is_refused() {
    assert_malformed(
        "<ObjectEncryption><SSE-KMS><KMSKeyArn>a</KMSKeyArn></SSE-KMS><FutureMode/></ObjectEncryption>",
        "contains an unknown variant",
    );
}

#[test]
fn n_the_selected_variant_cannot_omit_its_required_payload_member() {
    assert_malformed(
        "<ObjectEncryption><SSE-KMS><BucketKeyEnabled>true</BucketKeyEnabled></SSE-KMS></ObjectEncryption>",
        "omits a member",
    );
}

#[test]
fn n_another_document_root_cannot_supply_the_union() {
    assert_malformed("<Encryption><SSE-KMS><KMSKeyArn>a</KMSKeyArn></SSE-KMS></Encryption>", "wrong root");
}
