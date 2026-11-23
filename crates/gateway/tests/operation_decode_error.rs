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

//! Exercises a host mapping one registered operation's decode refusal over signed HTTP.
//! The codec still validates the input and the handler sees only successful decodes.
//! Uses the standard completion registration to compare the wire error with and without the mapping.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Method, StatusCode};
use rustfs_gateway::{CodecError, ErrorCode, Handler, HandlerError, HandlerResult, Req, S3Service, dto};

use crate::support;

struct Completion(AtomicUsize);

impl Handler<dto::CompleteMultipartUpload> for Completion {
    async fn call(&self, req: Req<dto::CompleteMultipartUpload>) -> HandlerResult<dto::CompleteMultipartUpload> {
        self.0.fetch_add(1, Ordering::Relaxed);
        assert_eq!(req.input().multipart_upload.parts.first().map(|part| part.part_number), Some(0));
        Err(HandlerError::new(ErrorCode::INVALID_PART_ORDER, "explicit zero reached the handler"))
    }
}

fn missing_number() -> CodecError {
    CodecError::malformed_xml("the body omits a member the schema requires").about("PartNumber")
}

fn service(mapped: bool) -> (S3Service, Arc<Completion>) {
    let handler = Arc::new(Completion(AtomicUsize::new(0)));
    let builder = support::wired_at_signed_time()
        .accept_all_checksum_omissions()
        .read_request_documents_as_rustfs();
    let builder = if mapped {
        builder.register_with_decode_error_mapping::<dto::CompleteMultipartUpload, _>(
            Arc::clone(&handler),
            missing_number(),
            CodecError::new(ErrorCode::INVALID_PART, "part number is missing"),
        )
    } else {
        builder.register::<dto::CompleteMultipartUpload, _>(Arc::clone(&handler))
    };
    (builder.build().expect("a valid fixture"), handler)
}

async fn complete(service: &S3Service, part: &str) -> (StatusCode, String) {
    let body = Bytes::from(format!("<CompleteMultipartUpload><Part>{part}</Part></CompleteMultipartUpload>"));
    let request = support::signed_target_with_body(Method::POST, "/bucket/key?uploadId=id", body);
    support::exchange(service, request).await
}

#[tokio::test]
async fn a_missing_member_can_be_answered_by_its_host_without_dispatching() {
    let (service, handler) = service(true);
    let (status, body) = complete(&service, "<ETag>abc</ETag>").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(support::element_text(&body, "Code"), Some("InvalidPart"));
    assert_eq!(support::element_text(&body, "Message"), Some("part number is missing"));
    assert_eq!(support::element_text(&body, "Resource"), None);
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn n_a_different_malformed_member_keeps_its_codec_error() {
    let (service, handler) = service(true);
    let (status, body) = complete(&service, "<PartNumber>not-an-integer</PartNumber>").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(support::element_text(&body, "Code"), Some("MalformedXML"));
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn n_an_explicit_part_number_reaches_its_handler_with_either_registration() {
    for mapped in [true, false] {
        let (service, handler) = service(mapped);
        let (status, body) = complete(&service, "<PartNumber>0</PartNumber>").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(support::element_text(&body, "Code"), Some("InvalidPartOrder"));
        assert_eq!(handler.0.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn n_the_standard_registration_keeps_the_generated_missing_member_refusal() {
    let (service, handler) = service(false);
    let (status, body) = complete(&service, "<ETag>abc</ETag>").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(support::element_text(&body, "Code"), Some("MalformedXML"));
    assert_eq!(support::element_text(&body, "Resource"), Some("PartNumber"));
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn n_a_mapping_cannot_turn_a_refusal_into_a_success() {
    let handler = Arc::new(Completion(AtomicUsize::new(0)));
    let service = support::wired_at_signed_time()
        .accept_all_checksum_omissions()
        .register_with_decode_error_mapping::<dto::CompleteMultipartUpload, _>(
            Arc::clone(&handler),
            missing_number(),
            CodecError::new(ErrorCode::custom("Wrong", StatusCode::OK), "unreachable"),
        )
        .build()
        .expect("a fixture");
    let (status, body) = complete(&service, "<ETag>abc</ETag>").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(support::element_text(&body, "Code"), Some("InternalError"));
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}

#[test]
fn n_a_static_dispatch_cannot_silently_discard_a_mapping() {
    type Ops = rustfs_gateway::OperationSetNode<dto::CompleteMultipartUpload, rustfs_gateway::OperationSetEnd>;
    let handler = Arc::new(Completion(AtomicUsize::new(0)));
    let result = support::wired_at_signed_time()
        .register_with_decode_error_mapping::<dto::CompleteMultipartUpload, _>(
            Arc::clone(&handler),
            missing_number(),
            CodecError::new(ErrorCode::INVALID_PART, "missing part"),
        )
        .build_monomorphic::<_, Ops>(handler);
    assert!(matches!(result, Err(rustfs_gateway::AssemblyError::MonomorphicSet { .. })));
}

impl Handler<dto::PutBucketTagging> for Completion {
    async fn call(&self, _request: Req<dto::PutBucketTagging>) -> HandlerResult<dto::PutBucketTagging> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(HandlerError::internal_error("malformed tag set reached its handler"))
    }
}

#[tokio::test]
async fn n_an_identical_refusal_from_another_operation_is_unaffected() {
    let handler = Arc::new(Completion(AtomicUsize::new(0)));
    let service = support::wired_at_signed_time()
        .accept_all_checksum_omissions()
        .read_request_documents_as_rustfs()
        .register_with_decode_error_mapping::<dto::CompleteMultipartUpload, _>(
            Arc::clone(&handler),
            CodecError::malformed_xml("the request body is not the XML this operation accepts"),
            CodecError::new(ErrorCode::INVALID_PART, "bad completion XML"),
        )
        .register::<dto::PutBucketTagging, _>(Arc::clone(&handler))
        .build()
        .expect("both operations registered");
    for (method, path, code) in [
        (Method::POST, "/bucket/key?uploadId=id", "InvalidPart"),
        (Method::PUT, "/bucket?tagging", "MalformedXML"),
    ] {
        let request = support::signed_target_with_body(method, path, Bytes::from_static(b"<"));
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(support::element_text(&body, "Code"), Some(code));
    }
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
}
