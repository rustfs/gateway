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

//! POST Object's explicit body handoff and hand-authored codec boundary.
//!
//! Responsible for: proving that only a policy-prepared form reaches the decoder and that its
//! required bucket, resolved key and live file stream survive type erasure.
//! NOT responsible for: multipart parsing or signature verification, which the gateway owns.
//! Upstream: the public core/types API. Downstream: nothing.

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::dto::{PostObject, PostObjectFields, PostObjectInput};
use rustfs_gateway_types::{BucketName, ObjectKey};

fn meta() -> MetaView<'static> {
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", "multipart/form-data; boundary=x")
        .body(())
        .expect("valid request");
    let wire = Box::leak(Box::new(WireRequest::accept(request, &Limits::default()).expect("accepted request")));
    MetaView::of(wire, rustfs_gateway_core::TargetKind::Bucket).expect("bucket target")
}

fn prepared() -> PostObjectInput {
    PostObjectInput {
        bucket: BucketName::new("example-bucket").expect("valid bucket"),
        key: ObjectKey::new("uploads/report.txt").expect("valid key"),
        body: ByteStream::from_bytes(Bytes::from_static(b"report")),
        content_length: Some(6),
        content_type: Some("text/plain".to_owned()),
        metadata: vec![("source".to_owned(), "browser".to_owned())],
        fields: PostObjectFields::default(),
    }
}

#[test]
fn a_policy_prepared_form_survives_the_erased_decoder() {
    let input = PostObject::decode(&meta(), RequestBody::PostObject(Box::new(prepared()))).expect("a prepared form decodes");

    assert_eq!(input.bucket.as_str(), "example-bucket");
    assert_eq!(input.key.as_str(), "uploads/report.txt");
    assert_eq!(input.body.remaining_length().get(), Some(6));
    assert_eq!(input.content_length, Some(6), "the fixed length crosses the decoder with the stream");
}

#[test]
fn an_absent_body_cannot_enter_the_post_object_handler() {
    assert!(PostObject::decode(&meta(), RequestBody::None).is_err());
}

#[test]
fn a_buffered_body_cannot_bypass_the_form_policy_stage() {
    assert!(PostObject::decode(&meta(), RequestBody::Buffered(Bytes::from_static(b"not a form proof"))).is_err());
}

#[test]
fn a_plain_live_stream_cannot_bypass_the_form_policy_stage() {
    assert!(
        PostObject::decode(&meta(), RequestBody::Stream(ByteStream::from_bytes(Bytes::from_static(b"unproved file"))),).is_err()
    );
}
