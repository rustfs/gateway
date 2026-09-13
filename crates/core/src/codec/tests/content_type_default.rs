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

//! `q-content-0008`: where the S3 default media type is applied — on the read, never on the write.
//!
//! Responsible for: the wire contract of the default — a write without `Content-Type` decodes to
//! no type, so the backend decides what an untyped object is (rustfs/gateway#749), and a read whose
//! backend names no type still answers `binary/octet-stream`, so the AWS answer stays the default
//! for every deployment.
//! NOT responsible for: what a backend stores (`rustfs-gateway-fs`, the conformance reference
//! backend), or the migration ruling (`rd-put-0001` in the goldens register).
//! Upstream: the parent codec test helpers. Downstream: nothing; this is a leaf test module.

use super::*;

/// The AWS default, spelled once so a test that expects the IANA spelling cannot pass by accident.
const S3_DEFAULT: &str = "binary/octet-stream";

fn put(headers: &[(&str, &str)]) -> dto::PutObjectInput {
    let mut all = vec![("content-length", "0")];
    all.extend_from_slice(headers);
    let request = accepted("PUT", "/photos/a.png", &all);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    dto::PutObject::decode(&view, RequestBody::None).expect("a well-formed write decodes")
}

/// Negative — an absent header is not turned into a type the client never sent.
#[test]
fn n_a_put_without_a_content_type_decodes_to_no_type() {
    assert_eq!(put(&[]).content_type, None);
}

/// Positive — a type the client sent is kept exactly as sent.
#[test]
fn a_put_keeps_the_content_type_it_was_sent() {
    assert_eq!(put(&[("content-type", "image/png")]).content_type.as_deref(), Some("image/png"));
}

/// Negative — a client that sends the default spelling explicitly is not told it sent nothing.
#[test]
fn n_a_put_that_names_the_default_keeps_it_as_sent() {
    assert_eq!(put(&[("content-type", S3_DEFAULT)]).content_type.as_deref(), Some(S3_DEFAULT));
}

/// Negative — the multipart create shares the rule: no header, no type.
#[test]
fn n_a_multipart_create_without_a_content_type_decodes_to_no_type() {
    let request = accepted("POST", "/photos/a.png?uploads", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let input = dto::CreateMultipartUpload::decode(&view, RequestBody::None).expect("decodes");
    assert_eq!(input.content_type, None);
}

/// Negative — a read whose backend names no type still answers the S3 default rather than
/// omitting the header, which is what crashed the `aws-sdk-go-v2` suite (rustfs/gateway#718).
#[test]
fn n_a_get_whose_backend_names_no_type_answers_the_s3_default() {
    let request = accepted("GET", "/photos/a.png", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let response = dto::GetObject::encode(dto::GetObjectOutput::default(), &view, 200).expect("encodes");
    assert_eq!(header(&response, "content-type").as_deref(), Some(S3_DEFAULT));
}

/// Negative — the same for `HEAD`, which a client uses to learn the type before it downloads.
#[test]
fn n_a_head_whose_backend_names_no_type_answers_the_s3_default() {
    let request = accepted("HEAD", "/photos/a.png", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let response = dto::HeadObject::encode(dto::HeadObjectOutput::default(), &view, 200).expect("encodes");
    assert_eq!(header(&response, "content-type").as_deref(), Some(S3_DEFAULT));
}

/// Negative — a `304` describes no representation (RFC 9110 §15.4.5), so the default is not
/// written on one: a revalidation answer that names a type the client never asked about is what
/// `c-cond-0005`, `c-cond-0007`, `c-cond-0017` and `c-cond-0022` refuse.
#[test]
fn n_a_not_modified_answer_carries_no_default_type() {
    let request = accepted("GET", "/photos/a.png", &[("if-none-match", "\"abc\"")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let response = dto::GetObject::encode(dto::GetObjectOutput::default(), &view, 304).expect("encodes");
    assert_eq!(response.status, StatusCode::NOT_MODIFIED);
    assert_eq!(header(&response, "content-type"), None);
}

/// Positive — a type the backend names (RustFS's guess from the key, say) is what the read answers.
#[test]
fn a_get_answers_the_type_its_backend_names() {
    let request = accepted("GET", "/photos/a.png", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectOutput {
        content_type: Some("image/png".to_owned()),
        ..Default::default()
    };
    let response = dto::GetObject::encode(output, &view, 200).expect("encodes");
    assert_eq!(header(&response, "content-type").as_deref(), Some("image/png"));
}

/// Negative — the default is a fallback for the object's own type, not a header written after the
/// `response-content-type` override; the override still wins over it.
#[test]
fn n_the_response_override_wins_over_the_default() {
    let request = accepted("GET", "/photos/a.png?response-content-type=text/plain", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let response = dto::GetObject::encode(dto::GetObjectOutput::default(), &view, 200).expect("encodes");
    assert_eq!(header(&response, "content-type").as_deref(), Some("text/plain"));
}
