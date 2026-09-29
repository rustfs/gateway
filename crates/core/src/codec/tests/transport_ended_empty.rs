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

//! The zero length a view reads for an upload the transport ended empty, seen through the
//! generated `PutObject` and `UploadPart` decoders.
//!
//! Responsible for: an absent `Content-Length` decoding as `0` under the reading, and everything
//! else — a length the request carries, a view without the reading, another header — decoding
//! exactly as it did before.
//! NOT responsible for: when an assembly applies the reading (`rustfs-gateway`'s builder), or the
//! default refusal, which `super`'s `n_refuses_a_put_with_no_content_length_using_the_code_the_overlay_names`
//! pins.
//! Upstream: `crate::codec::view::MetaView::with_transport_ended_empty_body`. Downstream: nothing.

use super::*;

fn put(headers: &[(&str, &str)], ended_empty: bool) -> Result<i64, crate::codec::CodecError> {
    let request = accepted("PUT", "/photos/key", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let view = if ended_empty {
        view.with_transport_ended_empty_body()
    } else {
        view
    };
    dto::PutObject::decode(&view, RequestBody::None).map(|input| input.content_length)
}

fn upload_part(headers: &[(&str, &str)], ended_empty: bool) -> Result<i64, crate::codec::CodecError> {
    let request = accepted("PUT", "/photos/key?partNumber=1&uploadId=abc", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let view = if ended_empty {
        view.with_transport_ended_empty_body()
    } else {
        view
    };
    dto::UploadPart::decode(&view, RequestBody::None).map(|input| input.content_length)
}

#[test]
fn an_absent_content_length_decodes_as_zero_under_the_reading() {
    assert_eq!(put(&[], true).ok(), Some(0));
    assert_eq!(upload_part(&[], true).ok(), Some(0));
}

#[test]
fn n_without_the_reading_an_absent_content_length_is_still_411() {
    for error in [
        put(&[], false).expect_err("the default requires the header"),
        upload_part(&[], false).expect_err("the default requires the header"),
    ] {
        assert_eq!(error.code().as_str(), "MissingContentLength");
        assert_eq!(error.status(), StatusCode::LENGTH_REQUIRED);
        assert_eq!(error.member(), Some("ContentLength"));
    }
}

#[test]
fn n_a_content_length_the_request_carries_is_never_replaced() {
    for raw in ["0", "3", "5368709120"] {
        let expected: i64 = raw.parse().expect("a test length");
        assert_eq!(put(&[("content-length", raw)], true).ok(), Some(expected), "content-length: {raw}");
        assert_eq!(
            upload_part(&[("content-length", raw)], true).ok(),
            Some(expected),
            "content-length: {raw}"
        );
    }
}

#[test]
fn n_the_reading_answers_no_other_header() {
    let request = accepted("PUT", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object)
        .expect("view")
        .with_transport_ended_empty_body();
    assert_eq!(view.header("content-length").as_deref(), Some("0"));
    for other in [
        "x-amz-decoded-content-length",
        "content-encoding",
        "transfer-encoding",
        "content-md5",
    ] {
        assert_eq!(view.header(other), None, "{other}");
    }
}

#[test]
fn n_an_aws_chunked_body_still_reads_its_decoded_length() {
    let request = accepted("PUT", "/photos/key", &[("content-encoding", "aws-chunked")]);
    let view = MetaView::of(&request, TargetKind::Object)
        .expect("view")
        .with_transport_ended_empty_body()
        .with_framed_content_length(11);
    assert_eq!(view.header("content-length").as_deref(), Some("11"));
    assert_eq!(view.header("content-encoding"), None);
}
