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

//! Required upload-id presence in the multipart input codecs.
//!
//! Responsible for: separating an empty query value from a missing binding or unfilled DTO.
//! NOT responsible for: HTTP routing or storage authorization and lookup.
//! Upstream: accepted HTTP request metadata. Downstream: decoded multipart inputs.

use bytes::Bytes;
use rustfs_gateway_core::{CodecError, MetaView, OperationCodec, RequestBody, TargetKind};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::{BucketName, ObjectKey, dto};

fn decode<O: OperationCodec>(
    method: &str,
    query: &str,
    extra_header: Option<(&str, &str)>,
    body: RequestBody,
) -> (&'static str, Result<(), CodecError>) {
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("http://host.invalid/target/key?{query}"))
        .header("host", "host.invalid");
    if let Some((name, value)) = extra_header {
        request = request.header(name, value);
    }
    let wire = WireRequest::accept(request.body(()).expect("valid request"), &Limits::default()).expect("accepted request");
    let view = MetaView::of(&wire, TargetKind::Object).expect("request metadata");
    (O::NAME, O::decode(&view, body).map(|_| ()))
}

fn decode_multipart(upload_query: &str) -> [(&'static str, Result<(), CodecError>); 5] {
    let part_query = if upload_query.is_empty() {
        "partNumber=1".to_owned()
    } else {
        format!("partNumber=1&{upload_query}")
    };
    [
        decode::<dto::AbortMultipartUpload>("DELETE", upload_query, None, RequestBody::None),
        decode::<dto::CompleteMultipartUpload>(
            "POST",
            upload_query,
            None,
            RequestBody::Buffered(Bytes::from_static(
                b"<CompleteMultipartUpload><Part><ETag>&quot;abc&quot;</ETag><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>",
            )),
        ),
        decode::<dto::ListParts>("GET", upload_query, None, RequestBody::None),
        decode::<dto::UploadPart>(
            "PUT",
            &part_query,
            Some(("content-length", "4")),
            RequestBody::Stream(ByteStream::from_bytes(Bytes::from_static(b"part"))),
        ),
        decode::<dto::UploadPartCopy>("PUT", &part_query, Some(("x-amz-copy-source", "source/key")), RequestBody::None),
    ]
}

#[test]
fn an_explicit_empty_upload_id_passes_the_multipart_required_checks() {
    let outcomes = decode_multipart("uploadId=");
    assert!(outcomes.iter().all(|(_, result)| result.is_ok()), "{outcomes:?}");
}

#[test]
fn a_nonempty_upload_id_passes_the_multipart_required_checks() {
    let outcomes = decode_multipart("uploadId=upload-0001");
    assert!(outcomes.iter().all(|(_, result)| result.is_ok()), "{outcomes:?}");
}

#[test]
fn a_missing_upload_id_is_refused_by_every_multipart_binding() {
    for (operation, result) in decode_multipart("") {
        let error = result.expect_err("missing upload ID must be refused");
        assert_eq!(error.member(), Some("UploadId"), "{operation}");
        assert_eq!(error.message(), "the request omits a member the wire contract requires", "{operation}");
    }
}

#[test]
fn an_unfilled_abort_upload_id_is_still_rejected() {
    let input = dto::AbortMultipartUploadInput {
        bucket: BucketName::new("target").expect("valid bucket"),
        key: ObjectKey::new("key").expect("valid key"),
        ..Default::default()
    };
    let error = input.check_required().expect_err("an unfilled upload ID must be refused");
    assert_eq!(error.member(), "UploadId");
}
