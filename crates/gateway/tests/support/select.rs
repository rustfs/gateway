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

//! The signed SelectObjectContent event-stream fixture shared by dispatch paths.
//!
//! Responsible for: producing one valid signed request and one framed event-stream answer.
//! NOT responsible for: asserting how a service transports that answer.
//! Upstream: shared signing constants. Downstream: dynamic/static pipeline parity tests.

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{ByteStream, EventSequence, Handler, HandlerResult, Req, Resp, stats_document};

use super::SIGNED_AT_STAMP;

pub struct SelectBackend;

impl Handler<rustfs_gateway::dto::SelectObjectContent> for SelectBackend {
    async fn call(
        &self,
        _request: Req<rustfs_gateway::dto::SelectObjectContent>,
    ) -> HandlerResult<rustfs_gateway::dto::SelectObjectContent> {
        let mut frames = Vec::new();
        let mut sequence = EventSequence::new();
        sequence.records(b"a,b\n1,2\n", &mut frames).expect("records first");
        sequence.stats(&stats_document(8, 8, 8), &mut frames).expect("accounting");
        sequence.end(&mut frames).expect("terminator");
        Ok(Resp::event_stream(ByteStream::from_bytes(Bytes::from(frames))))
    }
}

#[must_use]
pub fn signed_select(body: Bytes) -> http::Request<Bytes> {
    let target = "/bucket/rows.csv?select&select-type=2";
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/xml"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&body.len().to_string()).expect("a content length"),
    );
    let probe = http::Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let mut signer = SigV4Signer::new(credentials, scope);
    let signing = SigningRequest::new(
        &http::Method::POST,
        "/bucket/rows.csv",
        "select&select-type=2",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    )
    .with_wire_content_length(body.len() as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut builder = http::Request::builder().method(http::Method::POST).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(body).expect("a valid request")
}
