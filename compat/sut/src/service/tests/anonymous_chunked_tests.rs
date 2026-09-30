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

//! An anonymous aws-chunked upload as the RustFS-profile launcher serves it (rustfs/gateway#1060).
//!
//! Responsible for: proving the launcher turns on the RustFS profile's switch that leaves an
//! anonymous aws-chunked body undecoded, so a public-write bucket refuses an anonymous
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` upload and stores nothing, as legacy RustFS does, while an
//! ordinary anonymous write the same policy allows is stored.
//! NOT responsible for: the decode the generic gateway applies, or the switch itself
//! (`crates/gateway/tests/anonymous_chunked_upload.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::policy_tests::{policed, put_policy};
use super::*;

const PUBLIC_WRITE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:PutObject","s3:GetObject"],"Resource":"arn:aws:s3:::policed/*"}]}"#;
const PUBLIC_WRITE_MD5: &str = "kzbq+ZlTR/f0yIJkhorYxg==";

/// `hello world` in unsigned trailer framing, with its CRC32 as the trailing checksum.
const FRAMED: &[u8] = b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n";

fn anonymous_put(target: &str, headers: &[(&str, &str)], body: &'static [u8]) -> http::Request<Bytes> {
    let mut request = http::Request::builder()
        .method(http::Method::PUT)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Bytes::from_static(body)).expect("a valid unsigned request")
}

/// Negative — a public-write bucket refuses an anonymous unsigned-trailer upload and stores no
/// object, as legacy RustFS does; the plain anonymous write beside it proves the policy admits
/// anonymous writes, so the refusal is the undecoded framing and not the policy.
#[tokio::test]
async fn n_an_anonymous_unsigned_trailer_upload_is_refused_and_stores_nothing() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    let written = put_policy(&service, PUBLIC_WRITE, PUBLIC_WRITE_MD5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));

    let plain = exchange(&service, anonymous_put("/policed/plain", &[], b"hello world")).await;
    assert_eq!(plain.status(), 200, "{}", body_of(&plain));

    let chunked = exchange(
        &service,
        anonymous_put(
            "/policed/chunked",
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
                ("x-amz-trailer", "x-amz-checksum-crc32"),
                ("x-amz-decoded-content-length", "11"),
            ],
            FRAMED,
        ),
    )
    .await;
    assert_eq!(chunked.status(), 400, "{}", body_of(&chunked));

    let stored = exchange(&service, as_main(http::Method::GET, "/policed/chunked", Bytes::new())).await;
    assert_eq!(stored.status(), 404, "{}", body_of(&stored));
    assert!(body_of(&stored).contains("<Code>NoSuchKey</Code>"), "{}", body_of(&stored));
}
