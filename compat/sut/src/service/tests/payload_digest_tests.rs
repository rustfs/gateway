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

//! A header-signed `x-amz-content-sha256` given in base64, read by the RustFS-profile launcher as
//! legacy RustFS reads it (rustfs/gateway#1130).
//!
//! Responsible for: pinning, through the served assembly, that such a digest is signed as its
//! lowercase hex — a signature over the hex is verified and the body stored, a signature over the
//! base64 text as sent is `403 SignatureDoesNotMatch` and stores nothing — and that the body is
//! still held to the digest, refused with legacy RustFS's `400 BadDigest` when it does not match.
//! NOT responsible for: a presigned request's declaration (`presigned_payload_tests.rs`), or a
//! hex digest, which both readings sign as sent.
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.

use super::hand_signer::{HandSigned, sha256_base64, sha256_hex};
use super::*;

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/digests", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/digests/k", Bytes::from_static(b"stored"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

async fn read(service: &S3Service, path: &str) -> (u16, String) {
    let answer = exchange(service, as_main(http::Method::GET, path, Bytes::new())).await;
    (answer.status().as_u16(), body_of(&answer))
}

/// A header-signed request declaring `body`'s digest in base64 and signing `line`.
fn base64_declared(method: http::Method, path: &'static str, body: &'static [u8], line: String) -> http::Request<Bytes> {
    HandSigned::new(method, path, Bytes::from_static(body))
        .declaring(sha256_base64(body))
        .signing_payload_line(line)
        .request()
}

/// Positive — a base64 digest signed as its hex is verified: a read is served and an upload stored,
/// as legacy RustFS serves and stores them.
#[tokio::test]
async fn a_base64_digest_signed_as_its_hex_is_verified() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let get = base64_declared(http::Method::GET, "/digests/k", b"", sha256_hex(b""));
    let answer = exchange(&service, get).await;
    assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"));
    let put = base64_declared(http::Method::PUT, "/digests/new", b"uploaded", sha256_hex(b"uploaded"));
    let answer = exchange(&service, put).await;
    assert_eq!(answer.status(), 200, "{}", body_of(&answer));
    assert_eq!(read(&service, "/digests/new").await, (200, "uploaded".to_owned()));
}

/// Negative — a base64 digest signed as the base64 text it was sent as is `403
/// SignatureDoesNotMatch`: a read is not served and an upload stores nothing.
#[tokio::test]
async fn n_a_base64_digest_signed_as_sent_is_refused() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let get = base64_declared(http::Method::GET, "/digests/k", b"", sha256_base64(b""));
    let answer = exchange(&service, get).await;
    assert_eq!(answer.status(), 403, "{}", body_of(&answer));
    assert!(body_of(&answer).contains("<Code>SignatureDoesNotMatch</Code>"), "{}", body_of(&answer));
    for path in ["/digests/absent", "/digests/k"] {
        let put = base64_declared(http::Method::PUT, path, b"forged", sha256_base64(b"forged"));
        let answer = exchange(&service, put).await;
        assert_eq!(answer.status(), 403, "{path}: {}", body_of(&answer));
    }
    assert_eq!(read(&service, "/digests/absent").await.0, 404);
    assert_eq!(read(&service, "/digests/k").await, (200, "stored".to_owned()));
}

/// Negative — the body is held to the digest: an upload whose body does not hash to the base64
/// digest it declares, signed over that digest's hex, is legacy RustFS's `400 BadDigest`, and
/// neither a new key nor an overwrite is stored.
#[tokio::test]
async fn n_a_body_that_does_not_match_its_base64_digest_is_bad_digest() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for path in ["/digests/absent", "/digests/k"] {
        let put = HandSigned::new(http::Method::PUT, path, Bytes::from_static(b"replaced"))
            .declaring(sha256_base64(b"other"))
            .signing_payload_line(sha256_hex(b"other"))
            .request();
        let answer = exchange(&service, put).await;
        let body = body_of(&answer);
        assert_eq!(answer.status(), 400, "{path}: {body}");
        assert!(body.contains("<Code>BadDigest</Code>"), "{path}: {body}");
        assert!(
            body.contains("<Message>The Content-Md5 you specified did not match what we received.</Message>"),
            "{path}: {body}"
        );
    }
    assert_eq!(read(&service, "/digests/absent").await.0, 404);
    assert_eq!(read(&service, "/digests/k").await, (200, "stored".to_owned()));
}
