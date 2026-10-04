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

//! Host and payload-line coverage through the RustFS-profile assembly.
//!
//! Responsible for: Host and semantic-header refusals, authenticated payload declarations and
//! exact stored bytes after read, upload and overwrite. Header authentication may omit the payload
//! declaration from SignedHeaders because HashedPayload covers it (rustfs/gateway#1239).
//! The Host refusal remains the deliberate legacy difference `rd-loc-0009`; the old blanket
//! payload-header refusal was corrected against AWS in rustfs/backlog#2684.
//! NOT responsible for: the other `SignedHeaders` rules (`sigv4_acceptance_tests.rs`).
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.

use super::hand_signer::HandSigned;
use super::*;

/// Host is required whether or not the payload declaration also appears in SignedHeaders.
const UNSIGNED_HOST: [&[&str]; 2] = [&["host"], &["host", "x-amz-content-sha256"]];

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/coverage", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/coverage/k", Bytes::from_static(b"stored"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// Positive — the control: a request naming `host` and the payload hash is served, a read and an
/// upload alike, so the refusals below are the unsigned header's and nothing else's.
#[tokio::test]
async fn a_request_naming_host_and_the_payload_hash_is_served() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let read = exchange(&service, HandSigned::new(http::Method::GET, "/coverage/k", Bytes::new()).request()).await;
    assert_eq!((read.status().as_u16(), body_of(&read).as_str()), (200, "stored"));
    let upload = HandSigned::new(http::Method::PUT, "/coverage/new", Bytes::from_static(b"uploaded")).request();
    let stored = exchange(&service, upload).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let read_back = exchange(&service, as_main(http::Method::GET, "/coverage/new", Bytes::new())).await;
    assert_eq!(body_of(&read_back), "uploaded");
}

/// Negative — a read leaving `host` unsigned is refused with `403
/// SignatureDoesNotMatch`, where legacy RustFS serves it.
#[tokio::test]
async fn n_a_read_leaving_host_unsigned_is_refused() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for unsigned in UNSIGNED_HOST {
        let request = HandSigned::new(http::Method::GET, "/coverage/k", Bytes::new()).leaving_unsigned(unsigned);
        let answer = exchange(&service, request.request()).await;
        let body = body_of(&answer);
        assert_eq!(answer.status(), 403, "{unsigned:?}: {body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{unsigned:?}: {body}");
        assert!(!body.contains("stored"), "{unsigned:?}: {body}");
    }
}

/// Negative — an upload leaving `host` unsigned is refused and stores nothing:
/// the key stays absent.
#[tokio::test]
async fn n_an_upload_leaving_host_unsigned_stores_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for unsigned in UNSIGNED_HOST {
        let upload =
            HandSigned::new(http::Method::PUT, "/coverage/absent", Bytes::from_static(b"forged")).leaving_unsigned(unsigned);
        let answer = exchange(&service, upload.request()).await;
        assert_eq!(answer.status(), 403, "{unsigned:?}: {}", body_of(&answer));
        let read = exchange(&service, as_main(http::Method::GET, "/coverage/absent", Bytes::new())).await;
        assert_eq!(read.status(), 404, "{unsigned:?}: {}", body_of(&read));
    }
}

/// Negative — an overwrite leaving `host` unsigned is refused and the stored
/// object keeps its bytes.
#[tokio::test]
async fn n_an_overwrite_leaving_host_unsigned_keeps_the_stored_bytes() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for unsigned in UNSIGNED_HOST {
        let overwrite =
            HandSigned::new(http::Method::PUT, "/coverage/k", Bytes::from_static(b"replaced")).leaving_unsigned(unsigned);
        let answer = exchange(&service, overwrite.request()).await;
        assert_eq!(answer.status(), 403, "{unsigned:?}: {}", body_of(&answer));
        let read = exchange(&service, as_main(http::Method::GET, "/coverage/k", Bytes::new())).await;
        assert_eq!((read.status().as_u16(), body_of(&read).as_str()), (200, "stored"), "{unsigned:?}");
    }
}

#[tokio::test]
async fn a_payload_line_coverage_serves_reads_uploads_and_overwrites() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let read = HandSigned::new(http::Method::GET, "/coverage/k", Bytes::new()).leaving_unsigned(&["x-amz-content-sha256"]);
    let answer = exchange(&service, read.request()).await;
    assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"));

    for (path, body) in [("/coverage/new", "uploaded"), ("/coverage/k", "replaced")] {
        let upload = HandSigned::new(http::Method::PUT, path, Bytes::from_static(body.as_bytes()))
            .leaving_unsigned(&["x-amz-content-sha256"]);
        let answer = exchange(&service, upload.request()).await;
        assert_eq!(answer.status(), 200, "{}", body_of(&answer));
        let read_back = exchange(&service, as_main(http::Method::GET, path, Bytes::new())).await;
        assert_eq!((read_back.status().as_u16(), body_of(&read_back).as_str()), (200, body));
    }
}

#[tokio::test]
async fn n_an_unlisted_payload_declaration_remains_bound_to_the_payload_line() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (method, path, bytes) in [
        (http::Method::GET, "/coverage/k", Bytes::new()),
        (http::Method::PUT, "/coverage/new", Bytes::from_static(b"uploaded")),
        (http::Method::PUT, "/coverage/k", Bytes::from_static(b"replaced")),
    ] {
        let mut request = HandSigned::new(method, path, bytes)
            .leaving_unsigned(&["x-amz-content-sha256"])
            .request();
        request
            .headers_mut()
            .insert("x-amz-content-sha256", http::HeaderValue::from_static("UNSIGNED-PAYLOAD"));
        let answer = exchange(&service, request).await;
        assert_eq!(answer.status(), 403, "{}", body_of(&answer));
        assert!(body_of(&answer).contains("<Code>SignatureDoesNotMatch</Code>"));
    }
    let read = exchange(&service, as_main(http::Method::GET, "/coverage/k", Bytes::new())).await;
    assert_eq!((read.status().as_u16(), body_of(&read).as_str()), (200, "stored"));
    let absent = exchange(&service, as_main(http::Method::GET, "/coverage/new", Bytes::new())).await;
    assert_eq!(absent.status(), 404);
}

#[tokio::test]
async fn n_payload_line_coverage_does_not_sign_metadata_on_reads_or_mutations() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (method, path, bytes) in [
        (http::Method::GET, "/coverage/k", Bytes::new()),
        (http::Method::PUT, "/coverage/new", Bytes::from_static(b"uploaded")),
        (http::Method::PUT, "/coverage/k", Bytes::from_static(b"replaced")),
    ] {
        let request = HandSigned::new(method, path, bytes)
            .leaving_unsigned(&["x-amz-content-sha256"])
            .sending("x-amz-meta-mode", "changed", false)
            .request();
        let answer = exchange(&service, request).await;
        assert_eq!(answer.status(), 403, "{}", body_of(&answer));
        assert!(body_of(&answer).contains("<Code>AccessDenied</Code>"));
    }
    let read = exchange(&service, as_main(http::Method::GET, "/coverage/k", Bytes::new())).await;
    assert_eq!((read.status().as_u16(), body_of(&read).as_str()), (200, "stored"));
    let absent = exchange(&service, as_main(http::Method::GET, "/coverage/new", Bytes::new())).await;
    assert_eq!(absent.status(), 404);
}
