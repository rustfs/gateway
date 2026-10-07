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

//! A customer-provided key on a cleartext connection, as the RustFS-profile launcher answers it:
//! before routing and authentication, in legacy RustFS's words (rustfs/gateway#1349).
//!
//! Responsible for: an unsigned, a badly signed and a signed request carrying any customer-key
//! header — empty included, to a bucket that does not exist included — answering `400
//! InvalidRequest` with legacy RustFS's sentence, with nothing written; and the requests the gate
//! must not reach being served.
//! NOT responsible for: the gate rule (`rustfs-gateway`'s `builder::plaintext_customer_keys`) or
//! a copy from an SSE-C source over TLS (`sse_copy_source_tests`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a native build of rustfs/rustfs `95268a3b9` with
//! `RUSTFS_SSE_C_REQUIRE_TLS=true` over cleartext: a signed PUT, an unsigned one and one with a
//! forged signature carrying a target customer-key header, a copy carrying only copy-source key
//! headers, a GET carrying an empty key-MD5 header, an admin request and a CORS preflight each
//! answer `400 InvalidRequest` "Requests specifying Server Side Encryption with Customer provided
//! keys must be made over a secure connection." (`rustfs/src/server/ssec_transport.rs:69-149`).

use super::*;

const SENTENCE: &str =
    "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.";
const ALGORITHM: (&str, &str) = ("x-amz-server-side-encryption-customer-algorithm", "AES256");

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    body.split_once(&format!("<{name}>"))
        .and_then(|(_, rest)| rest.split_once(&format!("</{name}>")))
        .map(|(value, _)| value)
}

fn assert_gated(response: &WireResponse, what: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 400, "{what}: {body}");
    assert_eq!(element(&body, "Code"), Some("InvalidRequest"), "{what}: {body}");
    assert_eq!(element(&body, "Message"), Some(SENTENCE), "{what}: {body}");
}

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/gate", ""), ("/gate/kept", "kept")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    service
}

fn unsigned(method: http::Method, target: &str, extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut request = http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_LENGTH, "2");
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    request.body(Bytes::from_static(b"hi")).expect("a valid request")
}

/// Negative — unsigned and badly signed requests carrying a customer key are answered by the gate
/// before authentication, not with `403`, and nothing is written.
#[tokio::test]
async fn n_an_unauthenticated_customer_key_over_cleartext_is_gated_first() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    assert_gated(
        &exchange(&service, unsigned(http::Method::PUT, "/gate/new", &[ALGORITHM])).await,
        "unsigned",
    );
    let forged = signed(
        MAIN_KEY,
        "not-the-secret",
        http::Method::PUT,
        "/gate/new",
        Bytes::from_static(b"hi"),
        &[ALGORITHM],
    );
    assert_gated(&exchange(&service, forged).await, "forged");
    let read = exchange(&service, as_main(http::Method::GET, "/gate/new", Bytes::new())).await;
    assert_eq!(read.status(), 404, "{}", body_of(&read));
}

/// Negative — every header position counts, present with any value: a copy-source key alone, an
/// empty key MD5 on a read, and a request to a bucket that does not exist.
#[tokio::test]
async fn n_any_customer_key_header_over_cleartext_is_gated() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let copy = [
        ("x-amz-copy-source", "/gate/kept"),
        ("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256"),
    ];
    let copied = signed(MAIN_KEY, MAIN_SECRET, http::Method::PUT, "/gate/copy", Bytes::new(), &copy);
    assert_gated(&exchange(&service, copied).await, "copy source");
    let read = exchange(&service, as_main(http::Method::GET, "/gate/copy", Bytes::new())).await;
    assert_eq!(read.status(), 404, "{}", body_of(&read));

    let empty = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::GET,
        "/gate/kept",
        Bytes::new(),
        &[("x-amz-server-side-encryption-customer-key-md5", "")],
    );
    assert_gated(&exchange(&service, empty).await, "empty");
    assert_gated(
        &exchange(&service, unsigned(http::Method::GET, "/missing/k", &[ALGORITHM])).await,
        "missing bucket",
    );
}

/// Negative — a signed overwrite carrying a customer key is gated and the stored object keeps its
/// bytes.
#[tokio::test]
async fn n_a_signed_overwrite_with_a_customer_key_changes_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let overwrite = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/gate/kept",
        Bytes::from_static(b"new"),
        &[ALGORITHM],
    );
    assert_gated(&exchange(&service, overwrite).await, "overwrite");
    let read = exchange(&service, as_main(http::Method::GET, "/gate/kept", Bytes::new())).await;
    assert_eq!((read.status().as_u16(), read.body().as_ref()), (200, &b"kept"[..]));
}

/// Positive — what the gate does not reach is answered as before: a request with no customer-key
/// header (a managed algorithm included) is served, and an unsigned one without a key is refused
/// by authorization, not by the gate.
#[tokio::test]
async fn requests_without_a_customer_key_are_not_gated() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let managed = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/gate/managed",
        Bytes::from_static(b"hi"),
        &[("x-amz-server-side-encryption", "AES256")],
    );
    let stored = exchange(&service, managed).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let anonymous = exchange(&service, unsigned(http::Method::PUT, "/gate/anon", &[])).await;
    assert_eq!(anonymous.status(), 403, "{}", body_of(&anonymous));
}
