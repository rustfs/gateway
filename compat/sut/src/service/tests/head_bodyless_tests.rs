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

//! `HEAD` answers and the bodyless statuses as the RustFS-profile launcher shapes them
//! (rustfs/gateway#1120).
//!
//! Responsible for: the scenarios of RustFS's `HeadRequestBodyFixLayer` and `BodylessStatusFixLayer`
//! tests (`rustfs/src/server/layer.rs` `head_request_body_fix`, `bodyless_status_fix`) and of its
//! e2e `head_tls_bodyless_test`, over the served assembly: a refused `HEAD` — missing key, missing
//! bucket, denied, anonymous, failed precondition — carries its status and `Content-Type` and
//! neither content nor `Content-Length`; a successful `HEAD` keeps the length it reports; a refused
//! `GET` keeps its document; a `304` and a `204` carry no content, no `Content-Length` and no
//! `Content-Type`, and keep their other headers.
//! NOT responsible for: the invariants themselves (`rustfs-gateway`'s `src/invariants.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`) over raw
//! sockets: a refused `HEAD` answers `Content-Type: application/xml` with no `Content-Length`; a
//! `304` keeps `ETag` and `Last-Modified` on a `GET`; a `204` carries no framing header.

use super::*;

const CONTENT: &[u8] = b"eleven byte";

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/shapes", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let put = exchange(&service, as_main(http::Method::PUT, "/shapes/k", Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    service
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response.header(name)
}

fn assert_refused_head(response: &WireResponse, status: u16, what: &str) {
    assert_eq!(response.status(), status, "{what}: {}", body_of(response));
    assert!(response.body().is_empty(), "{what}: a HEAD carried content");
    assert_eq!(header(response, "content-length"), None, "{what}: a refused HEAD stated a length");
    assert_eq!(header(response, "content-type"), Some("application/xml"), "{what}");
    assert_eq!(header(response, "transfer-encoding"), None, "{what}");
}

/// Negative — every way a `HEAD` can be refused goes out with its status and `Content-Type`, no
/// content, and no `Content-Length`.
#[tokio::test]
async fn n_a_refused_head_states_no_length() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let missing_key = exchange(&service, as_main(http::Method::HEAD, "/shapes/absent", Bytes::new())).await;
    assert_refused_head(&missing_key, 404, "missing key");
    let missing_bucket = exchange(&service, as_main(http::Method::HEAD, "/no-such-bucket/k", Bytes::new())).await;
    assert_refused_head(&missing_bucket, 404, "missing bucket");
    let denied = exchange(&service, as_alt(http::Method::HEAD, "/shapes/k", Bytes::new())).await;
    assert_refused_head(&denied, 403, "denied");
    let failed = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::HEAD,
        "/shapes/k",
        Bytes::new(),
        &[("if-match", "\"not-the-etag\"")],
    );
    assert_refused_head(&exchange(&service, failed).await, 412, "failed precondition");
    let anonymous = http::Request::builder()
        .method(http::Method::HEAD)
        .uri("/shapes/k")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    assert_refused_head(&exchange(&service, anonymous).await, 403, "anonymous");
}

/// Positive — a `HEAD` that succeeds keeps the length it reports, and a `GET` that is refused keeps
/// its document and that document's length: the switch is about refused `HEAD`s only.
#[tokio::test]
async fn a_successful_head_and_a_refused_get_keep_their_lengths() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let head = exchange(&service, as_main(http::Method::HEAD, "/shapes/k", Bytes::new())).await;
    assert_eq!(head.status(), 200, "{}", body_of(&head));
    assert!(head.body().is_empty());
    assert_eq!(header(&head, "content-length"), Some("11"));

    let get = exchange(&service, as_main(http::Method::GET, "/shapes/absent", Bytes::new())).await;
    assert_eq!(get.status(), 404);
    assert!(body_of(&get).contains("<Code>NoSuchKey</Code>"), "{}", body_of(&get));
    assert_eq!(
        header(&get, "content-length").and_then(|length| length.parse::<usize>().ok()),
        Some(get.body().len())
    );
}

/// Negative — a `304` carries no content, no `Content-Length` and no `Content-Type` on a `GET` and
/// on a `HEAD`, and a `GET`'s keeps its `ETag` and `Last-Modified`; a `200` beside it keeps
/// everything.
#[tokio::test]
async fn n_a_not_modified_answer_carries_no_content_and_no_framing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let etag = exchange(&service, as_main(http::Method::HEAD, "/shapes/k", Bytes::new()))
        .await
        .header("etag")
        .expect("an entity tag")
        .to_owned();

    for method in [http::Method::GET, http::Method::HEAD] {
        let request = signed(
            MAIN_KEY,
            MAIN_SECRET,
            method.clone(),
            "/shapes/k",
            Bytes::new(),
            &[("if-none-match", etag.as_str())],
        );
        let response = exchange(&service, request).await;
        assert_eq!(response.status(), 304, "{method}: {}", body_of(&response));
        assert!(response.body().is_empty(), "{method}");
        assert_eq!(header(&response, "content-length"), None, "{method}");
        assert_eq!(header(&response, "content-type"), None, "{method}");
        assert_eq!(header(&response, "transfer-encoding"), None, "{method}");
        if method == http::Method::GET {
            assert_eq!(header(&response, "etag"), Some(etag.as_str()));
            assert!(header(&response, "last-modified").is_some());
        }
    }

    let read = exchange(&service, as_main(http::Method::GET, "/shapes/k", Bytes::new())).await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), CONTENT);
    assert_eq!(header(&read, "content-length"), Some("11"));
}

/// Negative, and the data-layer half — a `204` carries no content and no framing header, and the
/// delete it answers removed the object.
#[tokio::test]
async fn n_a_no_content_answer_carries_no_framing_and_the_object_is_gone() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let deleted = exchange(&service, as_main(http::Method::DELETE, "/shapes/k", Bytes::new())).await;
    assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    assert!(deleted.body().is_empty());
    assert_eq!(header(&deleted, "content-length"), None);
    assert_eq!(header(&deleted, "content-type"), None);
    assert_eq!(header(&deleted, "transfer-encoding"), None);
    let gone = exchange(&service, as_main(http::Method::GET, "/shapes/k", Bytes::new())).await;
    assert_eq!(gone.status(), 404, "{}", body_of(&gone));
}
