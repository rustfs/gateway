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

//! The headers of a `304` to an object read, as the RustFS-profile launcher answers it
//! (rustfs/gateway#1120).
//!
//! Responsible for: the object headers a `304` carries on `GET` and on `HEAD` — for an object
//! stored with caching, content and user metadata and a tag, for each precondition that answers
//! `304`, under response overrides, `partNumber` and `x-amz-checksum-mode`, and for a versioned
//! read — and the answers beside it that keep theirs.
//! NOT responsible for: a `304`'s framing (`head_bodyless_tests.rs`), the rule itself
//! (`rustfs-gateway`'s `src/builder/not_modified_headers.rs`), or which preconditions answer `304`
//! (the backend's).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`) over raw
//! sockets with the same object stored: every `GET` below answers `304` with `ETag` and
//! `Last-Modified` and no other header of the object, and every `HEAD` with no header of the object
//! at all — `check_preconditions` (`rustfs/src/storage/ecfs_extend.rs:527-609`) and `HeadObject`'s
//! bare `NotModified` (`rustfs/src/app/object/head.rs:417-432`).

use super::*;

const CONTENT: &[u8] = b"meta body";

/// The headers of the object a `304` must not repeat, besides `ETag` and `Last-Modified`.
const OBJECT_HEADERS: [&str; 13] = [
    "cache-control",
    "expires",
    "content-type",
    "content-disposition",
    "content-language",
    "content-encoding",
    "accept-ranges",
    "content-range",
    "x-amz-meta-foo",
    "x-amz-tagging-count",
    "x-amz-version-id",
    "x-amz-storage-class",
    "x-amz-mp-parts-count",
];

struct Stored {
    service: S3Service,
    etag: String,
    last_modified: String,
}

async fn served(root: &TestRoot) -> Stored {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/validators", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let put = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/validators/meta.txt",
            Bytes::from_static(CONTENT),
            &[
                ("cache-control", "max-age=60"),
                ("expires", "Wed, 01 Jan 2031 00:00:00 GMT"),
                ("content-type", "text/plain"),
                ("content-disposition", "attachment; filename=\"a.txt\""),
                ("content-language", "en"),
                ("x-amz-meta-foo", "bar"),
                ("x-amz-tagging", "k=v"),
            ],
        ),
    )
    .await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    let head = exchange(&service, as_main(http::Method::HEAD, "/validators/meta.txt", Bytes::new())).await;
    assert_eq!(head.status(), 200, "{}", body_of(&head));
    // The object answers a `200` with everything the `304` below must leave out.
    for name in [
        "cache-control",
        "expires",
        "content-type",
        "content-disposition",
        "content-language",
        "x-amz-meta-foo",
    ] {
        assert!(head.header(name).is_some(), "the stored object reports {name}");
    }
    Stored {
        etag: head.header("etag").expect("an entity tag").to_owned(),
        last_modified: head.header("last-modified").expect("a modification time").to_owned(),
        service,
    }
}

fn read(method: &http::Method, target: &str, conditions: &[(&str, &str)]) -> http::Request<Bytes> {
    signed(MAIN_KEY, MAIN_SECRET, method.clone(), target, Bytes::new(), conditions)
}

/// What every `304` below shares: no content, no framing, none of the object's other headers, and
/// the identifiers every answer carries.
fn assert_not_modified(response: &WireResponse, what: &str) {
    assert_eq!(response.status(), 304, "{what}: {}", body_of(response));
    assert!(response.body().is_empty(), "{what}");
    assert_eq!(response.header("content-length"), None, "{what}");
    for name in OBJECT_HEADERS {
        assert_eq!(response.header(name), None, "{what}: {name}");
    }
    assert!(response.header("x-amz-request-id").is_some(), "{what}: the request id is kept");
    assert!(response.header("date").is_some(), "{what}");
}

/// One read that answers `304`: what it exercises, its query, and its conditional headers.
type NotModifiedRead<'a> = (&'static str, &'static str, Vec<(&'static str, &'a str)>);

/// The preconditions that answer `304`, each with the query it is sent with.
fn not_modified_reads(stored: &Stored) -> Vec<NotModifiedRead<'_>> {
    vec![
        ("If-None-Match", "", vec![("if-none-match", stored.etag.as_str())]),
        ("If-None-Match: *", "", vec![("if-none-match", "*")]),
        ("If-Modified-Since", "", vec![("if-modified-since", stored.last_modified.as_str())]),
        (
            "response overrides",
            "?response-cache-control=no-cache&response-content-type=text%2Fhtml",
            vec![("if-none-match", stored.etag.as_str())],
        ),
        ("partNumber", "?partNumber=1", vec![("if-none-match", stored.etag.as_str())]),
        (
            "x-amz-checksum-mode",
            "",
            vec![("if-none-match", stored.etag.as_str()), ("x-amz-checksum-mode", "ENABLED")],
        ),
    ]
}

/// Positive — a `GET` whose precondition answers `304` carries the object's `ETag` and
/// `Last-Modified` and no other header of the object.
#[tokio::test]
async fn a_get_not_modified_carries_only_its_validators() {
    let root = TestRoot::new();
    let stored = served(&root).await;
    for (what, query, conditions) in not_modified_reads(&stored) {
        let target = format!("/validators/meta.txt{query}");
        let response = exchange(&stored.service, read(&http::Method::GET, &target, &conditions)).await;
        assert_not_modified(&response, what);
        assert_eq!(response.header("etag"), Some(stored.etag.as_str()), "{what}");
        assert_eq!(response.header("last-modified"), Some(stored.last_modified.as_str()), "{what}");
    }
}

/// Negative — a `HEAD` whose precondition answers `304` carries no header of the object at all,
/// its validators included.
#[tokio::test]
async fn n_a_head_not_modified_carries_nothing_of_the_object() {
    let root = TestRoot::new();
    let stored = served(&root).await;
    for (what, query, conditions) in not_modified_reads(&stored) {
        let target = format!("/validators/meta.txt{query}");
        let response = exchange(&stored.service, read(&http::Method::HEAD, &target, &conditions)).await;
        assert_not_modified(&response, what);
        assert_eq!(response.header("etag"), None, "{what}");
        assert_eq!(response.header("last-modified"), None, "{what}");
    }
}

/// Negative — a versioned read's `304` names no version, by version id or as the latest.
#[tokio::test]
async fn n_a_versioned_not_modified_names_no_version() {
    let root = TestRoot::new();
    let stored = served(&root).await;
    let service = &stored.service;
    let enabled = exchange(
        service,
        as_main(
            http::Method::PUT,
            "/validators?versioning",
            Bytes::from_static(
                b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>",
            ),
        ),
    )
    .await;
    assert_eq!(enabled.status(), 200, "{}", body_of(&enabled));
    let put = exchange(service, as_main(http::Method::PUT, "/validators/v.txt", Bytes::from_static(b"versioned"))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    let version = put.header("x-amz-version-id").expect("a version id").to_owned();
    let etag = put.header("etag").expect("an entity tag").to_owned();
    for target in [
        format!("/validators/v.txt?versionId={version}"),
        "/validators/v.txt".to_owned(),
    ] {
        for method in [http::Method::GET, http::Method::HEAD] {
            let response = exchange(service, read(&method, &target, &[("if-none-match", etag.as_str())])).await;
            assert_not_modified(&response, &format!("{method} {target}"));
            let expected = (method == http::Method::GET).then_some(etag.as_str());
            assert_eq!(response.header("etag"), expected, "{method} {target}");
        }
    }
}

/// Positive — the answers beside a `304` keep their headers: a `200` on both methods keeps the
/// object's, and a `412` keeps its own.
#[tokio::test]
async fn the_answers_beside_a_not_modified_keep_their_headers() {
    let root = TestRoot::new();
    let stored = served(&root).await;
    for method in [http::Method::GET, http::Method::HEAD] {
        let whole = exchange(&stored.service, read(&method, "/validators/meta.txt", &[])).await;
        assert_eq!(whole.status(), 200, "{method}: {}", body_of(&whole));
        for name in [
            "etag",
            "last-modified",
            "cache-control",
            "expires",
            "content-type",
            "content-disposition",
            "content-language",
            "accept-ranges",
            "x-amz-meta-foo",
            "x-amz-tagging-count",
        ] {
            assert!(whole.header(name).is_some(), "{method}: {name}");
        }
        let failed = exchange(
            &stored.service,
            read(&method, "/validators/meta.txt", &[("if-match", "\"not-the-etag\"")]),
        )
        .await;
        assert_eq!(failed.status(), 412, "{method}: {}", body_of(&failed));
        assert_eq!(failed.header("content-type"), Some("application/xml"), "{method}");
    }
}
