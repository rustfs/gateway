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

//! `--register-only`: the served assembly with part of its registry missing (rustfs/backlog#2758).
//!
//! Responsible for: that `super::build_service`, given `--register-only`, registers exactly the
//! named operations and answers every other one `501 NotImplemented` — the answer the client
//! matrix reads as `sut-unregistered` against an external endpoint — while the named ones, and
//! the whole profile around them, serve as they do in the full assembly.
//! NOT responsible for: classifying a matrix cell (`ci/compat/report.py`), or forwarding
//! (`tests/external.rs`).
//! Upstream: `super::build_service`. Downstream: nothing.

use super::*;

/// Negative — an operation outside the list is `501 NotImplemented`, the copy-object scenario's
/// first request (`CreateBucket`) and its copy (`CopyObject`) alike; the same requests against
/// the full assembly are served, so the `501` is the registry's and nothing else's.
#[tokio::test]
async fn n_an_operation_outside_the_list_is_not_implemented() {
    let root = TestRoot::new();
    let (_backend, partial) = assembled(&two_identity_options(&root, &["--register-only", "ListBuckets"]));
    let created = exchange(&partial, as_main(http::Method::PUT, "/partial", Bytes::new())).await;
    assert_eq!(created.status(), 501, "{}", body_of(&created));
    assert!(body_of(&created).contains("<Code>NotImplemented</Code>"), "{}", body_of(&created));
    let copy = signed_legacy_path(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/partial/copy",
        Bytes::new(),
        &[("x-amz-copy-source", "/partial/source")],
    );
    let copied = exchange(&partial, copy).await;
    assert_eq!(copied.status(), 501, "{}", body_of(&copied));

    let full_root = TestRoot::new();
    let (_backend, full) = assembled(&two_identity_options(&full_root, &[]));
    let created = exchange(&full, as_main(http::Method::PUT, "/partial", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
}

/// Positive — the named operation answers, so a `--register-only` endpoint is reachable and
/// authenticates; only its registry is short.
#[tokio::test]
async fn the_named_operation_is_served() {
    let root = TestRoot::new();
    let (_backend, partial) = assembled(&two_identity_options(&root, &["--register-only", "ListBuckets"]));
    let listed = exchange(&partial, as_main(http::Method::GET, "/", Bytes::new())).await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    assert!(body_of(&listed).contains("<ListAllMyBucketsResult"), "{}", body_of(&listed));
}

/// Negative — an anonymous request to an unregistered operation is still refused before the
/// registry is consulted: `--register-only` removes handlers, not authentication.
#[tokio::test]
async fn n_an_anonymous_request_is_refused_before_the_registry_answers() {
    let root = TestRoot::new();
    let (_backend, partial) = assembled(&two_identity_options(&root, &["--register-only", "ListBuckets"]));
    let anonymous = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/partial")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid unsigned request");
    let refused = exchange(&partial, anonymous).await;
    assert_ne!(refused.status(), 200, "{}", body_of(&refused));
}

/// Negative — a name the reference backend does not register, an empty list, and a name given
/// twice are refused at the command line, before anything is served.
#[test]
fn n_an_unusable_list_is_refused_at_the_command_line() {
    for list in ["NoSuchOperation", "", ",", "ListBuckets,ListBuckets", "listbuckets"] {
        assert!(
            crate::parse_options(["--register-only", list]).is_err(),
            "--register-only {list:?} was accepted"
        );
    }
    assert!(crate::parse_options(["--register-only"]).is_err());
}

/// Positive — the table `--register-only` registers from names every operation the reference
/// backend registers, and nothing else, so no name can be listed that the full assembly lacks.
#[test]
fn the_registrable_table_is_the_backends_registry() {
    let root = TestRoot::new();
    let backend = FsBackend::open(&root.0).expect("a usable data root");
    let mut table: Vec<&str> = crate::partial::REGISTRABLE.to_vec();
    table.sort_unstable();
    assert_eq!(table, crate::service::capability_names(&backend));
}
