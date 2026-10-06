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

//! The RustFS-profile `max-keys` ceiling as the launcher serves it (rustfs/backlog#1677, R1).
//!
//! Responsible for: an oversized `max-keys` on the three listings reaching the backend as RustFS's
//! ceiling — a page and a `<MaxKeys>` echo of a thousand, where the core default refuses
//! ListObjectsV2 with `400` — while a negative or unparseable value is still refused and
//! an oversized `max-uploads` is refused instead of silently clamped. The core's
//! `codec::tests::page_size_ceiling` pins the exact value passed to the backend.
//! NOT responsible for: the default refusal, which the conformance corpus pins (`c-list-0028`), or
//! how the backend pages (`rustfs_gateway_fs::listing`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn listing_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/pages", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    for key in ["a", "b", "c"] {
        let object = exchange(&service, as_main(http::Method::PUT, &format!("/pages/{key}"), Bytes::from_static(b"x"))).await;
        assert_eq!(object.status(), 200, "{}", body_of(&object));
    }
    service
}

/// Positive — Hadoop S3A's 5000 and the RustFS e2e suite's 1001 list the whole bucket and echo the
/// ceiling on every listing, as RustFS answers them.
#[tokio::test]
async fn an_oversized_max_keys_lists_under_the_rustfs_ceiling() {
    let root = TestRoot::new();
    let service = listing_bucket(&root).await;

    for target in [
        "/pages?list-type=2&max-keys=1001",
        "/pages?list-type=2&max-keys=5000",
        "/pages?max-keys=5000",
        "/pages?versions&max-keys=5000",
    ] {
        let listed = exchange(&service, as_main(http::Method::GET, target, Bytes::new())).await;
        let body = body_of(&listed);
        assert_eq!(listed.status(), 200, "{target}: {body}");
        assert!(body.contains("<MaxKeys>1000</MaxKeys>"), "{target}: {body}");
        for key in ["<Key>a</Key>", "<Key>b</Key>", "<Key>c</Key>"] {
            assert!(body.contains(key), "{target}: {body}");
        }
    }
}

/// Negative — an in-range page size is served as asked, so the ceiling is not a constant.
#[tokio::test]
async fn n_an_in_range_max_keys_is_served_as_asked() {
    let root = TestRoot::new();
    let service = listing_bucket(&root).await;

    let listed = exchange(&service, as_main(http::Method::GET, "/pages?list-type=2&max-keys=2", Bytes::new())).await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 200, "{body}");
    assert!(body.contains("<MaxKeys>2</MaxKeys>"), "{body}");
    assert!(body.contains("<IsTruncated>true</IsTruncated>"), "{body}");
    assert!(!body.contains("<Key>c</Key>"), "{body}");
}

/// Negative — a ceiling is not a floor and not a parser: a negative or unparseable page size is
/// still `InvalidArgument`, as RustFS answers it.
#[tokio::test]
async fn n_a_negative_or_unparseable_max_keys_is_still_refused() {
    let root = TestRoot::new();
    let service = listing_bucket(&root).await;

    for target in [
        "/pages?list-type=2&max-keys=-1",
        "/pages?list-type=2&max-keys=abc",
        "/pages?list-type=2&max-keys=99999999999",
        "/pages?max-keys=-1",
        "/pages?max-keys=abc",
    ] {
        let refused = exchange(&service, as_main(http::Method::GET, target, Bytes::new())).await;
        assert_eq!(refused.status(), 400, "{target}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains("<Code>InvalidArgument</Code>"),
            "{target}: {}",
            body_of(&refused)
        );
    }
}

/// Negative — the ceiling is `max-keys`'s alone: the backend refuses an oversized `max-uploads`
/// instead of serving a clamped page, while its valid upper boundary still succeeds.
#[tokio::test]
async fn n_oversized_max_uploads_is_refused_instead_of_clamped() {
    let root = TestRoot::new();
    let service = listing_bucket(&root).await;

    let listed = exchange(&service, as_main(http::Method::GET, "/pages?uploads&max-uploads=5000", Bytes::new())).await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 400, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");

    let listed = exchange(&service, as_main(http::Method::GET, "/pages?uploads&max-uploads=1000", Bytes::new())).await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 200, "{body}");
    assert!(body.contains("<MaxUploads>1000</MaxUploads>"), "{body}");
}
