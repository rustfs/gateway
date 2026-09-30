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

//! The legacy RustFS slash rule as the launcher serves it (rustfs/gateway#1101).
//!
//! Responsible for: the key a slash-shaped request path stores under the RustFS profile — a key
//! that starts with `/` folded (`PUT /b//x` stores `x`, as legacy RustFS stores it), every other
//! key kept as sent (`a//b` is not `a/b`, and RustFS's storage refuses it), and no object ever
//! stored under the leading slashes.
//! NOT responsible for: the rule itself (`rustfs-gateway-types`' `rustfs_slash_tests`) or whether
//! the handler is handed the same key legacy RustFS hands its storage (the difftest RustFS-profile
//! rows).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn slash_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/slashes", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

async fn put(service: &S3Service, target: &str, body: &'static [u8]) -> WireResponse {
    exchange(service, as_main(http::Method::PUT, target, Bytes::from_static(body))).await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

async fn keys(service: &S3Service) -> String {
    let listed = get(service, "/slashes?list-type=2").await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    body_of(&listed)
}

/// Positive — a key that starts with a slash is stored folded, and read back under the folded
/// spelling as well as under the one that was written.
#[tokio::test]
async fn a_rooted_key_is_stored_folded() {
    let root = TestRoot::new();
    let service = slash_bucket(&root).await;

    for (target, stored) in [("/slashes//x", "x"), ("/slashes///dir//y", "dir/y"), ("/slashes//z//", "z/")] {
        let written = put(&service, target, b"folded").await;
        assert_eq!(written.status(), 200, "{target}: {}", body_of(&written));
        let read = get(&service, &format!("/slashes/{stored}")).await;
        assert_eq!(read.status(), 200, "{target} was not stored as {stored}");
        assert_eq!(read.body().as_ref(), b"folded");
    }
    let listing = keys(&service).await;
    for stored in ["<Key>x</Key>", "<Key>dir/y</Key>", "<Key>z/</Key>"] {
        assert!(listing.contains(stored), "{stored} missing: {listing}");
    }
}

/// Negative — a key that does not start with a slash keeps its interior run: `a//b` reaches the
/// storage as `a//b`, never `a/b` (which the MinIO-style `Collapse` would have stored), and RustFS's
/// storage refuses a key holding `//` with `400 InvalidArgument` (rustfs/gateway#1145), so nothing
/// is stored — a folded key would have been.
#[tokio::test]
async fn n_an_interior_run_is_not_folded() {
    let root = TestRoot::new();
    let service = slash_bucket(&root).await;

    let written = put(&service, "/slashes/a//b", b"interior").await;
    assert_eq!(written.status(), 400, "{}", body_of(&written));
    assert!(body_of(&written).contains("<Code>InvalidArgument</Code>"), "{}", body_of(&written));
    assert_eq!(get(&service, "/slashes/a/b").await.status(), 404, "a//b must not land on a/b");
    let listing = keys(&service).await;
    assert!(!listing.contains("<Key>"), "{listing}");
}

/// Negative — no leading slash, no fold: a trailing slash and a plain key are stored as sent, and
/// a trailing run reaches the storage as sent, which RustFS's storage refuses (rustfs/gateway#1145)
/// rather than storing it as `dir/`.
#[tokio::test]
async fn n_a_key_without_a_leading_slash_is_stored_as_sent() {
    let root = TestRoot::new();
    let service = slash_bucket(&root).await;

    for (target, status) in [("/slashes/dir/", 200), ("/slashes/dir//", 400), ("/slashes/plain", 200)] {
        let written = put(&service, target, b"as-sent").await;
        assert_eq!(written.status(), status, "{target}: {}", body_of(&written));
    }
    let listing = keys(&service).await;
    for stored in ["<Key>dir/</Key>", "<Key>plain</Key>"] {
        assert!(listing.contains(stored), "{stored} missing: {listing}");
    }
    assert_eq!(listing.matches("<Key>").count(), 2, "{listing}");
}

/// Negative — the leading slashes name no object of their own: `//x` and `///x` both overwrite
/// `x`, and no key starting with a slash is ever stored.
#[tokio::test]
async fn n_no_object_is_stored_under_the_leading_slashes() {
    let root = TestRoot::new();
    let service = slash_bucket(&root).await;

    for (target, body) in [
        ("/slashes//x", &b"first"[..]),
        ("/slashes///x", b"second"),
        ("/slashes/%2F%2Fx", b"third"),
    ] {
        let written = exchange(&service, as_main(http::Method::PUT, target, Bytes::copy_from_slice(body))).await;
        assert_eq!(written.status(), 200, "{target}: {}", body_of(&written));
    }
    let read = get(&service, "/slashes/x").await;
    assert_eq!(read.body().as_ref(), b"third", "every spelling wrote the one object x");
    let listing = keys(&service).await;
    assert_eq!(listing.matches("<Key>").count(), 1, "{listing}");
    assert!(!listing.contains("<Key>/"), "{listing}");
}
