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

//! Legacy RustFS's path addressing as the launcher serves it (rustfs/gateway#1115).
//!
//! Responsible for: an escaped separator or bucket label reaching the object legacy RustFS stores
//! it under on a real backend, the buckets legacy RustFS creates that the AWS rules reserve, `GET
//! //` signed over `/` listing the buckets, and the refusals legacy RustFS makes before routing.
//! NOT responsible for: the split (`rustfs-gateway-core`'s `legacy_path` tests) or equality with the
//! bucket and key legacy RustFS hands its storage (the difftest RustFS-profile rows).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn addressing(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/addr", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

/// Positive — `/addr%2Fk` writes the key `k` in `addr`, and `/a%64dr/k` reads it back: the path is
/// decoded once, then split.
#[tokio::test]
async fn an_escaped_separator_or_label_reaches_the_legacy_object() {
    let root = TestRoot::new();
    let service = addressing(&root).await;
    let written = exchange(&service, as_main(http::Method::PUT, "/addr%2Fk", Bytes::from_static(b"escaped"))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    for target in ["/addr/k", "/a%64dr/k", "/addr%2Fk"] {
        let read = exchange(&service, as_main(http::Method::GET, target, Bytes::new())).await;
        assert_eq!(read.status(), 200, "{target}: {}", body_of(&read));
        assert_eq!(read.body().as_ref(), b"escaped", "{target}");
    }
}

/// Positive — a bucket legacy RustFS creates under a prefix or suffix the AWS rules reserve.
#[tokio::test]
async fn a_bucket_the_aws_rules_reserve_is_created_and_served() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/abc-s3alias", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let written = exchange(&service, as_main(http::Method::PUT, "/abc-s3alias/k", Bytes::from_static(b"kept"))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let read = exchange(&service, as_main(http::Method::GET, "/abc-s3alias/k", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), b"kept");
}

/// Positive — `GET //` signed over `/`, as the AWS S3 browser sends it, lists the buckets.
#[tokio::test]
async fn a_get_of_double_slash_signed_over_the_root_lists_the_buckets() {
    let root = TestRoot::new();
    let service = addressing(&root).await;
    let mut request = as_main(http::Method::GET, "/", Bytes::new());
    *request.uri_mut() = "//".parse().expect("a valid target");
    let listed = exchange(&service, request).await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    assert!(body_of(&listed).contains("<Name>addr</Name>"), "{}", body_of(&listed));
}

/// Negative — an empty or refused bucket segment is `InvalidBucketName` before routing, and an
/// undecodable path `InvalidURI`, as legacy RustFS answers them; nothing is written.
#[tokio::test]
async fn n_legacy_refusals_happen_before_routing() {
    let root = TestRoot::new();
    let service = addressing(&root).await;
    for (method, target, code) in [
        (http::Method::GET, "//addr", "InvalidBucketName"),
        (http::Method::PUT, "//addr/k", "InvalidBucketName"),
        (http::Method::PATCH, "/Bad_Bucket/k", "InvalidBucketName"),
        (http::Method::PUT, "/1.2.3.4/k", "InvalidBucketName"),
        (http::Method::PUT, "/addr/a%FFb", "InvalidURI"),
    ] {
        let refused = exchange(&service, as_main(method.clone(), target, Bytes::from_static(b"no"))).await;
        assert_eq!(refused.status(), 400, "{method} {target}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains(&format!("<Code>{code}</Code>")),
            "{method} {target}: {}",
            body_of(&refused)
        );
    }
    let listing = exchange(&service, as_main(http::Method::GET, "/addr?list-type=2", Bytes::new())).await;
    assert!(!body_of(&listing).contains("<Key>"), "{}", body_of(&listing));
}

/// Negative — `GET //` signed over `//` fails its signature: the launcher verifies it over `/`.
#[tokio::test]
async fn n_a_get_of_double_slash_signed_over_itself_is_refused() {
    let root = TestRoot::new();
    let service = addressing(&root).await;
    let refused = exchange(&service, as_main(http::Method::GET, "//", Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
}

/// Positive — an object in a bucket the AWS rules reserve, and an object whose key holds a `?`
/// named raw in the header, are copy sources, as on legacy RustFS; the copies hold their bytes.
#[tokio::test]
async fn a_reserved_bucket_or_a_question_mark_key_is_a_copy_source() {
    let root = TestRoot::new();
    let service = addressing(&root).await;
    let created = exchange(&service, as_main(http::Method::PUT, "/sthree-x", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    for (target, body) in [("/sthree-x/obj", &b"reserved"[..]), ("/addr/q%3Fpart%3D1", &b"question"[..])] {
        let written = exchange(&service, as_main(http::Method::PUT, target, Bytes::copy_from_slice(body))).await;
        assert_eq!(written.status(), 200, "{target}: {}", body_of(&written));
    }
    for (source, copy, expected) in [
        ("sthree-x/obj", "/addr/from-reserved", &b"reserved"[..]),
        ("addr/q?part=1", "/addr/from-question", &b"question"[..]),
    ] {
        let copied = exchange(
            &service,
            signed(
                MAIN_KEY,
                MAIN_SECRET,
                http::Method::PUT,
                copy,
                Bytes::new(),
                &[("x-amz-copy-source", source)],
            ),
        )
        .await;
        assert_eq!(copied.status(), 200, "{source}: {}", body_of(&copied));
        let read = exchange(&service, as_main(http::Method::GET, copy, Bytes::new())).await;
        assert_eq!(read.body().as_ref(), expected, "{source}");
    }
}
