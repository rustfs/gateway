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

//! Signed production-service evidence for stored representation headers (rustfs/gateway#718).
//!
//! Responsible for: `Content-Type` and the other standard stored headers surviving a restart on
//! `GET` and `HEAD`, the model default for an untyped object, the initiation-time headers a
//! multipart completion publishes, and the COPY/REPLACE split `CopyObject` applies to them.
//! NOT responsible for: `response-*` overrides, which the codec applies, or the record grammar's
//! refusals, which `records.rs` unit tests own.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

const TYPED: &[(&str, &str)] = &[
    ("content-type", "text/plain"),
    ("content-encoding", "identity"),
    ("content-disposition", "attachment; filename=\"report.txt\""),
    ("content-language", "en-GB"),
    ("cache-control", "max-age=60"),
    ("expires", "Thu, 01 Jan 2032 00:00:00 GMT"),
];

fn headers_of(pairs: &[(&str, &str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a fixture header name"),
            http::HeaderValue::from_str(value).expect("a fixture header value"),
        );
    }
    headers
}

async fn put_typed(service: &S3Service, target: &str, pairs: &[(&str, &str)]) {
    let response = exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(b"typed body"), headers_of(pairs)),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
}

fn assert_headers(response: &rustfs_gateway::WireResponse, pairs: &[(&str, &str)]) {
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    for (name, value) in pairs {
        assert_eq!(
            header(response, name).map(|value| value.to_str().expect("an ASCII header")),
            Some(*value),
            "{name}"
        );
    }
}

/// Positive — every stored header is answered by `GET` and `HEAD`, and survives a restart.
#[tokio::test]
async fn stored_representation_headers_are_answered_after_restart() {
    let root = TestRoot::new();
    {
        let (_, service) = service(&root);
        create_bucket(&service, "typed").await;
        put_typed(&service, "/typed/report.txt", TYPED).await;
    }
    let (_, service) = service(&root);
    let fetched = exchange(&service, signed(http::Method::GET, "/typed/report.txt", Bytes::new())).await;
    assert_headers(&fetched, TYPED);
    assert_eq!(fetched.body().as_ref(), b"typed body");
    let headed = exchange(&service, signed(http::Method::HEAD, "/typed/report.txt", Bytes::new())).await;
    assert_headers(&headed, TYPED);
}

/// Negative — an object written with no `Content-Type` answers the model default rather than
/// omitting the header, and carries none of the other stored headers.
#[tokio::test]
async fn an_untyped_object_answers_the_default_content_type() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "untyped").await;
    put_typed(&service, "/untyped/blob", &[]).await;
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = exchange(&service, signed(method, "/untyped/blob", Bytes::new())).await;
        assert_headers(&response, &[("content-type", "binary/octet-stream")]);
        for absent in [
            "content-encoding",
            "content-disposition",
            "content-language",
            "cache-control",
            "expires",
        ] {
            assert!(header(&response, absent).is_none(), "{absent} must not be invented");
        }
    }
}

/// Negative — an overwrite replaces the stored headers rather than merging with the old version's.
#[tokio::test]
async fn an_overwrite_replaces_the_stored_headers() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "overwrite").await;
    put_typed(&service, "/overwrite/report.txt", TYPED).await;
    put_typed(&service, "/overwrite/report.txt", &[("content-type", "application/json")]).await;
    let headed = exchange(&service, signed(http::Method::HEAD, "/overwrite/report.txt", Bytes::new())).await;
    assert_headers(&headed, &[("content-type", "application/json")]);
    assert!(header(&headed, "cache-control").is_none());
    assert!(header(&headed, "content-disposition").is_none());
}

/// Negative — each version answers its own headers, so an explicit older version is not
/// described by the newer version's `Content-Type`.
#[tokio::test]
async fn each_version_answers_its_own_headers() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "typed-versions").await;
    let enabled = super::multipart_versioning::set_versioning(&service, "typed-versions", "Enabled").await;
    assert_eq!(enabled.status(), 200, "{}", String::from_utf8_lossy(enabled.body()));
    let first = exchange(
        &service,
        signed_with_headers(
            http::Method::PUT,
            "/typed-versions/doc",
            Bytes::from_static(b"one"),
            headers_of(&[("content-type", "text/csv")]),
        ),
    )
    .await;
    let first_version = header(&first, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("an ASCII version id")
        .to_owned();
    put_typed(&service, "/typed-versions/doc", &[("content-type", "text/html")]).await;
    let old = exchange(
        &service,
        signed(
            http::Method::HEAD,
            &format!("/typed-versions/doc?versionId={first_version}"),
            Bytes::new(),
        ),
    )
    .await;
    assert_headers(&old, &[("content-type", "text/csv")]);
    let current = exchange(&service, signed(http::Method::HEAD, "/typed-versions/doc", Bytes::new())).await;
    assert_headers(&current, &[("content-type", "text/html")]);
}

/// Positive — multipart takes the headers from the initiating request, as it does user metadata.
#[tokio::test]
async fn multipart_publishes_the_initiation_headers() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "typed-mpu").await;
    let initiated = exchange(
        &service,
        signed_with_headers(
            http::Method::POST,
            "/typed-mpu/video.mp4?uploads",
            Bytes::new(),
            headers_of(&[("content-type", "video/mp4"), ("cache-control", "no-cache")]),
        ),
    )
    .await;
    assert_eq!(initiated.status(), 200, "{}", String::from_utf8_lossy(initiated.body()));
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let part = upload_part(&service, "typed-mpu", "video.mp4", &upload_id, 1, b"frames").await;
    let completed = complete(&service, "typed-mpu", "video.mp4", &upload_id, &[(1, &part)]).await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    let headed = exchange(&service, signed(http::Method::HEAD, "/typed-mpu/video.mp4", Bytes::new())).await;
    assert_headers(&headed, &[("content-type", "video/mp4"), ("cache-control", "no-cache")]);
}

/// Positive and negative — `COPY` carries the source's headers and ignores the request's, while
/// `REPLACE` rebuilds them from the request, including dropping a header the request omits.
#[tokio::test]
async fn copy_directives_decide_the_stored_headers() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "typed-copy").await;
    put_typed(&service, "/typed-copy/source", TYPED).await;

    let mut copy_headers = headers_of(&[("content-type", "application/xml")]);
    copy_headers.insert("x-amz-copy-source", http::HeaderValue::from_static("/typed-copy/source"));
    let copied = exchange(
        &service,
        signed_with_headers(http::Method::PUT, "/typed-copy/copied", Bytes::new(), copy_headers.clone()),
    )
    .await;
    assert_eq!(copied.status(), 200, "{}", String::from_utf8_lossy(copied.body()));
    let headed = exchange(&service, signed(http::Method::HEAD, "/typed-copy/copied", Bytes::new())).await;
    assert_headers(&headed, TYPED);

    copy_headers.insert("x-amz-metadata-directive", http::HeaderValue::from_static("REPLACE"));
    let replaced = exchange(
        &service,
        signed_with_headers(http::Method::PUT, "/typed-copy/replaced", Bytes::new(), copy_headers),
    )
    .await;
    assert_eq!(replaced.status(), 200, "{}", String::from_utf8_lossy(replaced.body()));
    let headed = exchange(&service, signed(http::Method::HEAD, "/typed-copy/replaced", Bytes::new())).await;
    assert_headers(&headed, &[("content-type", "application/xml")]);
    assert!(header(&headed, "cache-control").is_none());
    assert!(header(&headed, "expires").is_none());
}
