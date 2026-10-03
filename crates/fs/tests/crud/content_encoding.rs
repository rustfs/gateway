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

//! A stored `Content-Encoding` normalized as legacy RustFS normalizes it, once
//! `FsBackend::normalizing_content_encoding` is on (rustfs/gateway#1203).
//!
//! Responsible for: the default storing the declared value; with the option on, every
//! `aws-chunked` token dropped from an unframed upload's value (s3-tests
//! `test_object_content_encoding_aws_chunked`), the rest trimmed and joined with `, `, and nothing
//! stored when nothing remains — on `PutObject`, `CreateMultipartUpload` and a `REPLACE` copy — while
//! values without the token, lookalike tokens, a `COPY` copy's source value and the other stored
//! headers are left as they are.
//! NOT responsible for: the core stripping the token from a chunk-framed body (#813), or the other
//! stored headers (`content_headers.rs`).
//! Upstream: the assembled service over the fs backend (`super`). Downstream: nothing.

use super::*;

/// The fixture service over a backend that normalizes a stored `Content-Encoding`.
fn normalizing(root: &TestRoot) -> S3Service {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
        .expect("a usable test root")
        .normalizing_content_encoding();
    service_with_backend(Arc::new(backend)).1
}

fn with_headers(pairs: &[(&'static str, &str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, http::HeaderValue::from_str(value).expect("a fixture header value"));
    }
    headers
}

async fn send(
    service: &S3Service,
    method: http::Method,
    target: &str,
    body: &str,
    pairs: &[(&'static str, &str)],
) -> rustfs_gateway::WireResponse {
    let response = exchange(
        service,
        signed_with_headers(method, target, Bytes::copy_from_slice(body.as_bytes()), with_headers(pairs)),
    )
    .await;
    assert!(
        response.status().is_success(),
        "{target}: {} {}",
        response.status(),
        String::from_utf8_lossy(response.body())
    );
    response
}

/// The `Content-Encoding` a `HEAD` answers, checked against the one a `GET` answers.
async fn answered(service: &S3Service, target: &str) -> Option<String> {
    let mut seen = Vec::new();
    for method in [http::Method::HEAD, http::Method::GET] {
        let response = exchange(service, signed(method, target, Bytes::new())).await;
        assert_eq!(response.status(), 200, "{target}");
        seen.push(header(&response, "content-encoding").map(|value| value.to_str().expect("ASCII").to_owned()));
    }
    assert_eq!(seen[0], seen[1], "HEAD and GET agree on {target}");
    seen.remove(0)
}

/// Stores `/{bucket}/{index}` for each value with a plain body and returns what each answers.
async fn stored(service: &S3Service, bucket: &str, values: &[&str]) -> Vec<Option<String>> {
    create_bucket(service, bucket).await;
    let mut answers = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let target = format!("/{bucket}/{index}");
        send(service, http::Method::PUT, &target, "plain body", &[("content-encoding", value)]).await;
        answers.push(answered(service, &target).await);
    }
    answers
}

fn some(values: &[&str]) -> Vec<Option<String>> {
    values.iter().map(|value| Some((*value).to_owned())).collect()
}

/// Negative — by default the declared value is stored and answered as sent.
#[tokio::test]
async fn n_the_default_backend_stores_the_declared_value() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let values = ["gzip, aws-chunked", "aws-chunked", "gzip,deflate"];
    assert_eq!(stored(&service, "declared", &values).await, some(&values));
}

/// Positive — every `aws-chunked` token is dropped, whatever its case or spacing, and nothing is
/// stored when nothing remains.
#[tokio::test]
async fn the_token_is_dropped_from_an_unframed_upload() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    let values = [
        "gzip, aws-chunked",
        "aws-chunked",
        "AWS-Chunked, gzip",
        "gzip , aws-chunked ",
        "gzip, aws-chunked, br",
        "aws-chunked, aws-chunked",
        " , ",
    ];
    let expected = [Some("gzip"), None, Some("gzip"), Some("gzip"), Some("gzip, br"), None, None]
        .map(|value| value.map(ToOwned::to_owned))
        .to_vec();
    assert_eq!(stored(&service, "stripped", &values).await, expected);
}

/// Positive — the remaining values are trimmed and joined with `, `, empty members dropped.
#[tokio::test]
async fn the_remaining_values_are_joined_with_a_comma_and_a_space() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    let values = ["gzip,deflate", "gzip,,br", " br "];
    assert_eq!(stored(&service, "joined", &values).await, some(&["gzip, deflate", "gzip, br", "br"]));
}

/// Negative — a value without the token is stored as sent, capitals included.
#[tokio::test]
async fn n_values_without_the_token_are_stored_as_sent() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    let values = ["gzip", "deflate, gzip", "identity", "GZIP"];
    assert_eq!(stored(&service, "unchanged", &values).await, some(&values));
}

/// Negative — only the whole token is dropped: a longer name or a parameter keeps the member.
#[tokio::test]
async fn n_lookalike_tokens_are_kept() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    let values = ["x-aws-chunked", "aws-chunked;q=1", "aws-chunkedgzip"];
    assert_eq!(stored(&service, "lookalikes", &values).await, some(&values));
}

/// Positive — a multipart upload's initiation and a `REPLACE` copy store the normalized value.
#[tokio::test]
async fn multipart_and_replace_copies_store_the_normalized_value() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "paths").await;

    let created = send(
        &service,
        http::Method::POST,
        "/paths/multipart?uploads",
        "",
        &[("content-encoding", "gzip, aws-chunked")],
    )
    .await;
    let upload_id = element(created.body(), "UploadId").expect("an upload id");
    let part = send(
        &service,
        http::Method::PUT,
        &format!("/paths/multipart?partNumber=1&uploadId={upload_id}"),
        "part",
        &[],
    )
    .await;
    let e_tag = header(&part, "etag").expect("a part tag").to_str().expect("ASCII").to_owned();
    let document =
        format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{e_tag}</ETag></Part></CompleteMultipartUpload>");
    send(
        &service,
        http::Method::POST,
        &format!("/paths/multipart?uploadId={upload_id}"),
        &document,
        &[],
    )
    .await;
    assert_eq!(answered(&service, "/paths/multipart").await.as_deref(), Some("gzip"));

    send(&service, http::Method::PUT, "/paths/source", "source", &[("content-encoding", "br")]).await;
    for (key, value, expected) in [
        ("replaced", "aws-chunked", None),
        ("rejoined", "gzip,deflate", Some("gzip, deflate")),
    ] {
        let target = format!("/paths/{key}");
        send(
            &service,
            http::Method::PUT,
            &target,
            "",
            &[
                ("x-amz-copy-source", "/paths/source"),
                ("x-amz-metadata-directive", "REPLACE"),
                ("content-encoding", value),
            ],
        )
        .await;
        assert_eq!(answered(&service, &target).await.as_deref(), expected, "{key}");
    }
}

/// Negative — a `COPY` copy keeps the source's stored value and never reads the request's.
#[tokio::test]
async fn n_a_copy_keeps_its_sources_value() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "copied").await;
    send(&service, http::Method::PUT, "/copied/source", "source", &[("content-encoding", "br")]).await;
    send(
        &service,
        http::Method::PUT,
        "/copied/copy",
        "",
        &[
            ("x-amz-copy-source", "/copied/source"),
            ("content-encoding", "gzip, aws-chunked"),
        ],
    )
    .await;
    assert_eq!(answered(&service, "/copied/copy").await.as_deref(), Some("br"));
}

/// Negative — only `Content-Encoding` is normalized: the token in another stored header stays.
#[tokio::test]
async fn n_the_other_stored_headers_are_left_alone() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "others").await;
    let pairs = [
        ("content-encoding", "aws-chunked"),
        ("content-language", "aws-chunked"),
        ("cache-control", "no-cache, aws-chunked"),
        ("content-disposition", "inline,aws-chunked"),
    ];
    send(&service, http::Method::PUT, "/others/key", "body", &pairs).await;
    let response = exchange(&service, signed(http::Method::HEAD, "/others/key", Bytes::new())).await;
    assert_eq!(header(&response, "content-encoding"), None);
    for (name, value) in &pairs[1..] {
        assert_eq!(header(&response, name).and_then(|stored| stored.to_str().ok()), Some(*value), "{name}");
    }
}
