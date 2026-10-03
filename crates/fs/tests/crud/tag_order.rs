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

//! An object's tag set answered in key order, as legacy RustFS answers it, once
//! `FsBackend::sorting_object_tags` is on (rustfs/gateway#1000).
//!
//! Responsible for: the default answering the written order; with the option on, the tags of every
//! write path — `x-amz-tagging` on `PutObject`, `CreateMultipartUpload` and a `REPLACE` copy, a
//! `PutObjectTagging` document, a `COPY` copy — answered in key byte order, on the current and on a
//! named version; the stored document left in written order, so a backend without the option
//! answers that order again; and what the option leaves alone: bucket tags and the tag count.
//! NOT responsible for: tag validation or storage (`object_tagging.rs`, `write_attributes.rs`).
//! Upstream: the assembled service over the fs backend (`super`). Downstream: nothing.

use super::*;

/// Three tags written out of order.
const OBJECT_DOCUMENT: &str = "<Tagging><TagSet><Tag><Key>zeta</Key><Value>1</Value></Tag><Tag><Key>alpha</Key><Value>2</Value></Tag><Tag><Key>Mid</Key><Value>3</Value></Tag></TagSet></Tagging>";
const OBJECT_DOCUMENT_MD5: &str = "3dj2lB9qRP+2T2USzEKgrA==";
const BUCKET_DOCUMENT: &str = "<Tagging><TagSet><Tag><Key>zz</Key><Value>1</Value></Tag><Tag><Key>aa</Key><Value>2</Value></Tag><Tag><Key>Mm</Key><Value>3</Value></Tag></TagSet></Tagging>";
const BUCKET_DOCUMENT_MD5: &str = "Ktfk8mrOoledRKKXG57IcQ==";

/// The fixture service over a backend that answers object tags in key order.
fn sorting(root: &TestRoot) -> S3Service {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
        .expect("a usable test root")
        .sorting_object_tags();
    service_with_backend(Arc::new(backend)).1
}

fn with_headers(pairs: &[(&'static str, &str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, http::HeaderValue::from_str(value).expect("an ASCII fixture header"));
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

/// Every `<Key>` of a tagging answer, in the order it lists them.
fn keys_of(document: &str) -> Vec<String> {
    document
        .split("<Key>")
        .skip(1)
        .filter_map(|rest| rest.split("</Key>").next())
        .map(ToOwned::to_owned)
        .collect()
}

async fn object_keys(service: &S3Service, target: &str) -> Vec<String> {
    let separator = if target.contains('?') { '&' } else { '?' };
    let response = exchange(service, signed(http::Method::GET, &format!("{target}{separator}tagging"), Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    keys_of(&String::from_utf8_lossy(response.body()))
}

fn keys(expected: &[&str]) -> Vec<String> {
    expected.iter().map(|key| (*key).to_owned()).collect()
}

/// A bucket holding `/{bucket}/header` tagged `foo=bar&bar` and `/{bucket}/document` tagged with
/// [`OBJECT_DOCUMENT`].
async fn tagged(service: &S3Service, bucket: &str) {
    create_bucket(service, bucket).await;
    let header = format!("/{bucket}/header");
    send(service, http::Method::PUT, &header, "body", &[("x-amz-tagging", "foo=bar&bar")]).await;
    let document = format!("/{bucket}/document");
    send(service, http::Method::PUT, &document, "body", &[]).await;
    send(
        service,
        http::Method::PUT,
        &format!("{document}?tagging"),
        OBJECT_DOCUMENT,
        &[("content-md5", OBJECT_DOCUMENT_MD5)],
    )
    .await;
}

/// Negative — by default a tag set is answered in the order it was written.
#[tokio::test]
async fn n_the_default_backend_answers_the_written_order() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    tagged(&service, "written").await;
    assert_eq!(object_keys(&service, "/written/header").await, keys(&["foo", "bar"]));
    assert_eq!(object_keys(&service, "/written/document").await, keys(&["zeta", "alpha", "Mid"]));
}

/// Positive — s3-tests `test_put_obj_with_tags`: `foo=bar&bar` is answered `bar` then `foo`, and a
/// `PutObjectTagging` document is answered in key byte order, capitals first.
#[tokio::test]
async fn header_and_document_tags_are_answered_in_key_order() {
    let root = TestRoot::new();
    let service = sorting(&root);
    tagged(&service, "sorted").await;
    let response = exchange(&service, signed(http::Method::GET, "/sorted/header?tagging", Bytes::new())).await;
    let text = String::from_utf8_lossy(response.body()).into_owned();
    assert_eq!(keys_of(&text), keys(&["bar", "foo"]), "{text}");
    assert!(
        text.contains("<Tag><Key>bar</Key><Value></Value></Tag>") || text.contains("<Tag><Key>bar</Key><Value/></Tag>"),
        "{text}"
    );
    assert!(text.contains("<Tag><Key>foo</Key><Value>bar</Value></Tag>"), "{text}");
    assert_eq!(object_keys(&service, "/sorted/document").await, keys(&["Mid", "alpha", "zeta"]));
}

/// Positive — the order is the keys' byte order, as legacy RustFS's string comparison gives it:
/// digits, capitals, `_`, then lowercase, a prefix before its extensions, and a multi-byte
/// character after every ASCII one.
#[tokio::test]
async fn the_order_is_the_keys_byte_order() {
    let root = TestRoot::new();
    let service = sorting(&root);
    create_bucket(&service, "bytes").await;
    send(
        &service,
        http::Method::PUT,
        "/bytes/key",
        "body",
        &[("x-amz-tagging", "b=1&A=2&a=3&_=4&Z=5&0=6&%C3%A9=7&aa=8&a-b=9")],
    )
    .await;
    assert_eq!(
        object_keys(&service, "/bytes/key").await,
        keys(&["0", "A", "Z", "_", "a", "a-b", "aa", "b", "\u{e9}"])
    );
}

/// Positive — the other write paths answer in key order too: a multipart upload's initiation tags,
/// a `REPLACE` copy's tags, a `COPY` copy of a document's tags, and a named version's tags.
#[tokio::test]
async fn every_write_path_is_answered_in_key_order() {
    let root = TestRoot::new();
    let service = sorting(&root);
    tagged(&service, "paths").await;

    let created = send(
        &service,
        http::Method::POST,
        "/paths/multipart?uploads",
        "",
        &[("x-amz-tagging", "z=1&m=2&a=3")],
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
    send(
        &service,
        http::Method::POST,
        &format!("/paths/multipart?uploadId={upload_id}"),
        &format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{e_tag}</ETag></Part></CompleteMultipartUpload>"
        ),
        &[],
    )
    .await;
    assert_eq!(object_keys(&service, "/paths/multipart").await, keys(&["a", "m", "z"]));

    send(
        &service,
        http::Method::PUT,
        "/paths/replaced",
        "",
        &[
            ("x-amz-copy-source", "/paths/header"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "y=1&c=2&k=3"),
        ],
    )
    .await;
    assert_eq!(object_keys(&service, "/paths/replaced").await, keys(&["c", "k", "y"]));
    send(
        &service,
        http::Method::PUT,
        "/paths/copied",
        "",
        &[("x-amz-copy-source", "/paths/document")],
    )
    .await;
    assert_eq!(object_keys(&service, "/paths/copied").await, keys(&["Mid", "alpha", "zeta"]));

    create_bucket(&service, "paths-versions").await;
    let enabled = super::multipart_versioning::set_versioning(&service, "paths-versions", "Enabled").await;
    assert_eq!(enabled.status(), 200);
    let first = send(&service, http::Method::PUT, "/paths-versions/key", "one", &[("x-amz-tagging", "q=1&c=2")]).await;
    let first = header(&first, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("ASCII")
        .to_owned();
    send(&service, http::Method::PUT, "/paths-versions/key", "two", &[("x-amz-tagging", "t=1&e=2")]).await;
    assert_eq!(
        object_keys(&service, &format!("/paths-versions/key?versionId={first}")).await,
        keys(&["c", "q"])
    );
    assert_eq!(object_keys(&service, "/paths-versions/key").await, keys(&["e", "t"]));
}

/// Negative — the key decides the order, never the value: keys already in order stay in order
/// however their values sort.
#[tokio::test]
async fn n_values_do_not_decide_the_order() {
    let root = TestRoot::new();
    let service = sorting(&root);
    create_bucket(&service, "values").await;
    send(&service, http::Method::PUT, "/values/key", "body", &[("x-amz-tagging", "a=zz&b=mm&c=aa")]).await;
    assert_eq!(object_keys(&service, "/values/key").await, keys(&["a", "b", "c"]));
}

/// Negative — the stored document keeps the written order: the option changes the answer only,
/// so the same data root opened without it answers the written order again.
#[tokio::test]
async fn n_the_stored_document_keeps_the_written_order() {
    let root = TestRoot::new();
    let service = sorting(&root);
    create_bucket(&service, "stored").await;
    send(
        &service,
        http::Method::PUT,
        "/stored/key",
        "body",
        &[("x-amz-tagging", "zeta=1&alpha=2&Mid=3")],
    )
    .await;
    assert_eq!(object_keys(&service, "/stored/key").await, keys(&["Mid", "alpha", "zeta"]));

    let versions = root.0.join(format!("b-{}/versions", hex::encode("stored")));
    let version = std::fs::read_dir(versions)
        .expect("the version authority exists")
        .map(|entry| entry.expect("a readable version entry").path())
        .find(|path| path.is_dir())
        .expect("one stored version");
    let stored = std::fs::read_to_string(version.join("tags")).expect("the stored tag document");
    assert_eq!(keys_of(&stored), keys(&["zeta", "alpha", "Mid"]), "{stored}");
    drop(service);

    let (_, reopened) = super::service(&root);
    assert_eq!(object_keys(&reopened, "/stored/key").await, keys(&["zeta", "alpha", "Mid"]));
}

/// Negative — bucket tags are not reordered: legacy RustFS answers them as written.
#[tokio::test]
async fn n_bucket_tags_keep_the_written_order() {
    let root = TestRoot::new();
    let service = sorting(&root);
    create_bucket(&service, "bucket-tags").await;
    send(
        &service,
        http::Method::PUT,
        "/bucket-tags?tagging",
        BUCKET_DOCUMENT,
        &[("content-md5", BUCKET_DOCUMENT_MD5)],
    )
    .await;
    let response = exchange(&service, signed(http::Method::GET, "/bucket-tags?tagging", Bytes::new())).await;
    assert_eq!(response.status(), 200);
    assert_eq!(keys_of(&String::from_utf8_lossy(response.body())), keys(&["zz", "aa", "Mm"]));
}

/// Negative — the tag count a read reports is unchanged by the order.
#[tokio::test]
async fn n_the_tag_count_is_unchanged() {
    let root = TestRoot::new();
    let service = sorting(&root);
    tagged(&service, "counted").await;
    for method in [http::Method::HEAD, http::Method::GET] {
        let response = exchange(&service, signed(method.clone(), "/counted/document", Bytes::new())).await;
        assert_eq!(response.status(), 200, "{method}");
        assert_eq!(
            header(&response, "x-amz-tagging-count").and_then(|value| value.to_str().ok()),
            Some("3"),
            "{method}"
        );
    }
}
