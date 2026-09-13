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

//! Signed production-service evidence for write-carried tags and storage classes
//! (rustfs/gateway#722).
//!
//! Responsible for: `PutObject`'s `x-amz-tagging` stored per version, its refusals leaving nothing
//! written, the storage class `PutObject` and `CopyObject` name, the tagging directive on a copy,
//! and the copy-source `If-None-Match` refusal for a bare entity tag.
//! NOT responsible for: the `?tagging` subresource, which `object_tagging.rs` covers, or the
//! quoted copy-source conditions, which `copy_object.rs` covers.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

fn with_headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a fixture header name"),
            http::HeaderValue::from_str(value).expect("a fixture header value"),
        );
    }
    headers
}

async fn put(service: &S3Service, target: &str, pairs: &[(&str, &str)]) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(b"attributes"), with_headers(pairs)),
    )
    .await
}

async fn copy(service: &S3Service, source: &str, target: &str, pairs: &[(&str, &str)]) -> rustfs_gateway::WireResponse {
    let mut headers = with_headers(pairs);
    headers.insert("x-amz-copy-source", http::HeaderValue::from_str(source).expect("a copy source"));
    exchange(service, signed_with_headers(http::Method::PUT, target, Bytes::new(), headers)).await
}

async fn tags(service: &S3Service, target: &str) -> Vec<(String, String)> {
    let separator = if target.contains('?') { '&' } else { '?' };
    let response = exchange(service, signed(http::Method::GET, &format!("{target}{separator}tagging"), Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", text(&response));
    let body = text(&response);
    body.split("<Tag>")
        .skip(1)
        .map(|entry| {
            let key = element(entry.as_bytes(), "Key").expect("a tag key");
            let value = element(entry.as_bytes(), "Value").expect("a tag value");
            (key, value)
        })
        .collect()
}

async fn storage_class(service: &S3Service, target: &str) -> Option<String> {
    let response = exchange(service, signed(http::Method::HEAD, target, Bytes::new())).await;
    assert_eq!(response.status(), 200, "{target}");
    header(&response, "x-amz-storage-class").map(|value| value.to_str().expect("ASCII").to_owned())
}

fn text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

async fn status_of(service: &S3Service, target: &str) -> u16 {
    exchange(service, signed(http::Method::HEAD, target, Bytes::new()))
        .await
        .status()
        .as_u16()
}

/// Positive — the tags a `PutObject` carries are stored with that version, and each version in an
/// enabled bucket keeps its own set (the mint `versioning` suite's shape).
#[tokio::test]
async fn put_tags_are_stored_per_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "put-tags").await;
    let enabled = super::multipart_versioning::set_versioning(&service, "put-tags", "Enabled").await;
    assert_eq!(enabled.status(), 200, "{}", text(&enabled));
    let first = put(&service, "/put-tags/doc", &[("x-amz-tagging", "team=blue&tier=gold")]).await;
    assert_eq!(first.status(), 200, "{}", text(&first));
    let first_version = header(&first, "x-amz-version-id")
        .expect("a version")
        .to_str()
        .expect("ASCII")
        .to_owned();
    let second = put(&service, "/put-tags/doc", &[("x-amz-tagging", "team=red")]).await;
    assert_eq!(second.status(), 200, "{}", text(&second));
    assert_eq!(tags(&service, "/put-tags/doc").await, pairs(&[("team", "red")]));
    assert_eq!(
        tags(&service, &format!("/put-tags/doc?versionId={first_version}")).await,
        pairs(&[("team", "blue"), ("tier", "gold")])
    );
}

/// Negative — an overwrite that carries no tags does not inherit the replaced version's tags.
#[tokio::test]
async fn an_untagged_overwrite_has_no_tags() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "untagged").await;
    assert_eq!(put(&service, "/untagged/doc", &[("x-amz-tagging", "a=1")]).await.status(), 200);
    assert_eq!(put(&service, "/untagged/doc", &[]).await.status(), 200);
    assert!(tags(&service, "/untagged/doc").await.is_empty());
}

/// Negative — a malformed or over-long tag header refuses the write, and nothing is stored.
#[tokio::test]
async fn a_refused_tag_header_writes_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "bad-tags").await;
    let too_many = (0..11).map(|index| format!("k{index}=v")).collect::<Vec<_>>().join("&");
    for header_value in ["novalue", "a=1&a=2", too_many.as_str()] {
        let refused = put(&service, "/bad-tags/doc", &[("x-amz-tagging", header_value)]).await;
        assert_eq!(refused.status(), 400, "{header_value}: {}", text(&refused));
        // The tag refusal itself, not an abandoned-body report standing in for it.
        assert!(!text(&refused).contains("IncompleteBody"), "{header_value}: {}", text(&refused));
        assert_eq!(status_of(&service, "/bad-tags/doc").await, 404, "{header_value}");
    }
}

/// Positive — the storage class a `PutObject` names is recorded and reported.
#[tokio::test]
async fn put_records_its_storage_class() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "put-class").await;
    let stored = put(&service, "/put-class/doc", &[("x-amz-storage-class", "REDUCED_REDUNDANCY")]).await;
    assert_eq!(stored.status(), 200, "{}", text(&stored));
    assert_eq!(storage_class(&service, "/put-class/doc").await.as_deref(), Some("REDUCED_REDUNDANCY"));
    let listed = exchange(&service, signed(http::Method::GET, "/put-class?list-type=2", Bytes::new())).await;
    assert_eq!(element(listed.body(), "StorageClass").as_deref(), Some("REDUCED_REDUNDANCY"));
}

/// Negative — a class this backend cannot record refuses the write, and nothing is stored.
#[tokio::test]
async fn an_unrecordable_storage_class_writes_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "bad-class").await;
    let refused = put(&service, "/bad-class/doc", &[("x-amz-storage-class", "OUTPOSTS")]).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert!(text(&refused).contains("<Code>InvalidStorageClass</Code>"), "{}", text(&refused));
    assert_eq!(status_of(&service, "/bad-class/doc").await, 404);
}

/// Positive and negative — a copy records the class it names, and a copy that names none is
/// `STANDARD` whatever the source's class (the mint `awscli` suite's shape).
#[tokio::test]
async fn copy_applies_the_requested_class_only() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "copy-class").await;
    assert_eq!(
        put(&service, "/copy-class/src", &[("x-amz-storage-class", "STANDARD_IA")])
            .await
            .status(),
        200
    );
    let classed = copy(
        &service,
        "/copy-class/src",
        "/copy-class/classed",
        &[("x-amz-storage-class", "REDUCED_REDUNDANCY")],
    )
    .await;
    assert_eq!(classed.status(), 200, "{}", text(&classed));
    assert_eq!(
        storage_class(&service, "/copy-class/classed").await.as_deref(),
        Some("REDUCED_REDUNDANCY")
    );
    let plain = copy(&service, "/copy-class/src", "/copy-class/plain", &[]).await;
    assert_eq!(plain.status(), 200, "{}", text(&plain));
    assert_ne!(storage_class(&service, "/copy-class/plain").await.as_deref(), Some("STANDARD_IA"));
    assert_eq!(storage_class(&service, "/copy-class/src").await.as_deref(), Some("STANDARD_IA"));
}

/// Positive — a self copy that only names a new class is a change, not a refused no-op.
#[tokio::test]
async fn a_self_copy_may_change_only_the_class() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "self-class").await;
    assert_eq!(put(&service, "/self-class/doc", &[]).await.status(), 200);
    let moved = copy(&service, "/self-class/doc", "/self-class/doc", &[("x-amz-storage-class", "STANDARD_IA")]).await;
    assert_eq!(moved.status(), 200, "{}", text(&moved));
    assert_eq!(storage_class(&service, "/self-class/doc").await.as_deref(), Some("STANDARD_IA"));
}

/// Negative — a copy naming an unrecordable class writes no destination.
#[tokio::test]
async fn a_copy_with_an_unrecordable_class_writes_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "copy-bad-class").await;
    assert_eq!(put(&service, "/copy-bad-class/src", &[]).await.status(), 200);
    let refused = copy(
        &service,
        "/copy-bad-class/src",
        "/copy-bad-class/dst",
        &[("x-amz-storage-class", "OUTPOSTS")],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(status_of(&service, "/copy-bad-class/dst").await, 404);
}

/// Positive and negative — the default tagging directive copies the source's tags; `REPLACE` takes
/// the request's, including none at all.
#[tokio::test]
async fn the_tagging_directive_decides_the_copied_tags() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "copy-tags").await;
    assert_eq!(
        put(&service, "/copy-tags/src", &[("x-amz-tagging", "origin=src")])
            .await
            .status(),
        200
    );
    let inherited = copy(&service, "/copy-tags/src", "/copy-tags/inherited", &[("x-amz-tagging", "ignored=yes")]).await;
    assert_eq!(inherited.status(), 200, "{}", text(&inherited));
    assert_eq!(tags(&service, "/copy-tags/inherited").await, pairs(&[("origin", "src")]));
    let replaced = copy(
        &service,
        "/copy-tags/src",
        "/copy-tags/replaced",
        &[("x-amz-tagging-directive", "REPLACE"), ("x-amz-tagging", "origin=copy")],
    )
    .await;
    assert_eq!(replaced.status(), 200, "{}", text(&replaced));
    assert_eq!(tags(&service, "/copy-tags/replaced").await, pairs(&[("origin", "copy")]));
    let cleared = copy(
        &service,
        "/copy-tags/src",
        "/copy-tags/cleared",
        &[("x-amz-tagging-directive", "REPLACE")],
    )
    .await;
    assert_eq!(cleared.status(), 200, "{}", text(&cleared));
    assert!(tags(&service, "/copy-tags/cleared").await.is_empty());
}

/// Negative — an unknown tagging directive is refused without a destination write.
#[tokio::test]
async fn an_unknown_tagging_directive_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "copy-directive").await;
    assert_eq!(put(&service, "/copy-directive/src", &[]).await.status(), 200);
    let refused = copy(
        &service,
        "/copy-directive/src",
        "/copy-directive/dst",
        &[("x-amz-tagging-directive", "MERGE")],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(status_of(&service, "/copy-directive/dst").await, 404);
}

/// Negative — a copy-source `If-None-Match` naming the source's entity tag without quotes, as the
/// minio-js `CopyConditions.setMatchETagExcept` sends it, is refused with `412` and writes nothing.
#[tokio::test]
async fn a_bare_matching_copy_source_if_none_match_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "copy-bare").await;
    let stored = put(&service, "/copy-bare/src", &[]).await;
    let quoted = header(&stored, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("ASCII")
        .to_owned();
    let bare = quoted.trim_matches('"').to_owned();
    let refused = copy(
        &service,
        "/copy-bare/src",
        "/copy-bare/dst",
        &[("x-amz-copy-source-if-none-match", bare.as_str())],
    )
    .await;
    assert_eq!(refused.status(), 412, "{}", text(&refused));
    assert_eq!(status_of(&service, "/copy-bare/dst").await, 404);
}
