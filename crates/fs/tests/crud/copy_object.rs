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

//! Signed production-service evidence for filesystem-backed server-side copies.
//!
//! Responsible for: proving `CopyObject` preserves bytes while applying the metadata source the
//! request selected, including rclone's self-copy modification-time update. NOT responsible for:
//! parsing or authorizing `x-amz-copy-source`, which the gateway completes before dispatch.
//! Upstream: the public `rustfs-gateway` service and `rustfs-gateway-fs`. Downstream: the fs crate
//! verification gate.

use bytes::Bytes;

use std::sync::Arc;

use rustfs_gateway::{
    ClockSkewAck, Credentials, FixedClock, MetadataSource, RegionSet, S3Service, SigV4Authenticator, StaticCredentials,
    allow_when,
};
use rustfs_gateway_fs::FsBackend;

use super::{SIGNED_AT_SECONDS, TestRoot, create_bucket, exchange, header, service, signed, signed_with_headers};

async fn put(
    service: &S3Service,
    target: &str,
    body: &'static [u8],
    metadata: &[(&'static str, &'static str)],
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    for (name, value) in metadata {
        headers.insert(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    exchange(service, signed_with_headers(http::Method::PUT, target, Bytes::from_static(body), headers)).await
}

async fn copy(service: &S3Service, source: &str, target: &str, headers: &[(&str, &str)]) -> rustfs_gateway::WireResponse {
    let mut copy_headers = http::HeaderMap::new();
    copy_headers.insert(
        "x-amz-copy-source",
        http::HeaderValue::from_str(source).expect("a valid copy-source fixture"),
    );
    for (name, value) in headers {
        copy_headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a valid fixture header name"),
            http::HeaderValue::from_str(value).expect("a valid fixture header value"),
        );
    }
    exchange(service, signed_with_headers(http::Method::PUT, target, Bytes::new(), copy_headers)).await
}

async fn get(service: &S3Service, target: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

fn body(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

#[test]
fn metadata_source_is_reachable_through_the_public_facade() {
    assert_eq!(MetadataSource::parse(Some("REPLACE")), Some(MetadataSource::FromRequest));
}

/// Positive — rclone updates mtime by copying the object onto itself with metadata replacement.
/// The operation must preserve the bytes and ETag while replacing, rather than merging, metadata.
#[tokio::test]
async fn rclone_self_copy_replaces_mtime_and_converges() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "rclone").await;

    let initial = put(&service, "/rclone/nested/file.bin", b"payload", &[("x-amz-meta-stale", "remove-me")]).await;
    assert_eq!(initial.status(), http::StatusCode::OK);
    let original_etag = header(&initial, "etag").expect("PutObject returns an ETag").clone();

    let copied = copy(
        &service,
        "/rclone/nested/file.bin",
        "/rclone/nested/file.bin",
        &[
            ("x-amz-metadata-directive", "REPLACE"),
            ("x-amz-meta-mtime", "1767323045.000000000"),
        ],
    )
    .await;
    assert_eq!(copied.status(), http::StatusCode::OK, "{}", String::from_utf8_lossy(copied.body()));
    assert!(String::from_utf8_lossy(copied.body()).contains("<CopyObjectResult"));

    let fetched = get(&service, "/rclone/nested/file.bin").await;
    assert_eq!(fetched.status(), http::StatusCode::OK);
    assert_eq!(fetched.body().as_ref(), b"payload");
    assert_eq!(header(&fetched, "etag"), Some(&original_etag));
    assert_eq!(
        header(&fetched, "x-amz-meta-mtime"),
        Some(&http::HeaderValue::from_static("1767323045.000000000"))
    );
    assert_eq!(header(&fetched, "x-amz-meta-stale"), None, "REPLACE must not merge source metadata");
}

/// Positive — COPY inherits metadata and a matching source condition observes the selected source.
#[tokio::test]
async fn copy_inherits_source_metadata_and_bytes() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "copy").await;
    let stored = put(&service, "/copy/source", b"source-body", &[("x-amz-meta-owner", "source")]).await;
    let source_etag = header(&stored, "etag")
        .expect("PutObject returns an ETag")
        .to_str()
        .expect("an ASCII ETag")
        .to_owned();

    let copied = copy(
        &service,
        "/copy/source",
        "/copy/destination",
        &[("x-amz-copy-source-if-match", source_etag.as_str())],
    )
    .await;
    assert_eq!(copied.status(), http::StatusCode::OK, "{}", body(&copied));
    assert!(body(&copied).contains("<CopyObjectResult"));
    let escaped_etag = source_etag.replace('"', "&quot;");
    assert!(body(&copied).contains(&format!("<ETag>{escaped_etag}</ETag>")));

    let fetched = get(&service, "/copy/destination").await;
    assert_eq!(fetched.status(), http::StatusCode::OK);
    assert_eq!(fetched.body().as_ref(), b"source-body");
    assert_eq!(header(&fetched, "x-amz-meta-owner"), Some(&http::HeaderValue::from_static("source")));
}

/// Positive — REPLACE with no user metadata means an empty destination map, not COPY and not merge.
#[tokio::test]
async fn replace_without_metadata_clears_the_source_map() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "replace").await;
    assert_eq!(
        put(&service, "/replace/source", b"bytes", &[("x-amz-meta-old", "discard")],)
            .await
            .status(),
        http::StatusCode::OK
    );

    let copied = copy(
        &service,
        "/replace/source",
        "/replace/destination",
        &[("x-amz-metadata-directive", "REPLACE")],
    )
    .await;
    assert_eq!(copied.status(), http::StatusCode::OK, "{}", body(&copied));
    let fetched = get(&service, "/replace/destination").await;
    assert_eq!(fetched.body().as_ref(), b"bytes");
    assert_eq!(header(&fetched, "x-amz-meta-old"), None);
}

async fn enable_versioning(service: &S3Service, bucket: &str) {
    create_bucket(service, bucket).await;
    let document = Bytes::from_static(
        b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>",
    );
    let mut checksum = http::HeaderMap::new();
    checksum.insert("content-md5", http::HeaderValue::from_static("QQFYoy/mRYV9PGZUfFi0Bw=="));
    let target = format!("/{bucket}?versioning");
    let enabled = exchange(service, signed_with_headers(http::Method::PUT, &target, document, checksum)).await;
    assert_eq!(enabled.status(), http::StatusCode::OK, "{}", body(&enabled));
}

/// Positive — an explicit source version selects historic bytes and is reported separately from
/// the new destination version.
#[tokio::test]
async fn copy_reads_and_reports_the_explicit_source_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    enable_versioning(&service, "versions").await;
    let historic = put(&service, "/versions/source", b"historic", &[]).await;
    let historic_id = header(&historic, "x-amz-version-id")
        .expect("an enabled PutObject version")
        .to_str()
        .expect("an ASCII version id")
        .to_owned();
    assert_eq!(put(&service, "/versions/source", b"current", &[]).await.status(), http::StatusCode::OK);

    let copied = copy(
        &service,
        &format!("/versions/source?versionId={historic_id}"),
        "/versions/destination",
        &[],
    )
    .await;
    assert_eq!(copied.status(), http::StatusCode::OK, "{}", body(&copied));
    assert_eq!(
        header(&copied, "x-amz-copy-source-version-id").and_then(|value| value.to_str().ok()),
        Some(historic_id.as_str())
    );
    let destination_id = header(&copied, "x-amz-version-id").expect("the destination receives its own version");
    assert_ne!(destination_id.to_str().expect("an ASCII version id"), historic_id);
    assert_eq!(get(&service, "/versions/destination").await.body().as_ref(), b"historic");
}

/// Negative — a copy answers `x-amz-version-id` for the version it wrote, so a source that is a
/// delete marker is refused with the marker flag and without the marker's id, whether the copy
/// named the marker or found it current. A read of the same key is the control that does name it.
#[tokio::test]
async fn a_delete_marker_source_is_refused_without_naming_the_marker_as_the_copys_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    enable_versioning(&service, "versions").await;
    assert_eq!(put(&service, "/versions/source", b"bytes", &[]).await.status(), http::StatusCode::OK);
    let deleted = exchange(&service, signed(http::Method::DELETE, "/versions/source", Bytes::new())).await;
    let marker = header(&deleted, "x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        .expect("a versioned delete mints a marker")
        .to_owned();

    let read = get(&service, "/versions/source").await;
    assert_eq!(read.status(), http::StatusCode::NOT_FOUND, "{}", body(&read));
    assert_eq!(
        header(&read, "x-amz-version-id").and_then(|value| value.to_str().ok()),
        Some(marker.as_str())
    );

    for (source, status) in [
        (format!("/versions/source?versionId={marker}"), http::StatusCode::METHOD_NOT_ALLOWED),
        ("/versions/source".to_owned(), http::StatusCode::NOT_FOUND),
    ] {
        let copied = copy(&service, &source, "/versions/destination", &[]).await;
        assert_eq!(copied.status(), status, "{source}: {}", body(&copied));
        assert_eq!(
            header(&copied, "x-amz-delete-marker").and_then(|value| value.to_str().ok()),
            Some("true"),
            "{source}"
        );
        assert!(header(&copied, "x-amz-version-id").is_none(), "{source}: {}", body(&copied));
    }
    assert_eq!(get(&service, "/versions/destination").await.status(), http::StatusCode::NOT_FOUND);
}

/// Negative — COPY onto the same current key changes nothing and must not mint a replacement.
#[tokio::test]
async fn a_no_op_self_copy_is_refused_without_changing_the_object() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "self-copy").await;
    assert_eq!(put(&service, "/self-copy/key", b"kept", &[]).await.status(), http::StatusCode::OK);

    let refused = copy(&service, "/self-copy/key", "/self-copy/key", &[]).await;
    assert_eq!(refused.status(), http::StatusCode::BAD_REQUEST, "{}", body(&refused));
    assert!(body(&refused).contains("<Code>InvalidRequest</Code>"));
    assert_eq!(get(&service, "/self-copy/key").await.body().as_ref(), b"kept");
}

/// Negative — an unknown directive is not silently treated as COPY.
#[tokio::test]
async fn an_unknown_metadata_directive_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "directive").await;
    assert_eq!(put(&service, "/directive/source", b"source", &[]).await.status(), http::StatusCode::OK);

    let refused = copy(
        &service,
        "/directive/source",
        "/directive/destination",
        &[("x-amz-metadata-directive", "replace")],
    )
    .await;
    assert_eq!(refused.status(), http::StatusCode::BAD_REQUEST, "{}", body(&refused));
    assert!(body(&refused).contains("<Code>InvalidArgument</Code>"));
    assert_eq!(get(&service, "/directive/destination").await.status(), http::StatusCode::NOT_FOUND);
}

/// Negative — a source that does not exist never creates a destination.
#[tokio::test]
async fn a_missing_source_is_refused_without_a_target_write() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "missing-source").await;

    let refused = copy(&service, "/missing-source/absent", "/missing-source/destination", &[]).await;
    assert_eq!(refused.status(), http::StatusCode::NOT_FOUND, "{}", body(&refused));
    assert!(body(&refused).contains("<Code>NoSuchKey</Code>"));
    assert_eq!(get(&service, "/missing-source/destination").await.status(), http::StatusCode::NOT_FOUND);
}

async fn condition_fixture(
    bucket: &'static str,
    condition: (&'static str, &'static str),
) -> (rustfs_gateway::WireResponse, rustfs_gateway::WireResponse) {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, bucket).await;
    assert_eq!(
        put(&service, &format!("/{bucket}/source"), b"source", &[]).await.status(),
        http::StatusCode::OK
    );
    let refused = copy(&service, &format!("/{bucket}/source"), &format!("/{bucket}/destination"), &[condition]).await;
    let destination = get(&service, &format!("/{bucket}/destination")).await;
    (refused, destination)
}

/// Negative — a matching source If-None-Match blocks the copy before the destination write.
#[tokio::test]
async fn source_if_none_match_is_evaluated_before_writing() {
    let digest = "\"36cd38f49b9afa08222c0dc9ebfe35eb\"";
    let (refused, destination) = condition_fixture("if-none", ("x-amz-copy-source-if-none-match", digest)).await;
    assert_eq!(refused.status(), http::StatusCode::PRECONDITION_FAILED, "{}", body(&refused));
    assert_eq!(destination.status(), http::StatusCode::NOT_FOUND);
}

/// Negative — a modified-since bound equal to the source time is false and is not a future date
/// that the shared contract deliberately ignores.
#[tokio::test]
async fn source_if_modified_since_is_evaluated_before_writing() {
    let (refused, destination) =
        condition_fixture("if-modified", ("x-amz-copy-source-if-modified-since", "Fri, 02 Jan 2026 03:04:05 GMT")).await;
    assert_eq!(refused.status(), http::StatusCode::PRECONDITION_FAILED, "{}", body(&refused));
    assert_eq!(destination.status(), http::StatusCode::NOT_FOUND);
}

/// Negative — a past unmodified-since bound means the source changed after the allowed instant.
#[tokio::test]
async fn source_if_unmodified_since_is_evaluated_before_writing() {
    let (refused, destination) = condition_fixture(
        "if-unmodified",
        ("x-amz-copy-source-if-unmodified-since", "Thu, 01 Jan 2026 00:00:00 GMT"),
    )
    .await;
    assert_eq!(refused.status(), http::StatusCode::PRECONDITION_FAILED, "{}", body(&refused));
    assert_eq!(destination.status(), http::StatusCode::NOT_FOUND);
}

/// Negative — mutually exclusive source ETag conditions are a malformed request, not a guess.
#[tokio::test]
async fn conflicting_source_etag_conditions_are_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "condition-conflict").await;
    let stored = put(&service, "/condition-conflict/source", b"source", &[]).await;
    let digest = header(&stored, "etag")
        .expect("PutObject returns an ETag")
        .to_str()
        .expect("an ASCII ETag")
        .to_owned();
    let refused = copy(
        &service,
        "/condition-conflict/source",
        "/condition-conflict/destination",
        &[
            ("x-amz-copy-source-if-match", digest.as_str()),
            ("x-amz-copy-source-if-none-match", digest.as_str()),
        ],
    )
    .await;
    assert_eq!(refused.status(), http::StatusCode::BAD_REQUEST, "{}", body(&refused));
    assert_eq!(
        get(&service, "/condition-conflict/destination").await.status(),
        http::StatusCode::NOT_FOUND
    );
}

/// Negative — the destination permission cannot stand in for the derived source read permission.
#[tokio::test]
async fn source_authorization_denial_prevents_the_copy_handler_write() {
    let root = TestRoot::new();
    let (backend, allowed) = service(&root);
    create_bucket(&allowed, "authorization").await;
    assert_eq!(
        put(&allowed, "/authorization/source", b"secret", &[]).await.status(),
        http::StatusCode::OK
    );
    drop(allowed);
    drop(backend);

    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("the stored backend reopens"),
    );
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid fixture credentials")));
    let denied = backend
        .register_crud(
            rustfs_gateway::ServiceBuilder::new()
                .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("one region")))
                .authorizer(allow_when(|request| request.action != "s3:GetObject"))
                .clock_with_skew_ack(
                    FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
                    ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
                ),
        )
        .build()
        .expect("the CopyObject registry is complete");
    let refused = copy(&denied, "/authorization/source", "/authorization/destination", &[]).await;
    assert_eq!(refused.status(), http::StatusCode::FORBIDDEN, "{}", body(&refused));
    assert!(body(&refused).contains("<Code>AccessDenied</Code>"));
    drop(denied);
    drop(backend);

    let (_, allowed) = service(&root);
    assert_eq!(get(&allowed, "/authorization/destination").await.status(), http::StatusCode::NOT_FOUND);
}
