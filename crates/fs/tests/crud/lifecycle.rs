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

//! Signed production-service evidence for persistent bucket lifecycle configuration.
//!
//! Responsible for: complete rule replacement, read/delete semantics, restart persistence,
//! direct-handler validation, and corrupt or unsafe lifecycle-authority refusal.
//! NOT responsible for: lifecycle expiration execution, debug intervals, object tags, or transition workers.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

const DOCUMENT: &str = concat!(
    "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    "<Rule><Expiration><Days>30</Days></Expiration><ID>archive</ID>",
    "<Filter><And><Prefix>logs/</Prefix><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan></And></Filter>",
    "<Status>Enabled</Status><Transition><Days>7</Days><StorageClass>STANDARD_IA</StorageClass></Transition>",
    "<NoncurrentVersionExpiration><NoncurrentDays>5</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions>",
    "</NoncurrentVersionExpiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation>",
    "</AbortIncompleteMultipartUpload></Rule><Rule><Expiration><ExpiredObjectDeleteMarker>true",
    "</ExpiredObjectDeleteMarker></Expiration><ID>future</ID><Prefix>tmp/</Prefix><Status>Disabled</Status></Rule>",
    "</LifecycleConfiguration>"
);
const DOCUMENT_MD5: &str = "I2bt5DeWnoSXxCWGk37M8Q==";

fn lifecycle_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::HeaderName::from_static("content-md5"), http::HeaderValue::from_static(DOCUMENT_MD5));
    headers.insert(
        http::HeaderName::from_static("x-amz-transition-default-minimum-object-size"),
        http::HeaderValue::from_static("all_storage_classes_128K"),
    );
    headers
}

async fn put_lifecycle(service: &S3Service, bucket: &str) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("/{bucket}?lifecycle"),
            Bytes::from_static(DOCUMENT.as_bytes()),
            lifecycle_headers(),
        ),
    )
    .await
}

fn response_body(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

pub(super) fn lifecycle_record(root: &TestRoot, bucket: &str) -> PathBuf {
    root.0.join(format!("b-{}/lifecycle", hex::encode(bucket)))
}

/// Positive — every structured rule member and the transition header survive a backend reopen.
#[tokio::test]
async fn lifecycle_configuration_round_trips_and_survives_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "retention").await;
    let stored = put_lifecycle(&running, "retention").await;
    assert_eq!(stored.status(), 200, "{}", response_body(&stored));
    assert_eq!(
        header(&stored, "x-amz-transition-default-minimum-object-size"),
        Some(&http::HeaderValue::from_static("all_storage_classes_128K"))
    );
    drop(running);

    let (_, reopened) = service(&root);
    let fetched = exchange(&reopened, signed(http::Method::GET, "/retention?lifecycle", Bytes::new())).await;
    assert_eq!(fetched.status(), 200, "{}", response_body(&fetched));
    assert_eq!(
        header(&fetched, "x-amz-transition-default-minimum-object-size"),
        Some(&http::HeaderValue::from_static("all_storage_classes_128K"))
    );
    let body = response_body(&fetched);
    for member in [
        "<ID>archive</ID>",
        "<Prefix>logs/</Prefix>",
        "<ObjectSizeGreaterThan>10</ObjectSizeGreaterThan>",
        "<Days>30</Days>",
        "<StorageClass>STANDARD_IA</StorageClass>",
        "<NoncurrentDays>5</NoncurrentDays>",
        "<NewerNoncurrentVersions>2</NewerNoncurrentVersions>",
        "<DaysAfterInitiation>3</DaysAfterInitiation>",
        "<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>",
        "<Status>Disabled</Status>",
    ] {
        assert!(body.contains(member), "missing {member} in {body}");
    }

    let deleted = exchange(&reopened, signed(http::Method::DELETE, "/retention?lifecycle", Bytes::new())).await;
    assert_eq!(deleted.status(), 204);
    let absent = exchange(&reopened, signed(http::Method::GET, "/retention?lifecycle", Bytes::new())).await;
    assert_eq!(absent.status(), 404);
    assert!(response_body(&absent).contains("<Code>NoSuchLifecycleConfiguration</Code>"));
}

/// Negative — absent configuration differs from a missing bucket, while deleting absence succeeds.
#[tokio::test]
async fn absent_configuration_and_missing_bucket_remain_distinct() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "configured-later").await;
    let absent = exchange(&service, signed(http::Method::GET, "/configured-later?lifecycle", Bytes::new())).await;
    assert_eq!(absent.status(), 404);
    assert!(response_body(&absent).contains("<Code>NoSuchLifecycleConfiguration</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/configured-later?lifecycle", Bytes::new()),)
            .await
            .status(),
        204
    );

    for response in [
        exchange(&service, signed(http::Method::GET, "/missing-lc?lifecycle", Bytes::new())).await,
        exchange(&service, signed(http::Method::DELETE, "/missing-lc?lifecycle", Bytes::new())).await,
        put_lifecycle(&service, "missing-lc").await,
    ] {
        assert_eq!(response.status(), 404);
        assert!(response_body(&response).contains("<Code>NoSuchBucket</Code>"));
    }
}

/// Negative — direct handler callers cannot bypass the shared lifecycle semantic contract.
#[tokio::test]
async fn direct_invalid_configuration_is_refused_without_replacing_state() {
    let root = TestRoot::new();
    let (backend, service) = service(&root);
    create_bucket(&service, "validated").await;
    assert_eq!(put_lifecycle(&service, "validated").await.status(), 200);
    let invalid = dto::BucketLifecycleConfiguration {
        rules: vec![dto::LifecycleRule {
            expiration: Some(dto::LifecycleExpiration {
                days: Some(0),
                ..dto::LifecycleExpiration::default()
            }),
            prefix: Some("logs/".to_owned()),
            status: dto::Status::ENABLED,
            ..dto::LifecycleRule::default()
        }],
    };
    let error = Handler::<dto::PutBucketLifecycleConfiguration>::call(
        backend.as_ref(),
        Req::new(
            dto::PutBucketLifecycleConfigurationInput {
                bucket: BucketName::new("validated").expect("a valid bucket"),
                lifecycle_configuration: Some(invalid),
                ..dto::PutBucketLifecycleConfigurationInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect_err("zero expiration days must be refused");
    assert_eq!(
        error,
        rustfs_gateway::HandlerError::new(
            rustfs_gateway::ErrorCode::INVALID_ARGUMENT,
            "Days in the Expiration action must be a positive integer"
        )
    );
    let retained = exchange(&service, signed(http::Method::GET, "/validated?lifecycle", Bytes::new())).await;
    assert_eq!(retained.status(), 200);
    assert!(response_body(&retained).contains("<ID>archive</ID>"));
}

/// Negative — malformed persisted bytes fail closed instead of becoming an absent policy.
#[tokio::test]
async fn corrupt_lifecycle_authority_is_an_internal_error() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "corrupt-lc").await;
    assert_eq!(put_lifecycle(&service, "corrupt-lc").await.status(), 200);
    std::fs::write(lifecycle_record(&root, "corrupt-lc"), b"not a lifecycle record")
        .expect("the fixture corrupts the exact authority");
    let response = exchange(&service, signed(http::Method::GET, "/corrupt-lc?lifecycle", Bytes::new())).await;
    assert_eq!(response.status(), 500);
    assert!(response_body(&response).contains("<Code>InternalError</Code>"));
}

/// Negative — no lifecycle method follows a symbolic link outside the bucket authority.
#[cfg(unix)]
#[tokio::test]
async fn lifecycle_authority_symlink_is_refused_for_read_write_and_delete() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "linked-lc").await;
    let outside_record = outside.0.join("policy");
    std::fs::write(&outside_record, b"outside remains unchanged").expect("an outside fixture");
    symlink(&outside_record, lifecycle_record(&root, "linked-lc")).expect("a lifecycle symlink fixture");
    for response in [
        exchange(&service, signed(http::Method::GET, "/linked-lc?lifecycle", Bytes::new())).await,
        put_lifecycle(&service, "linked-lc").await,
        exchange(&service, signed(http::Method::DELETE, "/linked-lc?lifecycle", Bytes::new())).await,
    ] {
        assert_eq!(response.status(), 400, "{}", response_body(&response));
        assert!(response_body(&response).contains("<Code>InvalidRequest</Code>"));
    }
    assert_eq!(
        std::fs::read(&outside_record).expect("outside remains readable"),
        b"outside remains unchanged"
    );
}

/// Negative — deleting and recreating a bucket cannot leak its previous lifecycle policy.
#[tokio::test]
async fn bucket_recreation_does_not_restore_deleted_lifecycle_state() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "reborn-lc").await;
    assert_eq!(put_lifecycle(&service, "reborn-lc").await.status(), 200);
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/reborn-lc", Bytes::new()))
            .await
            .status(),
        204
    );
    create_bucket(&service, "reborn-lc").await;
    let response = exchange(&service, signed(http::Method::GET, "/reborn-lc?lifecycle", Bytes::new())).await;
    assert_eq!(response.status(), 404);
    assert!(response_body(&response).contains("<Code>NoSuchLifecycleConfiguration</Code>"));
}
