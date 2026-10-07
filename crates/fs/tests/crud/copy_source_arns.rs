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

//! ARN copy sources must not alias ordinary filesystem buckets.
//!
//! Responsible for: object/part refusal, same-name and missing buckets, and authorization order.
//! NOT responsible for: parsing ARN spellings or implementing access points and Outposts.
//! Upstream: the production copy routes. Downstream: filesystem data and the verification gate.

use super::*;

const DESTINATION: &str = "/destination/kept";
const ORIGINAL: &[u8] = b"original destination";
const SOURCE: &[u8] = b"ordinary bucket source";

async fn fixture(service: &S3Service) -> Vec<String> {
    create_bucket(service, "destination").await;
    assert_eq!(put(service, DESTINATION, ORIGINAL).await.status(), 200);
    let mut sources = Vec::new();
    for (bucket, arn) in [
        ("source", "arn:aws:s3:us-east-1:123456789012:accesspoint/source/object/key"),
        ("op-1", "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/object/key"),
        (
            "src-bucket",
            "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/bucket/src-bucket/object/key",
        ),
    ] {
        create_bucket(service, bucket).await;
        assert_eq!(
            super::super::multipart_versioning::set_versioning(service, bucket, "Enabled")
                .await
                .status(),
            200
        );
        let uploaded = put(service, &format!("/{bucket}/key"), SOURCE).await;
        assert_eq!(uploaded.status(), 200);
        let version = header(&uploaded, "x-amz-version-id")
            .expect("version")
            .to_str()
            .expect("ASCII version");
        sources.push(arn.to_owned());
        sources.push(format!("{arn}?versionId={version}"));
    }
    sources
}

async fn object_copy(service: &S3Service, source: &str, forged: bool) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-copy-source", http::HeaderValue::from_str(source).expect("source"));
    exchange(
        service,
        signed_as_with_headers(
            "AKIDEXAMPLE",
            if forged { b"wrong" } else { b"secret" },
            http::Method::PUT,
            DESTINATION,
            Bytes::new(),
            headers,
        ),
    )
    .await
}

fn unsupported(response: &WireResponse) {
    assert_eq!(response.status(), 501, "{}", text(response));
    assert_eq!(element(response.body(), "Code").as_deref(), Some("NotImplemented"));
}

#[tokio::test]
async fn n_arn_sources_do_not_copy_objects_from_same_named_buckets() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    for source in fixture(&service).await {
        for prefix in ["", "/"] {
            unsupported(&object_copy(&service, &format!("{prefix}{source}"), false).await);
            assert_eq!(read(&service, DESTINATION).await, ORIGINAL);
        }
    }
}

#[tokio::test]
async fn n_arn_sources_do_not_replace_existing_upload_parts() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let sources = fixture(&service).await;
    let id = initiate(&service, "destination", "kept").await;
    let tag = upload_part(&service, "destination", "kept", &id, 1, ORIGINAL).await;
    for source in sources {
        for prefix in ["", "/"] {
            unsupported(&part_copy(&service, DESTINATION, &id, 1, &format!("{prefix}{source}"), &[]).await);
            assert_eq!(read(&service, DESTINATION).await, ORIGINAL);
            assert_eq!(part_count(&service, DESTINATION, &id).await, 1);
        }
    }
    assert_eq!(complete(&service, "destination", "kept", &id, &[(1, &tag)]).await.status(), 200);
    assert_eq!(read(&service, DESTINATION).await, ORIGINAL);
}

#[tokio::test]
async fn n_missing_arn_buckets_have_the_same_unsupported_refusal() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "destination").await;
    assert_eq!(put(&service, DESTINATION, ORIGINAL).await.status(), 200);
    let id = initiate(&service, "destination", "kept").await;
    for source in [
        "arn:aws:s3:us-east-1:123456789012:accesspoint/missing/object/key",
        "arn:aws:s3-outposts:us-east-1:123456789012:outpost/missing/object/key",
        "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/bucket/missing/object/key",
    ] {
        for prefix in ["", "/"] {
            let source = format!("{prefix}{source}");
            unsupported(&object_copy(&service, &source, false).await);
            unsupported(&part_copy(&service, DESTINATION, &id, 1, &source, &[]).await);
        }
    }
    assert_eq!(read(&service, DESTINATION).await, ORIGINAL);
    assert_eq!(part_count(&service, DESTINATION, &id).await, 0);
}

#[tokio::test]
async fn n_signature_and_source_denial_precede_arn_backend_refusal() {
    let root = TestRoot::new();
    let (backend, allowed) = service(&root);
    let sources = fixture(&allowed).await;
    let id = initiate(&allowed, "destination", "kept").await;
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("credentials")));
    let builder = rustfs_gateway::ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region")))
        .authorizer(allow_when(|request| {
            request.action != "s3:GetObject" && request.action != "s3:GetObjectVersion"
        }))
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        );
    let denied = backend
        .register_multipart(backend.register_crud(builder))
        .build()
        .expect("copy registry");
    for source in sources {
        for prefix in ["", "/"] {
            let source = format!("{prefix}{source}");
            let object = object_copy(&denied, &source, false).await;
            assert_eq!(object.status(), 403);
            assert_eq!(element(object.body(), "Code").as_deref(), Some("AccessDenied"));
            let part = part_copy(&denied, DESTINATION, &id, 1, &source, &[]).await;
            assert_eq!(part.status(), 403);
            assert_eq!(element(part.body(), "Code").as_deref(), Some("AccessDenied"));
            let object = object_copy(&allowed, &source, true).await;
            assert_eq!(object.status(), 403);
            assert_eq!(element(object.body(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
            let mut headers = http::HeaderMap::new();
            headers.insert("x-amz-copy-source", http::HeaderValue::from_str(&source).expect("source"));
            let part = exchange(
                &allowed,
                signed_as_with_headers(
                    "AKIDEXAMPLE",
                    b"wrong",
                    http::Method::PUT,
                    &format!("{DESTINATION}?partNumber=1&uploadId={id}"),
                    Bytes::new(),
                    headers,
                ),
            )
            .await;
            assert_eq!(part.status(), 403);
            assert_eq!(element(part.body(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
        }
    }
    assert_eq!(read(&allowed, DESTINATION).await, ORIGINAL);
    assert_eq!(part_count(&allowed, DESTINATION, &id).await, 0);
}

#[tokio::test]
async fn plain_sources_still_copy_objects_and_parts() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    fixture(&service).await;
    assert_eq!(object_copy(&service, "/source/key", false).await.status(), 200);
    assert_eq!(read(&service, DESTINATION).await, SOURCE);
    let id = initiate(&service, "destination", "kept").await;
    let tag = copied_etag(&part_copy(&service, DESTINATION, &id, 1, "/source/key", &[]).await);
    assert_eq!(complete(&service, "destination", "kept", &id, &[(1, &tag)]).await.status(), 200);
    assert_eq!(read(&service, DESTINATION).await, SOURCE);
}
