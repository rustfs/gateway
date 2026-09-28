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

//! The `LocationConstraint` of a `CreateBucket` as the RustFS-profile launcher serves it
//! (rustfs/gateway#914).
//!
//! Responsible for: any constraint — minio-java's explicit `us-east-1`, another region, an unknown
//! name — creating the bucket, as RustFS creates it, in the launcher's own region; and a body that
//! is not a `CreateBucketConfiguration` still being refused.
//! NOT responsible for: the AWS default, which the conformance corpus and
//! `rustfs-gateway-fs`'s `bucket_location` tests pin, or the posture's unit rules
//! (`rustfs_gateway_core::ops::shared::location_constraint`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

/// What minio-java 9.0.3 `makeBucket` sends, with or without a region configured on the client.
fn configuration(constraint: &str) -> Bytes {
    Bytes::from(format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <LocationConstraint>{constraint}</LocationConstraint></CreateBucketConfiguration>"
    ))
}

/// Positive — the minio-java body creates the bucket, which then exists.
#[tokio::test]
async fn an_explicit_us_east_1_constraint_creates_the_bucket() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));

    let created = exchange(&service, as_main(http::Method::PUT, "/m-mj", configuration("us-east-1"))).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let head = exchange(&service, as_main(http::Method::HEAD, "/m-mj", Bytes::new())).await;
    assert_eq!(head.status(), 200);
}

/// Negative — a constraint RustFS ignores does not move the bucket: `eu-west-1`, a case variant
/// and an unknown name all create it, and it is still reported in the launcher's own region.
#[tokio::test]
async fn n_another_constraint_is_ignored_rather_than_honoured() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));

    for (bucket, constraint) in [("/m-eu", "eu-west-1"), ("/m-upper", "US-EAST-1"), ("/m-mars", "mars-north-1")] {
        let created = exchange(&service, as_main(http::Method::PUT, bucket, configuration(constraint))).await;
        assert_eq!(created.status(), 200, "{constraint}: {}", body_of(&created));
        let head = exchange(&service, as_main(http::Method::HEAD, bucket, Bytes::new())).await;
        assert_eq!(head.status(), 200, "{constraint}");
        assert_eq!(
            head.headers()
                .iter()
                .find(|(name, _)| name.as_str() == "x-amz-bucket-region")
                .and_then(|(_, value)| value.to_str().ok()),
            Some("us-east-1"),
            "{constraint}: the ignored constraint moved the bucket"
        );
    }
}

/// Negative — ignoring the constraint is not ignoring the body: a document that is not XML is
/// still refused, and leaves no bucket.
#[tokio::test]
async fn n_a_malformed_configuration_is_still_refused() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));

    let refused = exchange(
        &service,
        as_main(
            http::Method::PUT,
            "/m-malformed",
            Bytes::from_static(b"<CreateBucketConfiguration><Location"),
        ),
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    let head = exchange(&service, as_main(http::Method::HEAD, "/m-malformed", Bytes::new())).await;
    assert_eq!(head.status(), 404, "the refused creation left a bucket behind");
}
