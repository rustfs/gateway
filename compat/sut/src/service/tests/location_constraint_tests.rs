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

//! The explicit us-east-1 `LocationConstraint` as the RustFS-profile launcher serves it
//! (rustfs/gateway#914).
//!
//! Responsible for: minio-java's `makeBucket` body — a `CreateBucketConfiguration` naming
//! `us-east-1` — creating a bucket on the us-east-1 launcher, while every constraint the strict
//! posture refuses for another reason is still refused and leaves no bucket.
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

/// Negative — only the us-east-1 spelling is relaxed: an unserved region, a case variant of the
/// served one, and junk are still `400 InvalidLocationConstraint`, and none leaves a bucket.
#[tokio::test]
async fn n_every_other_constraint_is_still_refused() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));

    for constraint in ["eu-west-1", "US-EAST-1", "mars-north-1"] {
        let refused = exchange(&service, as_main(http::Method::PUT, "/m-refused", configuration(constraint))).await;
        assert_eq!(refused.status(), 400, "{constraint}: {}", body_of(&refused));
        assert!(
            body_of(&refused).contains("<Code>InvalidLocationConstraint</Code>"),
            "{constraint}: {}",
            body_of(&refused)
        );
        let head = exchange(&service, as_main(http::Method::HEAD, "/m-refused", Bytes::new())).await;
        assert_eq!(head.status(), 404, "{constraint}: the refused creation left a bucket behind");
    }
}
