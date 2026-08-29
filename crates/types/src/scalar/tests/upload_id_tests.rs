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

//! The owned upload-id claim and the ownership exchange that authorizes its use.
//!
//! Responsible for: proving the claim outlives the decoded query buffer and still requires a
//! bucket-and-key ownership exchange before its bytes become readable.
//! NOT responsible for: generated DTO field selection or query decoding.
//! Upstream: the upload-id scalar. Downstream: nothing.

use crate::{BucketName, ObjectKey, RecordedUpload, UploadIdClaim, WirePlaceholder, resolve_upload};

struct Recorded {
    bucket: &'static str,
    key: &'static str,
}

impl RecordedUpload for Recorded {
    fn bucket(&self) -> &str {
        self.bucket
    }

    fn key(&self) -> &str {
        self.key
    }
}

fn bucket() -> BucketName {
    BucketName::new("example-bucket").expect("the test bucket is valid")
}

fn key() -> ObjectKey {
    ObjectKey::new("object-key").expect("the test key is valid")
}

#[test]
fn an_owned_claim_survives_the_decoded_query_buffer() {
    let claim = {
        let decoded = String::from("upload-0001");
        UploadIdClaim::from_wire(decoded)
    };
    let (resolved, _) = resolve_upload(&claim, &bucket(), &key(), |_| {
        Some(Recorded {
            bucket: "example-bucket",
            key: "object-key",
        })
    })
    .expect("the recorded owner matches the request");

    assert_eq!(resolved.id(), "upload-0001");
}

#[test]
fn n_a_claim_is_not_authority_without_the_matching_owner() {
    let claim = UploadIdClaim::from_wire("upload-0001");
    let outcome = resolve_upload(&claim, &bucket(), &key(), |_| {
        Some(Recorded {
            bucket: "another-bucket",
            key: "object-key",
        })
    });

    assert!(outcome.is_err());
}

#[test]
fn n_the_default_claim_is_a_wire_placeholder() {
    assert!(UploadIdClaim::default().is_wire_placeholder());
}
