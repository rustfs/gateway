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

//! Authorization actions lowered from the protocol overlays.
//!
//! Responsible for: distinguishing version-list permission from ordinary-list permission.
//! NOT responsible for: policy evaluation or request dispatch.
//! Upstream: the pinned model and operation overlays. Downstream: generated operation contracts.

use super::codegen_tests::artifacts;

#[test]
fn list_versions_overlay_keeps_its_distinct_authorization_action() {
    let generated = artifacts();
    for (name, expected) in [
        ("ListObjectVersions", "s3:ListBucketVersions"),
        ("ListObjects", "s3:ListBucket"),
        ("ListObjectsV2", "s3:ListBucket"),
    ] {
        let operation = generated
            .operations
            .iter()
            .find(|operation| operation.operation == name)
            .expect("the listing is generated");
        assert_eq!(operation.auth.action, expected, "{name}");
    }
}
