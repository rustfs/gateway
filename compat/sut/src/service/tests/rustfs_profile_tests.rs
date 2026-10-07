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

//! The served assembly's posture is the RustFS profile's golden (rustfs/backlog#2751).
//!
//! Responsible for: that `super::build_service` — the one assembly the suites are pointed at —
//! reports, byte for byte, the posture the gateway pins for `ServiceBuilder::rustfs_profile` over
//! this same backend (`crates/gateway/tests/golden/rustfs-profile-posture.txt`): every start-up
//! line, then the security posture. A switch the launcher chained that the preset does not, or
//! the reverse, is a diff here.
//! NOT responsible for: what each switch does (the topic files beside this one), or the golden's
//! own control against the default assembly (`crates/gateway/tests/rustfs_profile.rs`).
//! Upstream: `super::build_service`. Downstream: nothing.

use super::*;

/// The golden the gateway renders from `ServiceBuilder::rustfs_profile` plus the reference backend.
const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/gateway/tests/golden/rustfs-profile-posture.txt"
);

/// The served assembly reports exactly the golden posture: the launcher runs the profile, whole.
#[test]
fn the_served_assembly_reports_the_rustfs_profiles_golden_posture() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let rendered = format!("{}{}\n", service.startup_posture(), service.security_posture());
    let golden = std::fs::read_to_string(GOLDEN).expect("the gateway's posture golden exists");
    assert_eq!(
        rendered, golden,
        "the served assembly's posture is not the RustFS profile's golden; one of the two moved without the other"
    );
}
