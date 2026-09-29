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

//! The startup line that names a presigned-lifetime rule other than the AWS default.
//!
//! Responsible for: rendering `PRESIGNED_EXPIRY_POSTURE rule=<rule>` when the floor reads
//! presigned lifetimes under a non-default [`PresignedExpiryRule`], and writing it to the startup
//! log. The RustFS profile's legacy rule accepts SigV2 links with no seven-day ceiling, which
//! widens the floor, so a deployment running it says so where operators look for what widens it.
//! NOT responsible for: the `SECURITY_POSTURE` line (`crate::posture`), which reads exactly as
//! before for every deployment, or the rule itself (`rustfs-gateway-sig`).
//! Upstream: `crate::builder`, at assembly. Downstream: none.

use rustfs_gateway_sig::{PresignedExpiryRule, SecurityFloor};

/// The line naming `floor`'s presigned-lifetime rule, or `None` for the AWS default, so every
/// deployment that did not opt in logs exactly what it logged before.
pub(crate) fn render_presigned_expiry_posture(floor: &SecurityFloor) -> Option<String> {
    match floor.presigned_expiry_rule() {
        PresignedExpiryRule::Aws => None,
        rule => Some(["PRESIGNED_EXPIRY_POSTURE rule=", rule.as_str()].concat()),
    }
}

/// Writes [`render_presigned_expiry_posture`]'s line, when there is one, to the startup log.
pub(crate) fn log_presigned_expiry_posture(floor: &SecurityFloor) {
    if let Some(line) = render_presigned_expiry_posture(floor) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RustFS profile's legacy reading is named; the AWS default adds no line at all.
    #[test]
    fn the_legacy_rule_is_named_and_the_default_is_silent() {
        let legacy = SecurityFloor::new().with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs);
        assert_eq!(
            render_presigned_expiry_posture(&legacy).as_deref(),
            Some("PRESIGNED_EXPIRY_POSTURE rule=legacy-rustfs")
        );
        assert_eq!(render_presigned_expiry_posture(&SecurityFloor::new()), None);
    }
}
