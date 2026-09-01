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

//! Maps the runner's claimed compatibility profile onto facade assembly policy.
//!
//! Responsible for: selecting the naming policy the measured service actually runs.
//! NOT responsible for: profile gating, report labels, or the naming rules themselves. Upstream:
//! `crate::runner`. Downstream: `super::InProcess::assemble` and both production transports.

use rustfs_gateway::{NamePolicy, SlashPolicy};

use crate::sut::Profile;

pub(super) fn name_policy(profile: Profile) -> NamePolicy {
    match profile {
        Profile::Minio => NamePolicy::default().with_slash_policy(SlashPolicy::Collapse),
        Profile::Aws | Profile::Strict => NamePolicy::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive — the named vendor profile selects its observable slash semantics.
    #[test]
    fn minio_selects_the_collapse_policy() {
        assert_eq!(name_policy(Profile::Minio).slash_policy(), SlashPolicy::Collapse);
    }

    /// Negative — the default profile must not inherit a vendor compatibility rewrite.
    #[test]
    fn aws_does_not_collapse_object_keys() {
        assert_eq!(name_policy(Profile::Aws).slash_policy(), SlashPolicy::AwsPreserve);
    }

    /// Negative — strict is an explicit divergence selector, not an alias for one vendor.
    #[test]
    fn strict_does_not_silently_select_the_minio_rewrite() {
        assert_eq!(name_policy(Profile::Strict).slash_policy(), SlashPolicy::AwsPreserve);
    }
}
