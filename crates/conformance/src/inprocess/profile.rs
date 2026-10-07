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
//! Responsible for: selecting the naming and deadline policies the measured service actually runs.
//! NOT responsible for: profile gating, report labels, or enforcing those policies. Upstream:
//! `crate::runner`. Downstream: `super::InProcess::assemble`.

use std::time::Duration;

use rustfs_gateway::{
    DEFAULT_MAX_BUFFERED_BODY_BYTES, HandlerDeadlineConfig, NamePolicy, RequestBodyDeadlineConfig, ServiceConfig, SlashPolicy,
};

use crate::sut::{Profile, SutError};

/// The naming policy the bundled assembly runs for a claimed profile.
///
/// # Errors
///
/// Returns [`SutError::Environment`] for `rustfs`: the bundled reference assembly does not run the
/// RustFS preset, and a service that claimed the profile without running it would report an
/// intention as an observation. The profile is measured on an external candidate (`--endpoint`).
pub(super) fn name_policy(profile: Profile) -> Result<NamePolicy, SutError> {
    match profile {
        Profile::Minio => Ok(NamePolicy::default().with_slash_policy(SlashPolicy::Collapse)),
        Profile::Aws | Profile::Strict => Ok(NamePolicy::default()),
        Profile::Rustfs => Err(SutError::Environment(
            "the `rustfs` profile names an external RustFS candidate (`--endpoint`); the bundled \
             reference assembly does not run the RustFS preset and cannot claim it"
                .to_owned(),
        )),
    }
}

pub(super) fn service_config(handler_deadlines: HandlerDeadlineConfig) -> Result<ServiceConfig, SutError> {
    let request_body_deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(2), Duration::from_secs(1))
        .ok_or_else(|| SutError::Environment("the conformance body deadlines must be non-zero".to_owned()))?;
    Ok(ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES)
        .with_handler_deadlines(handler_deadlines)
        .with_request_body_deadlines(request_body_deadlines))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive — the named vendor profile selects its observable slash semantics.
    #[test]
    fn minio_selects_the_collapse_policy() {
        assert_eq!(name_policy(Profile::Minio).expect("assembled").slash_policy(), SlashPolicy::Collapse);
    }

    /// Negative — the default profile must not inherit a vendor compatibility rewrite.
    #[test]
    fn aws_does_not_collapse_object_keys() {
        assert_eq!(name_policy(Profile::Aws).expect("assembled").slash_policy(), SlashPolicy::AwsPreserve);
    }

    /// Negative — strict is an explicit divergence selector, not an alias for one vendor.
    #[test]
    fn strict_does_not_silently_select_the_minio_rewrite() {
        assert_eq!(name_policy(Profile::Strict).expect("assembled").slash_policy(), SlashPolicy::AwsPreserve);
    }

    /// Negative — the bundled assembly does not run the RustFS preset, so it must not claim the
    /// profile: a `rustfs` run over it would report a profile the target never had.
    #[test]
    fn rustfs_is_refused_by_the_bundled_assembly() {
        let error = name_policy(Profile::Rustfs).expect_err("not this target");
        assert!(matches!(error, SutError::Environment(_)), "{error:?}");
        assert!(error.to_string().contains("--endpoint"), "{error}");
    }
}
