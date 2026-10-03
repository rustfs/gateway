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

//! The RustFS profile's version actions: which operations legacy RustFS asks its unversioned
//! action for a request that names one object version.
//!
//! Responsible for: [`ServiceBuilder::authorize_versions_as_legacy_rustfs`],
//! [`LEGACY_UNVERSIONED_OPERATIONS`], and [`VersionActions`], the choice the route stage reads.
//! NOT responsible for: which version action an operation declares
//! ([`rustfs_gateway_core::AuthRequirement::with_version_requirement`], in each op spec) or
//! asking it (`crate::service`'s route and input stages).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through `super::view_policy`.
//!
//! # What legacy RustFS asks
//!
//! Legacy RustFS asks `s3:GetObjectVersion` for a `GetObject`, `GetObjectAttributes` or copy
//! source naming a version, and `s3:DeleteObjectVersion` for a `DeleteObject` naming one
//! (`rustfs/src/storage/access.rs:1029-1056`, `:2213`, `:2423`, `:2705-2707`, `:2733-2735` on
//! rustfs/rustfs `d60dfbb826`), exactly as AWS does, so those need no switch. For a `HeadObject`
//! and the five object tag and ACL operations it asks the unversioned action whatever version the
//! request names (`:2839`, `:2787`, `:3260`, `:2466`, `:2721`, `:3202`), where AWS asks the
//! version action. The switch keeps those six as legacy RustFS asks them.

use super::ServiceBuilder;

/// The operations legacy RustFS authorises with their unversioned action even for a request that
/// names a version, and no others.
pub const LEGACY_UNVERSIONED_OPERATIONS: [&str; 6] = [
    "DeleteObjectTagging",
    "GetObjectAcl",
    "GetObjectTagging",
    "HeadObject",
    "PutObjectAcl",
    "PutObjectTagging",
];

/// Which action a request naming one object version is asked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum VersionActions {
    /// Every operation's declared version action: AWS's rule, and the default.
    #[default]
    Declared,
    /// The declared version action except on [`LEGACY_UNVERSIONED_OPERATIONS`].
    LegacyRustfs,
}

impl VersionActions {
    /// Whether a request to `operation` that names a version is asked the operation's version
    /// action.
    pub(crate) fn asks_version_action(self, operation: &str) -> bool {
        match self {
            Self::Declared => true,
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS authorises a `HeadObject` and the
            // object tag and ACL operations naming a version with their unversioned action, so a
            // principal allowed only the current object reads and rewrites the tags and ACL of
            // every noncurrent version and reads its metadata. Its own GHSA-3ppv note names these
            // paths as still to follow `GetObject`; the intended behaviour is the declared version
            // action, as AWS asks it.
            Self::LegacyRustfs => !LEGACY_UNVERSIONED_OPERATIONS.contains(&operation),
        }
    }
}

impl ServiceBuilder {
    /// Asks a `HeadObject`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`,
    /// `GetObjectAcl` or `PutObjectAcl` request that names one object version the operation's
    /// unversioned action, as legacy RustFS asks it, for a deployment in front of RustFS.
    ///
    /// Every other operation keeps its declared version action — `s3:GetObjectVersion` for a
    /// `GetObject` naming a version and `s3:DeleteObjectVersion` for a `DeleteObject` naming one,
    /// which legacy RustFS asks too. The question still carries the version the request names.
    ///
    /// Off by default: every operation that declares a version action asks it, as AWS does.
    #[must_use]
    pub fn authorize_versions_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.version_actions = VersionActions::LegacyRustfs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_version_actions_are_asked_by_default() {
        for operation in LEGACY_UNVERSIONED_OPERATIONS.iter().chain(&["GetObject", "DeleteObject"]) {
            assert!(VersionActions::default().asks_version_action(operation), "{operation}");
        }
    }

    /// Negative — the legacy choice waives the version action on its six operations only.
    #[test]
    fn n_the_legacy_choice_waives_exactly_its_six_operations() {
        for operation in LEGACY_UNVERSIONED_OPERATIONS {
            assert!(!VersionActions::LegacyRustfs.asks_version_action(operation), "{operation}");
        }
        for operation in [
            "GetObject",
            "DeleteObject",
            "GetObjectAttributes",
            "GetObjectRetention",
            "CopyObject",
        ] {
            assert!(VersionActions::LegacyRustfs.asks_version_action(operation), "{operation}");
        }
    }
}
