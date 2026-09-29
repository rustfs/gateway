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

//! The naming switches: the naming policy, its validator and slash rule, and the RustFS profile's
//! two: the object-key floor (rustfs/gateway#1107), the one builder switch that lowers the key
//! floor, named for what it does, and the path addressing (rustfs/gateway#1115), the one switch
//! that reads a request path as legacy RustFS does.
//!
//! Responsible for: [`ServiceBuilder::name_policy`], [`ServiceBuilder::name_validator`],
//! [`ServiceBuilder::slash_policy`],
//! [`ServiceBuilder::accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report`] and
//! [`ServiceBuilder::address_paths_as_legacy_rustfs`].
//! NOT responsible for: the rules themselves ([`NamePolicy`], [`rustfs_gateway_types::KeyFloor`],
//! the split [`rustfs_gateway_core::codec::legacy_rustfs_target`] and the bucket rules
//! [`LegacyRustfsNameValidator`]), where the pipeline applies the split
//! (`crate::legacy_addressing`), or the start-up line that reports them (`crate::naming_posture`).
//! Upstream: `super::ServiceBuilder`. Downstream: the naming policy every request is addressed and
//! every key is materialised under, the request path's and the request body's alike.

use std::sync::Arc;

use rustfs_gateway_types::{LegacyRustfsNameValidator, NamePolicy, NameValidator, SlashPolicy};

use super::ServiceBuilder;

impl ServiceBuilder {
    /// Installs a naming policy: the slash rule, the key floor and the validator.
    ///
    /// Defaults to [`NamePolicy::default`] — AWS slash semantics and the AWS bucket naming rules.
    /// A validator cannot lower the safety floor; only the policy's key floor can, and the start-up
    /// `NAMING_POSTURE` line reports that floor however it was set (rustfs/gateway#1107).
    #[must_use]
    pub fn name_policy(mut self, names: NamePolicy) -> Self {
        self.names = names;
        self
    }

    /// Installs a name validator, keeping the slash policy already set.
    ///
    /// It may refuse more than the built-in `AwsNameValidator` does, and it cannot refuse less
    /// than the floor: the framework runs the floor first and ANDs the two answers.
    #[must_use]
    pub fn name_validator(mut self, validator: impl NameValidator) -> Self {
        self.names = self.names.with_validator(Arc::new(validator));
        self
    }

    /// Chooses what happens to a run of slashes in an object key.
    ///
    /// **Persistence-affecting.** [`SlashPolicy::Collapse`] makes `a//b` and `a/b` the same object;
    /// switching it on a deployment that has data renames every object whose key held an empty
    /// segment. [`SlashPolicy::rewrites_keys`] is what a start-up posture report reads.
    #[must_use]
    pub fn slash_policy(mut self, slash: SlashPolicy) -> Self {
        self.names = self.names.with_slash_policy(slash);
        self
    }

    /// Replaces the object-key safety floor with legacy RustFS's rule
    /// ([`KeyFloor::RustfsLegacy`](rustfs_gateway_types::KeyFloor::RustfsLegacy)), for a
    /// deployment in front of RustFS only.
    ///
    /// **Lowers a security floor.** Under it a key reaches the backend unless it is empty, longer
    /// than 1024 bytes or holds a NUL: a `..` or `.` segment, a control character, a backslash, a
    /// UNC or drive-letter shape and a literal `%2F` that survived the one decode all do. That is
    /// what legacy RustFS's protocol front hands its storage today, and RustFS's storage layer
    /// then stores or refuses each of them itself, after authorization (rustfs/rustfs `e870a6d25b`
    /// `crates/ecstore/src/bucket/utils.rs` `is_valid_object_prefix` and
    /// `check_object_name_for_length_and_slash`). Only a backend that validates every key it is
    /// handed may be put behind this switch; one that maps a key onto a path without doing so
    /// reopens the traversal the floor exists to close.
    ///
    /// Off by default. The start-up `NAMING_POSTURE` line reports `key_floor=rustfs-legacy` while it
    /// is on, and the deployment's [`NameValidator`](rustfs_gateway_types::NameValidator) still
    /// runs after it and may refuse more.
    #[must_use]
    pub fn accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report(mut self) -> Self {
        self.names = self.names.with_legacy_rustfs_key_floor();
        self
    }

    /// Addresses a request as legacy RustFS does, for a deployment in front of RustFS.
    ///
    /// The path is decoded once as a whole (`400 InvalidURI` when it is not UTF-8) and split at its
    /// first decoded `/`, so `/bkt%2Fkey` is the key `key` in the bucket `bkt`; an empty bucket
    /// segment (`//bkt`) is `400 InvalidBucketName`; the bucket is held to legacy RustFS's naming
    /// rules ([`LegacyRustfsNameValidator`], which replaces any validator installed before this
    /// call); all of it is judged before routing, as legacy RustFS judges it; and a `GET` of exactly
    /// `//` is read as `GET /`, the signature included. A path inside a dialect's claim is left to
    /// the dialect, as legacy RustFS's own routes take theirs first.
    ///
    /// Off by default: the core splits the path as it arrived and refuses an escaped bucket label.
    #[must_use]
    pub fn address_paths_as_legacy_rustfs(mut self) -> Self {
        self.names = self
            .names
            .with_legacy_rustfs_path_split()
            .with_validator(Arc::new(LegacyRustfsNameValidator));
        self
    }
}
