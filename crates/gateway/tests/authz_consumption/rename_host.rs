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

//! Synchronous `HostResolver` fixture for `RenameObject` end-to-end authorization tests.
//!
//! Responsible for: classifying `EXPRESS_HOST` as `HostClass::S3Express` and all other hosts as
//! `HostClass::Standard` without async I/O.
//! NOT responsible for: request signing, authorization, or executing `RenameObject` tests.
//! Upstream: `authz_consumption/rename_object.rs`. Downstream: `rustfs_gateway::HostResolver`.

use rustfs_gateway::{Addressing, HostQuery, HostResolver, ResolvedHost, TargetKind};
use rustfs_gateway_core::HostClass;

pub(super) const EXPRESS_HOST: &str = "express.example.com";
pub(super) const STANDARD_HOST: &str = "s3.example.com";

/// Classifies `express.example.com` as `HostClass::S3Express` and every other host as
/// `HostClass::Standard`, using path-style addressing so one service exercises both classes.
pub(super) struct ExpressAwareHosts;

impl HostResolver for ExpressAwareHosts {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        let host_class = if query.host.raw_for_signing().as_str() == EXPRESS_HOST {
            HostClass::S3Express
        } else {
            HostClass::Standard
        };
        let trimmed = query.path.trim_start_matches('/');
        let target = if trimmed.is_empty() {
            TargetKind::Service
        } else if trimmed.contains('/') {
            TargetKind::Object
        } else {
            TargetKind::Bucket
        };
        ResolvedHost {
            target,
            host_class,
            arn_form: None,
            addressing: Addressing::Path,
            diagnostic: None,
        }
    }
}
