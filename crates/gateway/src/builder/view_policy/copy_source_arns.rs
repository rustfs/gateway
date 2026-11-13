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

//! The facade setting that selects ADR-0045's "copy-source ARNs unsupported" capability
//! (rustfs/gateway#1609).
//!
//! Responsible for: [`ServiceBuilder::refuse_copy_source_arns_as_not_implemented`], which marks the
//! view policy so every routed view carries the core capability.
//! NOT responsible for: which operations classify a Copy source, or the refusal itself — both are
//! `rustfs-gateway-core`'s (`ops/shared/copy_source/capability.rs`, `static_dispatch::decode`) —
//! nor deferring destination policy to the input stage, which ADR-0045 leaves to the adapter's
//! authorizer.
//! Upstream: `super::super::ServiceBuilder`. Downstream: `super::ViewPolicy::apply`.

use crate::builder::ServiceBuilder;

impl ServiceBuilder {
    /// Answers a `CopyObject` or `UploadPartCopy` whose copy source is an access-point or Outposts
    /// ARN with `501 NotImplemented`, as legacy RustFS does, before the source is turned into a
    /// resource and before the authorizer's input stage or the handler sees it (ADR-0045).
    ///
    /// Off by default: the generic assembly supports ARN sources as far as resource validation
    /// does, so an access-point source reaches input authorization and an Outposts spelling is
    /// refused by resource validation. Authentication, route authorization and the codec's own
    /// refusals of an unreadable ARN stay ahead of this one; a plain `bucket/key` source is
    /// unaffected. The RustFS profile turns it on.
    #[must_use]
    pub fn refuse_copy_source_arns_as_not_implemented(mut self) -> Self {
        self.view_policy.copy_source_arns_unsupported = true;
        self
    }
}
