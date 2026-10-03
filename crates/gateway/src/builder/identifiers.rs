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

//! The RustFS-profile switch that identifies every answer as legacy RustFS does (rustfs/backlog#1677,
//! ruling R10).
//!
//! Responsible for: [`ServiceBuilder::identify_requests_as_legacy_rustfs`].
//! NOT responsible for: what legacy RustFS answers with and why (`crate::trace`'s `answer` module
//! says, with its evidence), taking the host's identifier over (`crate::trace::HostRequestId`), or
//! writing anything (`crate::trace::RequestTrace`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.

use super::ServiceBuilder;
use crate::trace::Identification;

impl ServiceBuilder {
    /// Identifies every answer as legacy RustFS does, with the one addition ruling R10 of
    /// rustfs/backlog#1677 makes: an error document names the request its head names.
    ///
    /// An S3 answer carries the request identifier in `x-amz-request-id` and in `x-request-id`, and
    /// no `x-amz-id-2`; an error document names the same request in `<RequestId>` and carries no
    /// `<HostId>`; an answer on a path a dialect claims (RustFS's admin router's paths) carries no
    /// identifier of this service, and the host writes its own there. Pair it with a
    /// [`crate::HostRequestId`] on every request, so the identifier is RustFS's own, or, for an
    /// assembly with no host in front of it, with [`crate::MintedTraces::with_uuid_request_ids`], so
    /// it has RustFS's shape.
    ///
    /// Off by default: every other assembly answers as AWS does, with both identifiers in the head
    /// and in an error document. The events the service emits carry the same request identifier
    /// either way.
    #[must_use]
    pub fn identify_requests_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.identification = Identification::LegacyRustfs;
        self
    }
}
