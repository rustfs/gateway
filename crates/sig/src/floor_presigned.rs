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

//! Presigned admission on every standard operation: the service-level half of H3's presigned slot
//! (rustfs/backlog#1677, ruling R7; rustfs/gateway#1052).
//!
//! Responsible for: [`SecurityFloor::admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report`],
//! [`SecurityFloor::presigned_policy`], and [`SecurityFloor::admits_presigned`] — the one predicate
//! that both the floor's allow-list check and the startup posture report read.
//! NOT responsible for: the per-operation opt-in ([`crate::OperationFloor::allow_presigned`]),
//! verifying a presigned URL (its clock, lifetime, scope and signature rules are the same whoever
//! admitted it), whether SigV2 presigned URLs are accepted at all ([`crate::SigV2Policy`]), or
//! authorization, which stays the `Authorizer`'s.
//! Upstream: [`crate::operation`]. Downstream: `SecurityFloor::enforce_scheme_allowed`, and the
//! gateway's startup posture report.

use super::SecurityFloor;
use crate::operation::{OperationFloor, PresignedPolicy};

impl SecurityFloor {
    /// Admits a presigned URL to every non-privileged operation, as legacy RustFS does.
    ///
    /// Legacy RustFS verifies a presigned URL on any request before it routes it, and then
    /// authorizes the verified credential as it authorizes a header signature, so a presigned
    /// DeleteObject, HeadObject, ListObjectsV2 or UploadPart it serves today is refused by a floor
    /// that admits presigned URLs per operation (rustfs/gateway#1052). The name is long because the
    /// obligations are real: every such operation now appears in the startup posture report as
    /// presigned-reachable, and the installed authorizer decides a presigned request as strictly as
    /// a header-signed one.
    ///
    /// It widens the presigned slot only:
    ///
    /// * A privileged operation still refuses every presigned URL, and cannot be made to accept
    ///   one. Every third-party operation is privileged by default.
    /// * A SigV2 presigned URL is still refused unless the [`crate::SigV2Policy`] admits them.
    /// * Every rule of the presigned path still runs: the duplicate-parameter check, the clock,
    ///   the seven-day lifetime ceiling, the scope cross-check and the signature.
    #[must_use]
    pub const fn admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report(mut self) -> Self {
        self.presigned = PresignedPolicy::EveryStandardOperation;
        self
    }

    /// Which operations admit a presigned URL. It is [`PresignedPolicy::PerOperation`] unless a
    /// deployment widened it.
    #[must_use]
    pub const fn presigned_policy(&self) -> PresignedPolicy {
        self.presigned
    }

    /// Whether this floor admits a presigned URL to `operation`.
    ///
    /// This is the one answer. H3's presigned slot and the startup posture report both read it,
    /// so the report cannot list an operation the floor refuses, or miss one the floor admits.
    #[must_use]
    pub const fn admits_presigned(&self, operation: &OperationFloor) -> bool {
        operation.admits_presigned_under(self.presigned)
    }
}
