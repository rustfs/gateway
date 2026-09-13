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

//! Anonymous admission delegated to the `Authorizer`: the service-level half of H3's anonymous
//! slot (ADR-0021).
//!
//! Responsible for: [`SecurityFloor::delegate_anonymous_to_authorizer_after_listing_in_the_posture_report`],
//! [`SecurityFloor::anonymous_policy`], and [`SecurityFloor::admits_anonymous`] — the one
//! predicate that both the floor's allow-list check and the startup posture report read.
//! NOT responsible for: the per-operation opt-in ([`crate::OperationFloor`]), deciding whether
//! anything was presented ([`crate::CredentialPresence`]), or authorization, which stays the
//! `Authorizer`'s.
//! Upstream: [`crate::operation`]. Downstream: `SecurityFloor::enforce_scheme_allowed`, and the
//! gateway's startup posture report.

use super::SecurityFloor;
use crate::operation::{AnonymousPolicy, OperationFloor};

impl SecurityFloor {
    /// Admits a request that presented nothing to every non-privileged operation, and leaves the
    /// decision to the `Authorizer`, which every request reaches.
    ///
    /// This is for a deployment whose own access check decides every request, anonymous ones
    /// included: RustFS's bucket policy and ACL evaluation (rustfs/backlog#1752). The name is long
    /// because the obligations are real. Every such operation now appears in the startup posture
    /// report as anonymously reachable, and the installed authorizer must answer `Deny` to every
    /// anonymous request it does not mean to allow.
    ///
    /// It widens the anonymous slot only:
    ///
    /// * A privileged operation still has to opt in itself. Every third-party operation is
    ///   privileged by default.
    /// * Presigned and POST-policy admission still follow each operation's allow-list.
    /// * A request that presented any credential is still verified or refused. It is never
    ///   admitted as anonymous.
    #[must_use]
    pub const fn delegate_anonymous_to_authorizer_after_listing_in_the_posture_report(mut self) -> Self {
        self.anonymous = AnonymousPolicy::DelegateToAuthorizer;
        self
    }

    /// Who decides a request that presented nothing. It is [`AnonymousPolicy::PerOperation`]
    /// unless a deployment delegated.
    #[must_use]
    pub const fn anonymous_policy(&self) -> AnonymousPolicy {
        self.anonymous
    }

    /// Whether this floor admits a request that presented nothing to `operation`.
    ///
    /// This is the one answer. H3's anonymous slot and the startup posture report both read it,
    /// so the report cannot list an operation the floor refuses, or miss one the floor admits.
    #[must_use]
    pub const fn admits_anonymous(&self, operation: &OperationFloor) -> bool {
        operation.admits_anonymous_under(self.anonymous)
    }
}
