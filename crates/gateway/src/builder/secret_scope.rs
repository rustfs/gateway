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

//! The one assembly switch that widens the caller-secret scope (ADR-0024).
//!
//! Responsible for: [`ServiceBuilder::hand_caller_secret_to_every_operation_after_listing_in_the_posture_report`].
//! NOT responsible for: looking the secret up or attaching it (the authenticator), or dropping it
//! (`crate::service`, on the line that reads the verdict).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, `crate::posture`.

use super::ServiceBuilder;

impl ServiceBuilder {
    /// Hands the caller's secret, when the authenticator attached one, to every operation rather
    /// than only to the operations whose spec opted in (ADR-0024).
    ///
    /// Off by default. By default a secret reaches a handler only when its operation's spec called
    /// `OperationSpec::hand_caller_secret_to_handler`, and is dropped, zeroized, for every other
    /// operation on the line that reads the verdict. This switch restores ADR-0022's every-handler
    /// scope for one caller: an adapter that must fill a credential which always carries a secret
    /// — s3s's `Credentials`, which the migration seam refuses to invent — for handlers that never
    /// read it. The start-up report names it: `DIALECT_POSTURE … caller_secret_scope=every-operation`.
    #[must_use]
    pub fn hand_caller_secret_to_every_operation_after_listing_in_the_posture_report(mut self) -> Self {
        self.caller_secret_every_operation = true;
        self
    }
}
