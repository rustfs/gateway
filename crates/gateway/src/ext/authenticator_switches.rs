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

//! The opt-in switches of the built-in SigV4 authenticator: handing the caller's secret to
//! handlers (ADR-0022), verifying any signing region (ADR-0023), and verifying an empty signing
//! region (rustfs/backlog#1677). All are off by default.
//!
//! Responsible for: the three builder methods, their documented posture, and [`RegionPolicy`],
//! which turns the two region switches into the scope expectation.
//! NOT responsible for: verification itself, or what a switch changes in it; they are read in
//! `super::authenticator` (and the secret hand-off also in `super::sigv2`).
//! Upstream: `super::authenticator::SigV4Authenticator`. Downstream: deployments assembling the
//! service, the RustFS ring-2 adapter first.

use super::authenticator::SigV4Authenticator;
use rustfs_gateway_sig::{EmptyRegion, ExpectedScope};

/// The two opt-in scope-region policies of [`SigV4Authenticator`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RegionPolicy {
    /// ADR-0023: any region in the configured-name grammar.
    pub(super) any_region: bool,
    /// The empty region, which legacy RustFS reads as no region.
    pub(super) empty_region: bool,
}

impl RegionPolicy {
    /// How the credential parsers read an empty region field: admitted only when the scope check
    /// admits it too, so a parse that succeeds is never refused by name for its region shape alone.
    pub(super) const fn empty_region(self) -> EmptyRegion {
        if self.empty_region {
            EmptyRegion::Admitted
        } else {
            EmptyRegion::Refused
        }
    }

    /// `expected`, widened by exactly the policies this authenticator turned on.
    pub(super) const fn apply(self, expected: ExpectedScope<'_>) -> ExpectedScope<'_> {
        let expected = if self.any_region {
            expected.accepting_any_region()
        } else {
            expected
        };
        if self.empty_region {
            expected.accepting_empty_region()
        } else {
            expected
        }
    }
}

impl SigV4Authenticator {
    /// Verifies a SigV4 signature whose credential scope names any region in the configured-name
    /// grammar, not only one this deployment serves: the RustFS profile of rd-loc-0004
    /// (ADR-0023). RustFS verifies every scope region today, and its clients sign with
    /// `us-east-1` or an operator's label whatever the server is set to.
    ///
    /// Off by default, and meant only for a single-endpoint deployment with no per-region
    /// credentials. It changes no key material and no comparison: the key is derived from the
    /// region the client named, and the date and service are still enforced. What it gives up is
    /// the AWS answer that tells a misconfigured client which region to use.
    #[must_use]
    pub fn accept_any_signing_region(mut self) -> Self {
        self.region_policy.any_region = true;
        self
    }

    /// Verifies a SigV4 signature whose credential scope names an empty region
    /// (`AKID/20260929//s3/aws4_request`): the RustFS profile of the empty region
    /// (rustfs/backlog#1677, ruling R2).
    ///
    /// Legacy RustFS verifies such a signature and then reads the empty region as no region, and
    /// its own replication client signs with one: a bucket target's region, empty unless the
    /// operator set one, is the signing region of the remote client
    /// (rustfs/rustfs@1e7065101d `crates/ecstore/src/bucket/bucket_target_sys.rs:112`,
    /// `crates/ecstore/src/bucket/remote_s3_client.rs:299`). A RustFS deployment that refused it
    /// could not replicate to itself. It is separate from
    /// [`accept_any_signing_region`](Self::accept_any_signing_region) because the empty region is
    /// not a region name, and ADR-0023's grammar deliberately excludes it; the RustFS profile turns
    /// both on.
    ///
    /// Off by default: the default refuses an empty region as a region mismatch,
    /// `400 AuthorizationHeaderMalformed` naming the region to use. Like the any-region switch it
    /// changes no key material and no comparison: the key is derived from the empty region the
    /// client signed with, and the date and service are still enforced.
    #[must_use]
    pub fn accept_empty_signing_region(mut self) -> Self {
        self.region_policy.empty_region = true;
        self
    }

    /// Hands the secret this authenticator's own credential lookup returned for an authenticated
    /// principal to the handler, as `RequestPrincipal::secret_key_from_authenticator_lookup`
    /// (ADR-0022).
    ///
    /// Off by default, and meant for a backend that genuinely needs the secret: one that decrypts
    /// a payload the client encrypted with it, or an adapter filling s3s's
    /// `Credentials::secret_key`. The secret travels only after the signature matched and the
    /// credential was admitted; a rejected or anonymous request never carries one, and no lookup
    /// happens that verification did not already make.
    ///
    /// Which handlers receive it is the assembly's decision (ADR-0024): by default only the
    /// operations whose spec calls `OperationSpec::hand_caller_secret_to_handler`, and every one
    /// only after `ServiceBuilder::hand_caller_secret_to_every_operation_after_listing_in_the_posture_report`.
    #[must_use]
    pub fn hand_caller_secret_to_handlers(mut self) -> Self {
        self.hand_secret = true;
        self
    }
}
