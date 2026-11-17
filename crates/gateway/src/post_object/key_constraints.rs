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

//! Key conditions taken from the resolved POST form.
//!
//! Responsible for: matching the resolved policy to the authenticated signature family.
//! NOT responsible for: verification, body completion or derived-write authorization.
//! Upstream: the resolved form. Downstream: the gateway request context.

use http_body::Body;
use rustfs_gateway_sig::{SigFamily, post_policy::PostKeyConstraints};

use super::{AcceptedPolicy, ResolvedPostObject};

impl<B: Body> ResolvedPostObject<B> {
    pub(crate) fn key_constraints(&self, family: SigFamily) -> Option<&PostKeyConstraints> {
        match (&self.policy, family) {
            (AcceptedPolicy::SigV4(policy), SigFamily::V4) => Some(policy.key_constraints()),
            (AcceptedPolicy::SigV2(policy), SigFamily::V2) => Some(policy.key_constraints()),
            _ => None,
        }
    }
}
