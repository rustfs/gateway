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

//! Compile-time proof that an authorisation requirement's rule cannot be rewritten (ADR-0025).
//!
//! Responsible for: showing a declared requirement cannot have its action rule or subject rule
//! replaced after construction, so an any-of rule cannot be quietly widened and an own-account
//! rule cannot be dropped: only the constructors set them, and registration checks what they set.
//! NOT responsible for: the registration refusals, which the dialect refusal tests hold.
//! Upstream: `rustfs_gateway_core::AuthRequirement`. Downstream: the trybuild harness.

use rustfs_gateway_core::{ActionRule, AuthRequirement, ResourceShape};

fn main() {
    let mut requirement = AuthRequirement::new("admin:A", ResourceShape::Service);
    requirement.rule = ActionRule::AnyOf(&["admin:A", "admin:B"]);
    requirement.subject = None;
}
