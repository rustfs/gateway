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

//! Consolidated integration-test entry point for `sig`.
//!
//! Responsible for: registering every `sig` integration-test source in one Cargo target.
//! NOT responsible for: test behavior or repository automation implementation.
//! Upstream: the `sig` integration-test modules. Downstream: Cargo's test harness.

#[path = "canonical_request.rs"]
mod canonical_request;
#[path = "compile_fail.rs"]
mod compile_fail;
#[path = "effective_host.rs"]
mod effective_host;
#[path = "frozen_dimensions.rs"]
mod frozen_dimensions;
#[path = "post_form_replay.rs"]
mod post_form_replay;
#[path = "post_object_form.rs"]
mod post_object_form;
#[path = "security_floor.rs"]
mod security_floor;
#[path = "security_floor_fixtures/mod.rs"]
mod security_floor_fixtures;
#[path = "security_floor_schemes.rs"]
mod security_floor_schemes;
#[path = "sig_v2.rs"]
mod sig_v2;
#[path = "sig_v2_admission.rs"]
mod sig_v2_admission;
#[path = "signer_roundtrip.rs"]
mod signer_roundtrip;
#[path = "timing.rs"]
mod timing;
#[path = "verification_proof.rs"]
mod verification_proof;
