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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

use rustfs_gateway_core::{AuthRequirement, OperationSpec, ResourceShape};
use rustfs_gateway_sig::{OperationFloor, SigService};

pub static SPEC: OperationSpec = OperationSpec {
    name: "example:Probe",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:Probe", ResourceShape::Service)),
};

pub static FLOOR: OperationFloor = OperationFloor::builtin("example:Probe", SigService::S3);
