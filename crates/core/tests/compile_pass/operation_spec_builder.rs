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

//! Downstream const construction through the `OperationSpec` builder.
//!
//! Responsible for: compiling the supported additive construction path. NOT responsible for:
//! registry validation. Upstream: the public builder. Downstream: the trybuild SemVer test.

use rustfs_gateway_core::{AuthRequirement, HandlerDeadlineClass, OperationSpec, ResourceShape};

static SPEC: OperationSpec = OperationSpec::builder("extension:Ping", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .auth(AuthRequirement::new("extension:Ping", ResourceShape::Object))
    .build();

fn main() {
    assert_eq!(SPEC.name, "extension:Ping");
}
