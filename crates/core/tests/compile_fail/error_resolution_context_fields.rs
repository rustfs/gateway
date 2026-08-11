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

//! Compile-fail boundary for error context fields.
//!
//! Responsible for: proving downstream code cannot open a context selected by a named constructor.
//! NOT responsible for: choosing the named context.
//! Upstream: `rustfs_gateway_core::ErrorContext`. Downstream: external error producers.

use rustfs_gateway_core::{ErrorContext, MissingObject, ResourceVisibility};

fn main() {
    let context = ErrorContext::missing_object(MissingObject::Key, ResourceVisibility::Visible);
    let ErrorContext(_case) = context;
}
