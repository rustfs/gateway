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

//! Compile-time error-resolution boundary coverage.
//!
//! Responsible for: proving the legal handler-context wrapper cannot enclose an authorization context.
//! NOT responsible for: constructing a legal named handler context.
//! Upstream: `rustfs_gateway_core::HandlerErrorContext`. Downstream: external stage filters and handlers.

use rustfs_gateway_core::{ErrorContext, HandlerErrorContext};

fn main() {
    let context = ErrorContext::authorization_scope_malformed();
    let _wrapped = HandlerErrorContext(context);
}
