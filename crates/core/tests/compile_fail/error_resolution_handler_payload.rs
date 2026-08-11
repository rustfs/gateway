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

//! Compile-fail boundary for the handler's contextual payload.
//!
//! Responsible for: proving an ordinary handler builder cannot inject the private carrier.
//! NOT responsible for: transporting a context created through the public conversion.
//! Upstream: `rustfs_gateway_core::HandlerError`. Downstream: external handlers.

use rustfs_gateway_core::{HandlerError, HandlerErrorContext as ErrorContext};
use rustfs_gateway_types::ErrorCode;

fn main() {
    let _error = HandlerError {
        code: ErrorCode::NO_SUCH_BUCKET,
        message: "forged".into(),
        headers: Vec::new(),
        details: Vec::new(),
        context: Some(Box::new(ErrorContext::missing_bucket())),
    };
}
