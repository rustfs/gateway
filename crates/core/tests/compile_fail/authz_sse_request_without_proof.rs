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

//! An SSE-bearing handler request cannot be built without an enforcement proof.
//!
//! Responsible for: proving direct handler tests cannot put customer-key input behind `Req<O>`
//! without supplying the result of the SSE gate.
//! NOT responsible for: transport or header validation at run time.
//! Upstream: the trybuild harness. Downstream: every direct handler invocation.

use rustfs_gateway_core::Req;
use rustfs_gateway_types::dto::{PutObject, PutObjectInput};
use rustfs_gateway_types::SseCustomerKey;

fn main() {
    let input = PutObjectInput {
        sse_customer_key: Some(SseCustomerKey::new("bm90LWEtcmVhbC1rZXk=".to_owned())),
        ..Default::default()
    };
    let _ = Req::<PutObject>::new(input);
}
