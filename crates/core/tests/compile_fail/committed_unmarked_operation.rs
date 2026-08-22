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

//! An operation without the generated deferred marker cannot commit a response early.
//!
//! Responsible for: pinning the compile-time boundary on `Resp::commit`.
//! NOT responsible for: runtime header validation or response streaming.
//! Upstream: `rustfs_gateway_core::DeferredOperation`. Downstream: backend implementations.

use rustfs_gateway_core::{HeadPart, Resp};
use rustfs_gateway_types::dto::{ListBuckets, ListBucketsOutput};

fn main() {
    let head = HeadPart::<ListBuckets>::new(http::HeaderMap::new()).unwrap();
    let _ = Resp::<ListBuckets>::commit(head, Box::pin(async { Ok(ListBucketsOutput::default()) }));
}
