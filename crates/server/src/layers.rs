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

//! General-purpose tower layer attachment points.
//!
//! Responsible for: making the supported panic, request-ID, trace and compression layers
//! reachable without adding deployment policy. NOT responsible for: choosing IDs, spans,
//! compression policy or any storage-specific readiness decision.
//! Upstream: tower-http. Downstream: callers assembling a service before `Server::new`.

pub use tower_http::catch_panic::CatchPanicLayer;
pub use tower_http::compression::CompressionLayer;
pub use tower_http::request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer};
pub use tower_http::trace::TraceLayer;
