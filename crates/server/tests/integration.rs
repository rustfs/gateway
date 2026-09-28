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

//! Consolidated integration-test entry point for `server`.
//!
//! Responsible for: registering every `server` integration-test source in one Cargo target.
//! NOT responsible for: test behavior or repository automation implementation.
//! Upstream: the `server` integration-test modules. Downstream: Cargo's test harness.

#[path = "acceptance.rs"]
mod acceptance;
#[path = "guards.rs"]
mod guards;
#[path = "lingering_close.rs"]
mod lingering_close;
#[path = "server_load.rs"]
mod server_load;
#[path = "server_runtime.rs"]
mod server_runtime;
#[path = "tls_alpn.rs"]
mod tls_alpn;
#[path = "tls_h2.rs"]
mod tls_h2;
