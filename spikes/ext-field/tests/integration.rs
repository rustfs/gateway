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

//! Consolidated integration-test entry point for `ext-field`.
//!
//! Responsible for: registering every `ext-field` integration-test source in one Cargo target.
//! NOT responsible for: test behavior or repository automation implementation.
//! Upstream: the `ext-field` integration-test modules. Downstream: Cargo's test harness.

#[path = "roundtrip.rs"]
mod roundtrip;
#[path = "security.rs"]
mod security;
#[path = "unknown_elements.rs"]
mod unknown_elements;
