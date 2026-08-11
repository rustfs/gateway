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

//! Compile-time serialization boundary for signature secrets.
//!
//! Responsible for: executing c-sig-0018 against the real serde implementation used by a sig
//! consumer. NOT responsible for: the signature crate's other compile-time boundaries.
//! Upstream: `rustfs_gateway_sig::SessionToken`. Downstream: serialization callers.

#[test]
fn session_tokens_are_not_serializable() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/c_sig_0018_*.rs");
}
