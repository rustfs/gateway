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

//! Fuzzes equivalence between the readable generated route table and compiled router.
//!
//! Responsible for: the libFuzzer entry point for compiled/readable route equivalence.
//! NOT responsible for: request generation or route-lattice disjointness.
//! Upstream: libFuzzer bytes and shared route support. Downstream: nothing — it asserts.

#![no_main]

#[path = "../support/route.rs"]
mod route;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| route::check_compiled_equiv(input));
