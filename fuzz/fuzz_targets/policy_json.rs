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

//! Fuzzes the bucket policy write path with arbitrary request bodies.
//!
//! Responsible for: the libFuzzer entry point for the `policy_json` property.
//! NOT responsible for: the property itself, or the fixed-seed replay that runs it on stable.
//! Upstream: libFuzzer bytes; seed it from `fuzz/seeds/policy_json/`, listed after a writable
//! corpus directory so new inputs never land among the committed seeds:
//! `cargo +nightly fuzz run policy_json fuzz/corpus/policy_json fuzz/seeds/policy_json`.
//! Downstream: the generated `PutBucketPolicy` codec and `validate_policy`, through
//! `fuzz/support/policy_json.rs`.

#![no_main]

#[path = "../support/policy_json.rs"]
mod policy_json;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = policy_json::check(input);
});
