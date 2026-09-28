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

//! Fuzzes the gateway/s3s encode differential (rustfs/backlog#1762) with answers built from bytes.
//!
//! Responsible for: the libFuzzer entry point for the `encode_diff` property: a listing or head
//! answer whose keys, prefixes, tokens, metadata or content headers come from fuzz bytes, written
//! differently by the gateway and the pinned s3s with no register entry accepting it, is a crash.
//! NOT responsible for: the property (`rustfs_gateway_difftest::fuzz::check_encode`), or the stable
//! replay (`crates/difftest/src/tests/fuzz.rs`).
//! Upstream: libFuzzer bytes: `cargo +nightly fuzz run encode_diff fuzz/corpus/encode_diff`.
//! Downstream: `rustfs_gateway_difftest::fuzz`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Err(report) = rustfs_gateway_difftest::fuzz::check_encode(input) {
        panic!("{report}");
    }
});
