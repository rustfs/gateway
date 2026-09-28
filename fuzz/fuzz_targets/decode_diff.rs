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

//! Fuzzes the gateway/s3s decode differential (rustfs/backlog#1762) with raw requests.
//!
//! Responsible for: the libFuzzer entry point for the `decode_diff` property: the same request
//! bytes routed to different operations by the gateway and the pinned s3s, with no register entry
//! accepting it, is a crash.
//! NOT responsible for: the property (`rustfs_gateway_difftest::fuzz::check_decode`), the input
//! format (`fuzz::request_of`), or the stable replay (`crates/difftest/src/tests/fuzz.rs`).
//! Upstream: libFuzzer bytes; seed it from `fuzz/seeds/decode_diff/`, listed after a writable corpus
//! directory: `cargo +nightly fuzz run decode_diff fuzz/corpus/decode_diff fuzz/seeds/decode_diff`.
//! A crash becomes a conformance case draft with
//! `cargo run -p rustfs-gateway-difftest --bin fuzz-to-case -- <artifact>`.
//! Downstream: `rustfs_gateway_difftest::fuzz`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Err(report) = rustfs_gateway_difftest::fuzz::check_decode(input) {
        panic!("{report}");
    }
});
