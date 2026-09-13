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

//! Fuzzes request acceptance with arbitrary header fields and header ceilings.
//!
//! Responsible for: the libFuzzer entry point for the `header_accept` property.
//! NOT responsible for: the property itself, or the fixed-seed replay that runs it on stable.
//! Upstream: libFuzzer bytes; seed it from `fuzz/seeds/header_accept/`, listed after a writable
//! corpus directory so new inputs never land among the committed seeds:
//! `cargo +nightly fuzz run header_accept fuzz/corpus/header_accept fuzz/seeds/header_accept`.
//! Downstream: `rustfs-gateway-http::WireRequest::accept`, through `fuzz/support/header_accept.rs`.

#![no_main]

#[path = "../support/header_accept.rs"]
mod header_accept;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = header_accept::check(input);
});
