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

//! Fuzzes virtual-host resolution with arbitrary `Host` bytes, methods and paths.
//!
//! Responsible for: the libFuzzer entry point for the `host_resolve` property.
//! NOT responsible for: the property itself, or the fixed-seed replay that runs it on stable.
//! Upstream: libFuzzer bytes; seed it from `fuzz/seeds/host_resolve/`, listed after a writable
//! corpus directory so new inputs never land among the committed seeds:
//! `cargo +nightly fuzz run host_resolve fuzz/corpus/host_resolve fuzz/seeds/host_resolve`.
//! Downstream: `rustfs_gateway::VirtualHostStyle` and `MetaView`, through
//! `fuzz/support/host_resolve.rs`.

#![no_main]

#[path = "../support/host_resolve.rs"]
mod host_resolve;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = host_resolve::check(input);
});
