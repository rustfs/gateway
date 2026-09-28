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

//! Fuzzes restore header grammar through the stable replay property.
//! Responsible for: the libFuzzer entry.
//! NOT responsible for: HTTP I/O or archive state changes.
//! Upstream: libFuzzer bytes. Downstream: fuzz/support/restore_header.rs.
//! Seed a writable corpus from `fuzz/seeds/restore_header`:
//! `cargo +nightly fuzz run restore_header fuzz/corpus/restore_header fuzz/seeds/restore_header`.
#![no_main]
#[path = "../support/restore_header.rs"]
mod property;
libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let _ = property::check(input);
});
