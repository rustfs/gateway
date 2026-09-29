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

//! Fuzzes POST Object forms through the form reader, under both grammars, and the POST policy
//! parsers behind it.
//!
//! Responsible for: the libFuzzer entry point for the `post_form` property.
//! NOT responsible for: the property itself, or the fixed-seed replay that runs it on stable.
//! Upstream: libFuzzer bytes; seed it from `fuzz/seeds/post_form/`, listed after a writable corpus
//! directory so new inputs never land among the committed seeds:
//! `cargo +nightly fuzz run post_form fuzz/corpus/post_form fuzz/seeds/post_form`.
//! Downstream: `rustfs-gateway-http`'s `FormReader` and `FileReader`, and
//! `rustfs-gateway-sig`'s `PostPolicy` and `SigV2PostPolicy`, through `fuzz/support/post_form.rs`.

#![no_main]

#[path = "../support/post_form.rs"]
mod post_form;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = post_form::check(input);
});
