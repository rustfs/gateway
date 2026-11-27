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

//! Fuzzes `rustfs-gateway-http` RFC 2047 user-metadata codecs and `QueryIndex`/`QueryView`.
//!
//! Responsible for: the libFuzzer entry point for the `http_metadata_query` property.
//! NOT responsible for: the property invariants themselves (`fuzz/support/http_metadata_query.rs`)
//! or full `WireRequest::accept` header acceptance (`header_accept.rs`).
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-http`, through
//! `fuzz/support/http_metadata_query.rs`.

#![no_main]

#[path = "../support/http_metadata_query.rs"]
mod http_metadata_query;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    http_metadata_query::check(input);
});
