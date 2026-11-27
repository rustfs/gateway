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

//! Fuzzes S3 Vectors (`s3vectors`) canonical query signing, scope enforcement, and route admission.
//!
//! Responsible for: the libFuzzer entry point for the `s3vectors_auth` property.
//! NOT responsible for: the property itself (`fuzz/support/s3vectors_auth.rs`) or S3 Vectors
//! storage handlers.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-sig` and `rustfs-gateway-core`, through
//! `fuzz/support/s3vectors_auth.rs`.

#![no_main]

#[path = "../support/s3vectors_auth.rs"]
mod s3vectors_auth;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = s3vectors_auth::check(input);
});
