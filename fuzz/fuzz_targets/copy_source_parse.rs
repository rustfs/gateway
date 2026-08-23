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

//! Exercises every copy-source grammar and rejection path with arbitrary UTF-8 header values.
//! It does not authorize or resolve a parsed source into its bucket, key or version.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-core` copy-source parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_core::ops::shared::copy_source::CopySource;

fuzz_target!(|input: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(input) {
        if let Ok(source) = CopySource::parse(raw) {
            let _ = source.form();
        }
    }
});
