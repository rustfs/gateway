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

//! Exercises tolerant ETag parsing and all explicit render contexts with arbitrary text.
//! It does not evaluate HTTP preconditions or construct operation responses.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-types` scalar parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_types::{ETag, EtagRender};

fuzz_target!(|input: &[u8]| {
    if let Ok(value) = std::str::from_utf8(input)
        && let Ok(tag) = ETag::parse_http_header(value)
    {
        let _ = tag.render(EtagRender::HeaderQuoted);
        let _ = tag.render(EtagRender::XmlQuoted);
        let _ = tag.render(EtagRender::XmlBare);
        let _ = tag.part_count();
        let _ = tag.matches_strong(&tag);
        let _ = tag.matches_weak(&tag);
    }
});
