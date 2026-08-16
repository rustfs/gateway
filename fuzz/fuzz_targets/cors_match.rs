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

//! Exercises CORS origin, method, and requested-header matching with bounded arbitrary text.
//! It does not parse stored XML, classify HTTP requests, or render response headers.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-core` CORS matching.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_core::cors::{RequestedHeaders, match_actual, match_preflight, wildcard_match};
use rustfs_gateway_types::dto::{CorsConfiguration, CorsRule};

const MAX_INPUT_BYTES: usize = 8192;
const MAX_RULES: usize = 16;

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_INPUT_BYTES {
        return;
    }
    let text = String::from_utf8_lossy(input);
    let mut fields = text.split('\0');
    let origin = fields.next().unwrap_or_default();
    let method = fields.next().unwrap_or_default();
    let requested = fields.next().unwrap_or_default();
    let mut cors_rules = Vec::new();

    for _ in 0..MAX_RULES {
        let Some(allowed_origin) = fields.next() else {
            break;
        };
        let allowed_method = fields.next().unwrap_or_default();
        let allowed_header = fields.next().unwrap_or_default();
        let _ = wildcard_match(allowed_origin, origin);
        cors_rules.push(CorsRule {
            allowed_origins: vec![allowed_origin.to_owned()],
            allowed_methods: vec![allowed_method.to_owned()],
            allowed_headers: vec![allowed_header.to_owned()],
            ..CorsRule::default()
        });
    }

    let configuration = CorsConfiguration { cors_rules };
    let _ = match_actual(&configuration, origin, method);
    if let Ok(headers) = RequestedHeaders::parse(requested) {
        let _ = match_preflight(&configuration, origin, method, &headers);
    }
});
