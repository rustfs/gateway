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

//! Exercises credential-header parsing and session-token comparison with arbitrary bytes.
//! It does not verify requests or issue credentials.
//! Upstream: libFuzzer. Downstream: `rustfs-gateway-sig` parsers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_sig::{SessionToken, SigV4Authorization};

fuzz_target!(|input: &[u8]| {
    let split = input.len() / 2;
    if let Ok(header) = std::str::from_utf8(&input[..split]) {
        let _ = SigV4Authorization::parse(header);
    }
    if let Ok(expected) = std::str::from_utf8(&input[split..]) {
        if let Ok(token) = SessionToken::new(expected) {
            let _ = token.ct_verify(&input[..split]);
        }
    }
});
