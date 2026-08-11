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

//! Exercises Range parsing, resolution and response metadata with arbitrary text and lengths.
//! It does not select response statuses, read bodies or combine Range with partNumber.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-types` scalar parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_types::RangeSpec;

fuzz_target!(|input: &[u8]| {
    let prefix_len = input.len().min(8);
    let mut length_bytes = [0_u8; 8];
    length_bytes[..prefix_len].copy_from_slice(&input[..prefix_len]);
    let object_len = u64::from_le_bytes(length_bytes);

    if let Ok(header) = std::str::from_utf8(&input[prefix_len..]) {
        let spec = RangeSpec::new(header);
        let outcome = spec.resolve(object_len);
        let _ = spec.as_str();
        let _ = outcome.content_length(object_len);
        let _ = outcome.content_range(object_len);
    }
});
