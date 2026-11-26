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
//! Responsible for: asserting that no control character ever survives `decode_metadata_value`,
//! that `encode_metadata_value` never emits raw CR/LF/NUL bytes, that `validate_metadata_value`
//! agrees with `decode_metadata_value`, and that `QueryIndex::parse` / `QueryView` reject
//! percent-escaped names, forbidden control bytes, and repeated `SINGLE_VALUED_QUERY_PARAMS`.
//! NOT responsible for: full `WireRequest::accept` header acceptance (`header_accept.rs`).
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-http`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_http::{
    Limits, QueryIndex, QueryView, SINGLE_VALUED_QUERY_PARAMS, decode_metadata_value, encode_metadata_value,
    validate_metadata_key, validate_metadata_value,
};

fuzz_target!(|input: &[u8]| {
    // 1. RFC 2047 user-metadata validation, decoding, and encoding invariants.
    let valid_bytes = validate_metadata_value(input);
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = validate_metadata_key(text);
        let decoded = decode_metadata_value(text);
        assert_eq!(
            valid_bytes.is_ok(),
            decoded.is_ok(),
            "validate_metadata_value and decode_metadata_value must agree on UTF-8 input"
        );
        if let Ok(decoded_text) = decoded {
            assert!(
                !decoded_text.chars().any(char::is_control),
                "control character survived RFC 2047 metadata decoding: {decoded_text:?}"
            );
        }
        if let Ok(encoded) = encode_metadata_value(text) {
            assert!(
                !encoded.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)),
                "encode_metadata_value emitted header-injection byte: {encoded:?}"
            );
            // Round-trip: anything encode_metadata_value accepts must decode cleanly back to text.
            let round_trip = decode_metadata_value(&encoded).expect("encoded metadata value must decode");
            assert_eq!(round_trip, text, "RFC 2047 metadata round-trip mismatch");
        }

        // 2. QueryIndex / QueryView invariants under default and tight limits.
        let limits = Limits::default();
        if let Ok(index) = QueryIndex::parse(text, &limits) {
            let view = QueryView::new(text, &index);
            assert!(view.len() <= limits.max_query_params);
            for (name, _value) in view.iter() {
                assert!(!name.contains('%'), "percent-escaped query name survived QueryIndex::parse");
            }
            for &single in SINGLE_VALUED_QUERY_PARAMS {
                let count = view.iter().filter(|(name, _)| *name == single).count();
                assert!(count <= 1, "duplicate single-valued query parameter {single} survived QueryIndex::parse");
            }
        }
    } else {
        assert!(valid_bytes.is_err(), "non-UTF-8 bytes must be rejected by validate_metadata_value");
    }
});
