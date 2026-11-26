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

//! The `http_metadata_query` fuzz property: RFC 2047 user-metadata codecs and `QueryIndex`/`QueryView`.
//!
//! Responsible for: asserting that `validate_metadata_value` agrees with `decode_metadata_value`,
//! that no control character survives `decode_metadata_value`, that `encode_metadata_value` always
//! emits printable ASCII (`0x20..0x7f`) whose decode rejects control-bearing values with
//! `MetadataReject::ControlCharacterAfterDecoding` and round-trips clean values verbatim, and that
//! `QueryIndex::parse` / `QueryView` uphold limit, percent-escape, and single-value invariants under
//! both default and tight limits.
//! NOT responsible for: full `WireRequest::accept` header acceptance (`header_accept.rs`).
//! Upstream: libFuzzer bytes or fixed replay tests in `crates/http/tests/header_and_query.rs`.
//! Downstream: `rustfs-gateway-http`.

use rustfs_gateway_http::{
    Limits, MetadataReject, QueryIndex, QueryView, SINGLE_VALUED_QUERY_PARAMS, decode_metadata_value, encode_metadata_value,
    validate_metadata_key, validate_metadata_value,
};

/// Exercises RFC 2047 metadata and query-index invariants on arbitrary bytes.
pub(crate) fn check(input: &[u8]) {
    let valid_bytes = validate_metadata_value(input);
    let Ok(text) = std::str::from_utf8(input) else {
        assert!(valid_bytes.is_err(), "non-UTF-8 bytes must be rejected by validate_metadata_value");
        return;
    };

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

    let encoded = encode_metadata_value(text).expect("encode_metadata_value accepts every UTF-8 str");
    assert!(
        encoded.bytes().all(|b| (0x20..0x7f).contains(&b)),
        "encode_metadata_value emitted non-printable-ASCII byte: {encoded:?}"
    );
    if text.chars().any(char::is_control) {
        assert_eq!(
            decode_metadata_value(&encoded),
            Err(MetadataReject::ControlCharacterAfterDecoding),
            "encoded control-bearing metadata must be refused on decode: {text:?}"
        );
    } else {
        assert_eq!(
            decode_metadata_value(&encoded).as_deref(),
            Ok(text),
            "RFC 2047 metadata round-trip mismatch for control-free value: {text:?}"
        );
    }

    let tight = Limits {
        max_query_params: 2,
        max_query_bytes: 32,
        ..Limits::default()
    };
    for limits in [Limits::default(), tight] {
        if let Ok(index) = QueryIndex::parse(text, &limits) {
            let view = QueryView::new(text, &index);
            assert!(view.len() <= limits.max_query_params);
            assert!(text.len() <= limits.max_query_bytes);
            for (name, _value) in view.iter() {
                assert!(!name.contains('%'), "percent-escaped query name survived QueryIndex::parse");
            }
            for &single in SINGLE_VALUED_QUERY_PARAMS {
                let count = view.iter().filter(|(name, _)| *name == single).count();
                assert!(count <= 1, "duplicate single-valued query parameter {single} survived QueryIndex::parse");
            }
        }
    }
}
