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

//! Base64 cases: the RFC 4648 vectors, and the strictness that keeps one digest to one spelling.
//!
//! Responsible for: the published test vectors, rejection of every malformed shape, and a
//! round-trip property.
//! NOT responsible for: checksum semantics, which are next door.
//! Upstream: [`crate::scalar::base64`]. Downstream: nothing.

use proptest::prelude::*;

use crate::scalar::base64::{decode_into, encode};

fn decode(value: &str) -> Result<Vec<u8>, crate::scalar::ParseError> {
    let mut out = [0u8; 64];
    let written = decode_into("Test", value, &mut out)?;
    Ok(out[..written].to_vec())
}

#[test]
fn rfc4648_vectors_encode_exactly() {
    let vectors = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, encoded) in vectors {
        assert_eq!(encode(plain.as_bytes()), encoded, "encoding {plain}");
        if !plain.is_empty() {
            assert_eq!(decode(encoded).expect("a published vector decodes"), plain.as_bytes());
        }
    }
}

#[test]
fn malformed_input_is_rejected() {
    for value in [
        "",         // empty
        "Zg=",      // not a multiple of four
        "Zg===",    // over-padded
        "=Zm8",     // padding first
        "Z=8=",     // padding in the middle
        "Zm8=Zm8=", // padding followed by data
        "Zm9-",     // URL-safe alphabet
        "Zm9 v",    // whitespace
        "Zg==\n",   // trailing newline
    ] {
        assert!(decode(value).is_err(), "{value:?} must not decode");
    }
}

#[test]
fn non_canonical_trailing_bits_are_rejected() {
    // `Zh==` and `Zg==` would decode to the same byte; accepting both would give one digest two
    // spellings, which is exactly what a strict comparison must not allow.
    assert!(decode("Zg==").is_ok());
    assert!(decode("Zh==").is_err());
    assert!(decode("Zm9=").is_err());
}

#[test]
fn a_value_wider_than_the_target_is_refused() {
    let mut small = [0u8; 4];
    let encoded = encode(&[0u8; 32]);
    assert!(decode_into("Test", &encoded, &mut small).is_err());
}

proptest! {
    #[test]
    fn round_trip(bytes in proptest::collection::vec(any::<u8>(), 1..48)) {
        let encoded = encode(&bytes);
        let decoded = decode(&encoded).expect("what this module encoded, it decodes");
        prop_assert_eq!(decoded, bytes);
    }
}
