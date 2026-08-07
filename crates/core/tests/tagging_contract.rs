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

//! The shared tagging contract: one parser for the packed header, one validator for both channels.
//!
//! Responsible for: every observable behaviour of `ops::shared::tagging` — the
//! `x-amz-tagging` header grammar, the per-scope tag-set limits, the character set, and the
//! rejection codes each violation carries. 8 positive / 17 negative, plus one property.
//! NOT responsible for: the XML wire form (generated codecs) or what a backend stores.
//! Upstream: `rustfs_gateway_core::ops::shared::tagging`. Downstream: nothing.

use proptest::prelude::*;
use rustfs_gateway_core::ops::shared::tagging::{
    MAX_BUCKET_TAGS, MAX_OBJECT_TAGS, MAX_TAG_KEY_CHARS, MAX_TAG_VALUE_CHARS, TagScope, parse_tagging_header, validate_tag_set,
};
use rustfs_gateway_types::ErrorCode;

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// The header the AWS SDKs send: pairs joined with `&`, keys before `=`.
#[test]
fn a_plain_header_parses_into_ordered_pairs() {
    let parsed = parse_tagging_header(Some("a=1&b=2")).expect("a well-formed header");
    assert_eq!(parsed, pairs(&[("a", "1"), ("b", "2")]));
}

/// No header means no tags, not an error: the header is optional on every operation carrying it.
#[test]
fn an_absent_header_is_an_empty_tag_set() {
    assert_eq!(parse_tagging_header(None).expect("absence is not a fault"), Vec::new());
}

/// Form decoding: `+` is a space and `%xx` is a byte, in both halves of a pair.
#[test]
fn the_header_is_form_decoded() {
    let parsed = parse_tagging_header(Some("a%20b=c%2Bd&e+f=g")).expect("escapes decode");
    assert_eq!(parsed, pairs(&[("a b", "c+d"), ("e f", "g")]));
}

/// An empty value is legal — a tag may be a bare label.
#[test]
fn an_empty_value_is_legal() {
    let parsed = parse_tagging_header(Some("flag=")).expect("an empty value is a value");
    assert_eq!(parsed, pairs(&[("flag", "")]));
    validate_tag_set(&parsed, TagScope::Object).expect("an empty value validates");
}

/// The documented character set: letters, numbers, space, and `+ - = . _ : / @`.
#[test]
fn the_documented_special_characters_validate() {
    let set = pairs(&[("k+-=._:/@ 1", "v+-=._:/@ 2")]);
    validate_tag_set(&set, TagScope::Object).expect("the documented set is legal");
}

/// Unicode letters count as letters: a label in another script is not a protocol violation.
#[test]
fn unicode_letters_validate_and_count_as_single_characters() {
    let key = "标签".repeat(64); // 128 characters, 384 UTF-8 bytes.
    let value = "值".repeat(256);
    validate_tag_set(&pairs(&[(&key, &value)]), TagScope::Object).expect("128 and 256 characters exactly");
}

/// The two scopes differ only in the count ceiling.
#[test]
fn the_scope_ceilings_are_the_documented_ten_and_fifty() {
    assert_eq!(TagScope::Object.max_tags(), MAX_OBJECT_TAGS);
    assert_eq!(TagScope::Bucket.max_tags(), MAX_BUCKET_TAGS);
    assert_eq!(MAX_OBJECT_TAGS, 10);
    assert_eq!(MAX_BUCKET_TAGS, 50);
    assert_eq!(MAX_TAG_KEY_CHARS, 128);
    assert_eq!(MAX_TAG_VALUE_CHARS, 256);
}

/// Fifty tags on a bucket is the ceiling, not past it.
#[test]
fn a_bucket_holds_exactly_fifty_tags() {
    let set: Vec<(String, String)> = (0..50).map(|index| (format!("k{index}"), "v".to_owned())).collect();
    validate_tag_set(&set, TagScope::Bucket).expect("fifty is within the bucket ceiling");
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// A segment with no `=` is not half a tag.
#[test]
fn n_a_segment_without_a_separator_is_refused() {
    let rejection = parse_tagging_header(Some("a")).expect_err("no separator");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_ARGUMENT);
}

/// An empty key has no legal representation.
#[test]
fn n_an_empty_key_is_refused() {
    let rejection = parse_tagging_header(Some("=v")).expect_err("an empty key");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// A repeated key in the header is the header's own refusal, with AWS's one sentence for it.
#[test]
fn n_a_duplicate_key_in_the_header_is_refused() {
    let rejection = parse_tagging_header(Some("a=1&a=2")).expect_err("a duplicate");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_ARGUMENT);
    assert!(rejection.reason().contains("duplicates"), "{}", rejection.reason());
}

/// A truncated escape would store a key no later request can spell.
#[test]
fn n_a_truncated_escape_is_refused() {
    let rejection = parse_tagging_header(Some("a=%2")).expect_err("a truncated escape");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_ARGUMENT);
}

/// A non-hex escape is the same refusal.
#[test]
fn n_a_non_hex_escape_is_refused() {
    let rejection = parse_tagging_header(Some("a=%zz")).expect_err("a non-hex escape");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_ARGUMENT);
}

/// An escape that decodes to bytes that are not UTF-8 is refused, not stored as mojibake.
#[test]
fn n_an_escape_that_is_not_utf8_is_refused() {
    let rejection = parse_tagging_header(Some("a=%ff%fe")).expect_err("not UTF-8");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_ARGUMENT);
}

/// The reason never echoes what the caller sent: a constant, in every refusal.
#[test]
fn n_a_rejection_reason_never_echoes_the_header() {
    for header in ["secret-key-name", "a=%2", "=leaked"] {
        if let Err(rejection) = parse_tagging_header(Some(header)) {
            assert!(!rejection.reason().contains("secret"), "{}", rejection.reason());
            assert!(!rejection.reason().contains("leaked"), "{}", rejection.reason());
        }
    }
}

/// Eleven tags on an object is one past the documented ceiling.
#[test]
fn n_an_eleventh_object_tag_is_refused() {
    let set: Vec<(String, String)> = (0..11).map(|index| (format!("k{index}"), "v".to_owned())).collect();
    let rejection = validate_tag_set(&set, TagScope::Object).expect_err("eleven tags");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// Fifty-one tags on a bucket is one past the documented ceiling.
#[test]
fn n_a_fifty_first_bucket_tag_is_refused() {
    let set: Vec<(String, String)> = (0..51).map(|index| (format!("k{index}"), "v".to_owned())).collect();
    let rejection = validate_tag_set(&set, TagScope::Bucket).expect_err("fifty-one tags");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// Eleven tags is legal for a bucket: the ceilings must not be swapped.
#[test]
fn n_the_object_ceiling_is_not_applied_to_a_bucket() {
    let set: Vec<(String, String)> = (0..11).map(|index| (format!("k{index}"), "v".to_owned())).collect();
    validate_tag_set(&set, TagScope::Bucket).expect("eleven tags fit a bucket");
}

/// A 129-character key is over the ceiling, in characters rather than bytes.
#[test]
fn n_an_overlong_key_is_refused() {
    let key = "k".repeat(129);
    let rejection = validate_tag_set(&pairs(&[(&key, "v")]), TagScope::Object).expect_err("129 characters");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// A 257-character value is over its own ceiling.
#[test]
fn n_an_overlong_value_is_refused() {
    let value = "v".repeat(257);
    let rejection = validate_tag_set(&pairs(&[("k", &value)]), TagScope::Object).expect_err("257 characters");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// A multi-byte key at 129 characters is refused even though its UTF-8 form was legal at 128.
#[test]
fn n_the_key_ceiling_counts_characters_not_bytes() {
    let key = "标".repeat(129);
    let rejection = validate_tag_set(&pairs(&[(&key, "v")]), TagScope::Object).expect_err("129 characters");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// An empty key is refused by the validator too — the XML channel does not pass through the parser.
#[test]
fn n_the_validator_refuses_an_empty_key() {
    let rejection = validate_tag_set(&pairs(&[("", "v")]), TagScope::Object).expect_err("an empty key");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// A duplicate key in the XML channel is `InvalidTag`, the document's own code for it.
#[test]
fn n_the_validator_refuses_a_duplicate_key() {
    let rejection = validate_tag_set(&pairs(&[("a", "1"), ("a", "2")]), TagScope::Object).expect_err("a duplicate");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
    assert!(rejection.reason().contains("duplicate"), "{}", rejection.reason());
}

/// A control character is outside the documented set.
#[test]
fn n_a_control_character_is_refused() {
    let rejection = validate_tag_set(&pairs(&[("a\u{1}b", "v")]), TagScope::Object).expect_err("a control byte");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
    let rejection = validate_tag_set(&pairs(&[("k", "v\u{1}")]), TagScope::Object).expect_err("a control byte");
    assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG);
}

/// Punctuation outside the documented set — `<` would nest into the XML rendering, `#`, `?` and
/// `&` would corrupt the header rendering.
#[test]
fn n_undocumented_punctuation_is_refused() {
    for illegal in ["a<b", "a#b", "a?b", "a&b", "a\"b"] {
        let outcome = validate_tag_set(&pairs(&[(illegal, "v")]), TagScope::Object);
        let rejection = outcome.expect_err("undocumented punctuation must be refused");
        assert_eq!(*rejection.code(), ErrorCode::INVALID_TAG, "{illegal}");
    }
}

// ── property ─────────────────────────────────────────────────────────────────────────────────

/// A strategy over keys and values drawn from the documented character set.
fn legal_text(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select("abcXYZ019 +-=._:/@标".chars().collect::<Vec<char>>()), 1..max)
        .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    /// Any legal tag set survives the header channel: an independently written form encoder
    /// produces a header the shared parser reads back into the same ordered pairs, and the
    /// validator accepts what it accepted before.
    #[test]
    fn any_legal_tag_set_round_trips_through_the_header_form(
        keys in proptest::collection::btree_set(legal_text(128), 1..10),
        values in proptest::collection::vec(legal_text(256), 10),
    ) {
        let set: Vec<(String, String)> = keys.into_iter().zip(values).collect();
        prop_assert!(validate_tag_set(&set, TagScope::Object).is_ok());

        // The encoder is written here, against the form-urlencoded alphabet, precisely so that the
        // parser is measured against something it did not write.
        let encode = |text: &str| -> String {
            let mut out = String::new();
            for byte in text.as_bytes() {
                match byte {
                    b' ' => out.push('+'),
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => out.push(char::from(*byte)),
                    other => {
                        out.push('%');
                        out.push_str(&format!("{other:02X}"));
                    }
                }
            }
            out
        };
        let header = set
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<String>>()
            .join("&");
        let parsed = parse_tagging_header(Some(&header)).expect("a legal set encodes to a legal header");
        prop_assert_eq!(parsed, set);
    }
}
