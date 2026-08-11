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

//! `ETag` cases, including the eight historical defects this type exists to make unwritable.
//!
//! Responsible for: the three rendering contexts, tolerant parsing, the `*` wildcard, strong and
//! weak comparison, the multipart shape, and a round-trip property.
//! NOT responsible for: precondition evaluation as a whole.
//! Upstream: [`crate::scalar::etag`]. Downstream: nothing.

use proptest::prelude::*;

use crate::scalar::{ETag, EtagRender};

const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

#[test]
fn c_etag_0101_header_rendering_is_always_quoted() {
    let tag = ETag::new(EMPTY_MD5).expect("a hex digest is a valid opaque tag");
    assert_eq!(tag.render(EtagRender::HeaderQuoted), format!("\"{EMPTY_MD5}\""));
}

#[test]
fn c_etag_0002_xml_rendering_carries_literal_quotes() {
    let tag = ETag::new(EMPTY_MD5).expect("a hex digest is a valid opaque tag");
    assert_eq!(tag.render(EtagRender::XmlQuoted), format!("\"{EMPTY_MD5}\""));
}

#[test]
fn c_etag_0003_get_object_attributes_renders_bare() {
    let tag = ETag::new(EMPTY_MD5).expect("a hex digest is a valid opaque tag");
    let rendered = tag.render(EtagRender::XmlBare);
    assert_eq!(rendered, EMPTY_MD5);
    assert!(!rendered.contains('"'), "the GetObjectAttributes spelling has no quotes");
}

#[test]
fn c_etag_0004_quoted_header_parses_to_the_bare_tag() {
    let tag = ETag::parse_http_header("\"abc\"").expect("a quoted header value is valid");
    assert_eq!(tag.opaque_tag(), "abc");
    assert!(!tag.is_weak());
}

#[test]
fn c_etag_0005_multipart_etag_carries_its_part_count() {
    let parts = [[1u8; 16], [2u8; 16], [3u8; 16]];
    let tag = ETag::from_part_digests(&parts).expect("three parts are a valid multipart upload");
    assert_eq!(tag.part_count(), Some(3));
    assert!(tag.opaque_tag().ends_with("-3"));
    assert_eq!(tag.opaque_tag().len(), 32 + 2, "an MD5 hex digest plus the -N suffix");
}

#[test]
fn c_etag_n001_bare_values_are_accepted() {
    // Several SDKs send an unquoted tag in the copy-source conditional headers; rejecting it turns
    // a working client into a 400.
    let tag = ETag::parse_http_header("abc123").expect("a bare header value must be accepted");
    assert_eq!(tag.opaque_tag(), "abc123");
}

#[test]
fn c_etag_n002_weak_prefix_is_recognised() {
    let tag = ETag::parse_http_header("W/\"abc\"").expect("a weak validator is valid");
    assert!(tag.is_weak());
    assert_eq!(tag.opaque_tag(), "abc");
}

#[test]
fn c_etag_n003_wildcard_parses_instead_of_failing() {
    let tag = ETag::parse_http_header("*").expect("a wildcard is a legal conditional header value");
    assert!(tag.is_any());
    assert_eq!(tag.render(EtagRender::HeaderQuoted), "*");
}

#[test]
fn c_etag_n004_quoting_does_not_affect_comparison() {
    let stored = ETag::new(EMPTY_MD5).expect("stored tags have no quotes");
    let from_header = ETag::parse_http_header(&format!("\"{EMPTY_MD5}\"")).expect("the header carries quotes");
    assert!(stored.matches_strong(&from_header));
    assert_eq!(stored, from_header, "normalisation makes the two spellings one value");
}

#[test]
fn c_etag_n005_strong_comparison_rejects_a_weak_tag() {
    let weak = ETag::parse_http_header("W/\"abc\"").expect("valid");
    let strong = ETag::parse_http_header("\"abc\"").expect("valid");
    assert!(!weak.matches_strong(&strong));
    assert!(!strong.matches_strong(&weak));
}

#[test]
fn c_etag_n006_weak_comparison_ignores_weakness() {
    let weak = ETag::parse_http_header("W/\"abc\"").expect("valid");
    let strong = ETag::parse_http_header("\"abc\"").expect("valid");
    assert!(weak.matches_weak(&strong));
}

#[test]
fn c_etag_n007_empty_input_is_rejected_with_a_rule_reference() {
    let error = ETag::parse_http_header("").expect_err("an empty entity tag is not a tag");
    assert_eq!(error.subject(), "ETag");
    assert!(error.rule().contains("rfc9110"), "the diagnostic names the rule it enforces");
    assert!(ETag::parse_http_header("\"\"").is_err());
}

#[test]
fn c_etag_n008_an_embedded_quote_stays_a_single_xml_text_node() {
    // The XML writer escapes text nodes; rendering must not pre-escape, or the wire carries
    // `&amp;quot;`. What matters here is that the value is returned intact for it to escape.
    let tag = ETag::new("a\"b".to_owned()).expect("a backend may store any opaque value");
    assert_eq!(tag.render(EtagRender::XmlQuoted), "\"a\"b\"");
    // A header, unlike XML, has no escaping layer downstream, so the quote is escaped here.
    assert_eq!(tag.render(EtagRender::HeaderQuoted), "\"a\\\"b\"");
    // The same value may not arrive from the wire, where it would be ambiguous.
    assert!(ETag::parse_http_header("\"a\"b\"").is_err());
}

#[test]
fn c_etag_n010_a_zero_part_suffix_is_not_a_part_count() {
    let tag = ETag::new(format!("{EMPTY_MD5}-0")).expect("the value is a legal opaque tag");
    assert_eq!(tag.part_count(), None, "there is no such thing as a zero-part upload");

    let too_many = ETag::new(format!("{EMPTY_MD5}-10001")).expect("still a legal opaque tag");
    assert_eq!(too_many.part_count(), None);

    let padded = ETag::new(format!("{EMPTY_MD5}-03")).expect("still a legal opaque tag");
    assert_eq!(padded.part_count(), None, "a leading zero is not the wire form");

    assert!(ETag::from_part_digests(&[]).is_err());
}

#[test]
fn a_stored_value_that_kept_its_quotes_is_not_double_quoted() {
    // The failure this prevents: a value round-tripped through a database with quotes attached,
    // then quoted again on the way out.
    let tag = ETag::new("\"abc\"".to_owned()).expect("valid");
    assert_eq!(tag.render(EtagRender::HeaderQuoted), "\"abc\"");
    assert_eq!(tag.render(EtagRender::XmlBare), "abc");
}

#[test]
fn unbalanced_quotes_are_rejected() {
    for value in ["\"abc", "abc\"", "\"", "W/\"abc"] {
        assert!(ETag::parse_http_header(value).is_err(), "{value} is not a well-formed entity tag");
    }
}

#[test]
fn a_wildcard_matches_under_both_comparison_rules() {
    let concrete = ETag::new(EMPTY_MD5).expect("valid");
    assert!(ETag::ANY.matches_strong(&concrete));
    assert!(ETag::ANY.matches_weak(&concrete));
    assert!(concrete.matches_strong(&ETag::ANY));
}

#[test]
fn a_wildcard_is_not_special_in_an_xml_body() {
    let tag = ETag::parse_xml_text("*").expect("valid as an opaque tag");
    assert!(!tag.is_any(), "a body has no wildcard semantics");
}

#[test]
fn a_bare_value_starting_with_the_weak_prefix_is_read_as_weak() {
    // The price of accepting bare values. Documented on `parse_http_header`, and resolved in
    // favour of the RFC: quote the value if the two characters were meant literally.
    let ambiguous = ETag::parse_http_header("W/abc").expect("valid");
    assert!(ambiguous.is_weak());
    assert_eq!(ambiguous.opaque_tag(), "abc");

    let quoted = ETag::parse_http_header("\"W/abc\"").expect("valid");
    assert!(!quoted.is_weak());
    assert_eq!(quoted.opaque_tag(), "W/abc");
}

#[test]
fn control_characters_are_rejected() {
    assert!(ETag::parse_http_header("ab\nc").is_err());
    assert!(ETag::new("ab\u{0}c".to_owned()).is_err());
}

proptest! {
    /// Whatever spelling arrives, rendering it back into a header and re-parsing yields the same
    /// value. This is the property the quoting defects kept violating.
    #[test]
    fn header_round_trip_is_stable(tag in "[a-zA-Z0-9._:-]{1,40}", weak in any::<bool>()) {
        let prefix = if weak { "W/" } else { "" };
        let parsed = ETag::parse_http_header(&format!("{prefix}\"{tag}\"")).expect("generated tags are valid");
        let rendered = parsed.render(EtagRender::HeaderQuoted).into_owned();
        let reparsed = ETag::parse_http_header(&rendered).expect("a rendered tag re-parses");
        prop_assert_eq!(&parsed, &reparsed);
        prop_assert_eq!(parsed.is_weak(), weak);
    }

    /// The quoted and bare spellings of one tag are the same value, which is what makes
    /// comparison independent of the position the tag arrived in.
    #[test]
    fn quoted_and_bare_spellings_agree(tag in "[a-zA-Z0-9._:-]{1,40}") {
        let quoted = ETag::parse_http_header(&format!("\"{tag}\"")).expect("generated tags are valid");
        let bare = ETag::parse_http_header(&tag).expect("generated tags are valid");
        prop_assert!(quoted.matches_strong(&bare));
        prop_assert_eq!(quoted.render(EtagRender::XmlBare), bare.render(EtagRender::XmlBare));
    }
}
