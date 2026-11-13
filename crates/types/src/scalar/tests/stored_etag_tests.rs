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

//! `ETag::from_stored`: the entity tag a host holds, kept byte for byte (rustfs/gateway#1611).
//!
//! Responsible for: that the stored constructor never rewrites or refuses, that the request-side
//! constructors keep refusing the shapes it admits, how a stored tag renders in each context, and
//! how it compares with a tag a request carried.
//! NOT responsible for: the bytes the codecs write around the rendered value (the core crate's
//! `stored_entity_tag` integration test), or the ordinary constructors (`etag_tests`).
//! Upstream: [`crate::scalar::etag`]. Downstream: nothing.

use crate::WirePlaceholder;
use crate::scalar::{ETag, EtagRender};

/// The four stored values the issue names: a quoted empty tag, one with a tab, one with markup,
/// and an ordinary quoted digest as a header delivered it.
const STORED: &[&str] = &["\"\"", "a\tb", "<x>&amp;</ETag>", "\"d41d8cd98f00b204e9800998ecf8427e\""];

/// Stored values `ETag::new` refuses: empty, empty once its quotes are stripped, and three control
/// characters, one of them a line feed.
const REFUSED_SHAPES: &[&str] = &["", "\"\"", "a\tb", "a\u{1}b", "a\nb"];

/// Request spellings the request-side parser accepts, among them every normalised form one of the
/// refused shapes could be mistaken for.
const REQUEST_TAGS: &[&str] = &[
    "\"ab\"",
    "ab",
    "\"a b\"",
    "\"a\"",
    "\"b\"",
    "W/\"ab\"",
    "\"d41d8cd98f00b204e9800998ecf8427e\"",
];

fn request(value: &str) -> ETag {
    ETag::parse_http_header(value).expect("the fixture is a spelling a request may carry")
}

#[test]
fn n_the_storage_constructor_still_refuses_what_the_stored_one_admits() {
    for value in ["\"\"", "a\tb", "", "W/\"\""] {
        assert!(ETag::new(value).is_err(), "ETag::new admitted {value:?}");
        assert!(ETag::new_weak(value).is_err(), "ETag::new_weak admitted {value:?}");
    }
}

#[test]
fn n_the_request_parsers_still_refuse_what_the_stored_one_admits() {
    for value in ["\"\"", "\"a\tb\"", "\"<x>\"\"\"", ""] {
        assert!(ETag::parse_http_header(value).is_err(), "the header parser admitted {value:?}");
        assert!(ETag::parse_xml_text(value).is_err(), "the XML text parser admitted {value:?}");
    }
}

#[test]
fn n_a_stored_tag_keeps_its_quotes_and_weakness_prefix_as_bytes() {
    let quoted = ETag::from_stored("\"abc\"");
    assert_eq!(quoted.opaque_tag(), "\"abc\"", "the stored quotes were stripped");
    let prefixed = ETag::from_stored("W/\"abc\"");
    assert_eq!(prefixed.opaque_tag(), "W/\"abc\"", "the stored prefix was read as weakness");
    assert!(!prefixed.is_weak(), "a stored tag is the host's strong value");
}

#[test]
fn n_a_stored_star_is_a_tag_and_not_the_wildcard() {
    let star = ETag::from_stored("*");
    assert!(!star.is_any());
    assert_eq!(star.render(EtagRender::HeaderQuoted), "\"*\"");
    assert!(!star.matches_strong(&request("\"abc\"")), "a stored star matched an unrelated tag");
}

#[test]
fn n_a_stored_empty_tag_is_a_value_and_not_the_placeholder() {
    let empty = ETag::from_stored("");
    assert!(!empty.is_wire_placeholder(), "the host's empty tag would fail the response as unset");
    assert_ne!(empty, ETag::default());
    assert!(ETag::default().is_wire_placeholder(), "the placeholder itself is unchanged");
}

#[test]
fn n_a_refused_shape_stored_tag_matches_no_request_tag() {
    for stored in REFUSED_SHAPES {
        let stored_tag = ETag::from_stored(*stored);
        for spelling in REQUEST_TAGS {
            let asked = request(spelling);
            assert!(!stored_tag.matches_strong(&asked), "{stored:?} strongly matched {spelling:?}");
            assert!(!asked.matches_strong(&stored_tag), "{spelling:?} strongly matched {stored:?}");
            assert!(!stored_tag.matches_weak(&asked), "{stored:?} weakly matched {spelling:?}");
            assert!(!asked.matches_weak(&stored_tag), "{spelling:?} weakly matched {stored:?}");
        }
    }
}

#[test]
fn n_a_stored_quoted_tag_does_not_match_its_unquoted_request_form() {
    let stored = ETag::from_stored("\"d41d8cd98f00b204e9800998ecf8427e\"");
    let asked = request("\"d41d8cd98f00b204e9800998ecf8427e\"");
    assert!(!stored.matches_strong(&asked), "normalisation matched bytes the host never stored");
    assert!(!asked.matches_strong(&stored));
}

#[test]
fn n_a_weak_request_tag_never_strongly_matches_a_stored_one() {
    let stored = ETag::from_stored("abc");
    assert!(!stored.matches_strong(&request("W/\"abc\"")));
    assert!(stored.matches_weak(&request("W/\"abc\"")), "weak comparison ignores weakness, as before");
}

#[test]
fn an_ordinary_stored_tag_matches_the_same_request_tag_both_ways() {
    let stored = ETag::from_stored("d41d8cd98f00b204e9800998ecf8427e");
    let asked = request("\"d41d8cd98f00b204e9800998ecf8427e\"");
    assert!(stored.matches_strong(&asked));
    assert!(asked.matches_strong(&stored));
    assert_eq!(stored, ETag::new("d41d8cd98f00b204e9800998ecf8427e").expect("a digest"));
}

#[test]
fn a_refused_shape_stored_tag_matches_itself() {
    for stored in REFUSED_SHAPES {
        assert!(ETag::from_stored(*stored).matches_strong(&ETag::from_stored(*stored)), "{stored:?}");
    }
}

#[test]
fn every_stored_value_survives_in_every_rendering_context() {
    for stored in STORED {
        let tag = ETag::from_stored(*stored);
        assert_eq!(tag.opaque_tag(), *stored);
        assert_eq!(tag.render(EtagRender::XmlBare), *stored);
        assert_eq!(tag.render(EtagRender::XmlQuoted), format!("\"{stored}\""));
        let escaped = stored.replace('\\', "\\\\").replace('"', "\\\"");
        assert_eq!(tag.render(EtagRender::HeaderQuoted), format!("\"{escaped}\""));
    }
}
