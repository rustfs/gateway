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

//! The trailer container itself.
//!
//! Responsible for: proving that an absent trailer section is an empty map rather than an
//! absent value, and that the fields survive the round trip through the container.
//! NOT responsible for: when the container may be obtained — that is `eof_trailers`.
//! Upstream: `support`. Downstream: nothing.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

use crate::tests::support::{trailer_value, trailers};
use crate::trailers::TrailingHeaders;

#[test]
fn an_absent_trailer_section_is_an_empty_map_not_an_absent_value() {
    let trailers = TrailingHeaders::empty();

    assert!(trailers.is_empty());
    assert_eq!(trailers.len(), 0);
    assert_eq!(trailers.iter().count(), 0);
    assert!(trailers.as_header_map().is_empty());
}

#[test]
fn a_trailer_field_survives_the_round_trip() {
    let trailers = trailers(&[("x-trailer-value", "AAAAAA=="), ("x-trailer-mark", "1")]);

    assert_eq!(trailers.len(), 2);
    assert_eq!(trailer_value(&trailers, "x-trailer-value").as_deref(), Some("AAAAAA=="));
    assert!(trailers.contains_key(&HeaderName::from_static("x-trailer-mark")));

    let map: HeaderMap = trailers.into_header_map();
    assert_eq!(map.get("x-trailer-value"), Some(&HeaderValue::from_static("AAAAAA==")));
}

#[test]
fn an_unknown_trailer_name_reads_as_absent() {
    let trailers = trailers(&[("x-trailer-value", "AAAAAA==")]);

    assert_eq!(trailer_value(&trailers, "x-trailer-missing"), None);
    assert!(!trailers.contains_key(&HeaderName::from_static("x-trailer-missing")));
}

#[test]
fn the_default_trailer_section_is_empty() {
    let trailers = TrailingHeaders::default();
    assert!(trailers.is_empty());

    let borrowed: Vec<_> = (&trailers).into_iter().collect();
    assert!(borrowed.is_empty());
}
