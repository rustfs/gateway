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

//! Range cases: the three forms, clamping, and the two ways a range is answered with 200.
//!
//! Responsible for: the parse classification, resolution against an object length, `Content-Range`
//! output, and the property that a satisfied range never runs past the object.
//! NOT responsible for: status code selection, or the `Range` + `partNumber` conflict.
//! Upstream: [`crate::scalar::range`]. Downstream: nothing.

use proptest::prelude::*;

use crate::scalar::{ByteRange, RangeOutcome, RangeParse, RangeSpec};

fn one(header: &str) -> ByteRange {
    match RangeParse::parse(header) {
        RangeParse::One(range) => range,
        other => panic!("{header:?} should be a single range, got {other:?}"),
    }
}

#[test]
fn c_rng_0001_a_closed_range_resolves_to_itself() {
    assert_eq!(
        one("bytes=0-9").resolve(100),
        RangeOutcome::Satisfied {
            start: 0,
            end_inclusive: 9
        }
    );
    assert_eq!(one("bytes=0-9").resolve(100).content_length(100), 10, "end - start + 1");
}

#[test]
fn the_three_forms_parse() {
    assert_eq!(one("bytes=0-9"), ByteRange::FromTo { first: 0, last: 9 });
    assert_eq!(one("bytes=5-"), ByteRange::From { first: 5 });
    assert_eq!(one("bytes=-5"), ByteRange::Suffix { length: 5 });
    assert_eq!(one(" bytes=0-9 "), ByteRange::FromTo { first: 0, last: 9 });
}

#[test]
fn an_overlong_range_is_clamped_rather_than_rejected() {
    // Resumable downloads routinely ask for more than is there; a 416 here breaks them.
    assert_eq!(
        one("bytes=5-100").resolve(50),
        RangeOutcome::Satisfied {
            start: 5,
            end_inclusive: 49
        }
    );
    assert_eq!(
        one("bytes=0-").resolve(50),
        RangeOutcome::Satisfied {
            start: 0,
            end_inclusive: 49
        }
    );
    assert_eq!(
        one("bytes=-500").resolve(50),
        RangeOutcome::Satisfied {
            start: 0,
            end_inclusive: 49
        },
        "a suffix longer than the object is the whole object, with a 206"
    );
}

#[test]
fn a_range_that_starts_past_the_end_is_unsatisfiable() {
    assert_eq!(one("bytes=100-200").resolve(50), RangeOutcome::Unsatisfiable { actual: 50 });
    assert_eq!(one("bytes=50-").resolve(50), RangeOutcome::Unsatisfiable { actual: 50 });
    assert_eq!(one("bytes=-0").resolve(50), RangeOutcome::Unsatisfiable { actual: 50 });
    assert_eq!(one("bytes=0-9").resolve(0), RangeOutcome::Unsatisfiable { actual: 0 });
}

#[test]
fn a_syntactically_invalid_range_is_ignored_not_rejected() {
    // RFC 9110 requires an unparseable Range to be ignored. Returning 400 breaks clients whose
    // proxy rewrote the header.
    for header in [
        "bytes=",
        "bytes=-",
        "bytes=abc",
        "bytes=9-0",
        "bytes=--5",
        "bytes=0-9-10",
        "items=0-9",
        "0-9",
        "bytes=0-99999999999999999999999",
    ] {
        assert_eq!(RangeParse::parse(header), RangeParse::Ignore, "{header:?} must be ignored");
        assert_eq!(RangeParse::parse(header).resolve(100), RangeOutcome::Full);
    }
}

#[test]
fn a_multi_range_request_yields_the_whole_object() {
    // S3 does not implement multipart/byteranges; it answers 200 with everything.
    assert_eq!(RangeParse::parse("bytes=0-1,5-6"), RangeParse::MultiRange);
    assert_eq!(RangeParse::parse("bytes=0-1,5-6").resolve(100), RangeOutcome::Full);
    assert_eq!(RangeParse::parse("bytes=0-1, 5-6"), RangeParse::MultiRange);
    // A malformed member makes the whole header malformed, not a multi-range.
    assert_eq!(RangeParse::parse("bytes=0-1,,"), RangeParse::Ignore);
    assert_eq!(RangeParse::parse("bytes=0-1,junk"), RangeParse::Ignore);
}

#[test]
fn an_absent_header_is_distinguishable_from_a_broken_one() {
    assert_eq!(RangeParse::parse_optional(None), RangeParse::Absent);
    assert_eq!(
        RangeParse::parse_optional(Some("bytes=0-1")),
        RangeParse::One(ByteRange::FromTo { first: 0, last: 1 })
    );
    assert_eq!(RangeParse::parse_optional(None).resolve(10), RangeOutcome::Full);
}

#[test]
fn content_range_is_rendered_for_both_answerable_and_unsatisfiable() {
    assert_eq!(one("bytes=0-9").resolve(100).content_range(100).as_deref(), Some("bytes 0-9/100"));
    assert_eq!(one("bytes=5-100").resolve(50).content_range(50).as_deref(), Some("bytes 5-49/50"));
    assert_eq!(
        one("bytes=100-").resolve(50).content_range(50).as_deref(),
        Some("bytes */50"),
        "the 416 body and header both report the real size"
    );
    assert_eq!(RangeOutcome::Full.content_range(50), None);
    assert_eq!(RangeOutcome::Full.content_length(50), 50);
}

// ---------------------------------------------------------------------------------------------
// RangeSpec — the parse that keeps its source
//
// These say why the binding is `RangeSpec` and not `ByteRange`: two different headers that resolve
// identically, and a header that resolves to nothing and still has to be quotable. Neither was
// representable before, and both are what a 416 document needs.
// ---------------------------------------------------------------------------------------------

/// Negative — two different headers, one resolution. This is the pair that makes re-spelling the
/// range out of the parsed value a guess rather than a derivation.
#[test]
fn n_two_spellings_that_resolve_alike_are_still_told_apart() {
    let open = RangeSpec::new("bytes=0-");
    let overlong = RangeSpec::new("bytes=0-99999");

    assert_eq!(
        open.resolve(100),
        overlong.resolve(100),
        "against a hundred bytes both are the same window"
    );
    assert_ne!(open.as_str(), overlong.as_str(), "and only one of the two is what the client wrote");
    assert_eq!(open.as_str(), "bytes=0-");
    assert_eq!(overlong.as_str(), "bytes=0-99999");
}

/// Negative — a header this server will not honour keeps its text. The old binding answered `None`
/// here and the bytes were gone with it.
#[test]
fn n_a_header_that_cannot_be_honoured_is_still_quotable() {
    for header in ["items=0-1", "bytes=", "bytes=9-0", "bytes=0-4, bytes=9-9", "bytes=0-1,2-3"] {
        let spec = RangeSpec::new(header);
        assert_eq!(spec.resolve(100), RangeOutcome::Full, "{header:?} is ignored, per RFC 9110 §14.2");
        assert_eq!(spec.as_str(), header, "{header:?} survives the parse that refused it");
    }
}

/// Negative — the source is verbatim, not the parser's tidied reading of it. A `<RangeRequested>`
/// built from a normalised value reports the server's reading back as though it were the request.
#[test]
fn n_the_source_is_not_normalised_on_the_way_through() {
    let spec = RangeSpec::new(" bytes=0-9 ");
    assert_eq!(spec.as_str(), " bytes=0-9 ");
    assert_eq!(
        spec.resolve(100),
        RangeOutcome::Satisfied {
            start: 0,
            end_inclusive: 9
        },
        "the parse still tolerates the whitespace it does not report"
    );
}

/// Positive — the parse reached through the spec is the same parse.
#[test]
fn a_spec_resolves_exactly_as_its_parse_does() {
    let spec = RangeSpec::new("bytes=-5");
    assert_eq!(spec.parsed(), RangeParse::parse("bytes=-5"));
    assert_eq!(spec.resolve(10), RangeParse::parse("bytes=-5").resolve(10));
}

proptest! {
    /// A spec never loses, adds to, or rewrites the bytes it was built from, whatever it parsed to.
    /// Stated as a property because the failure it guards is a silent normalisation that would show
    /// up as exactly one wrong element in exactly one error document.
    #[test]
    fn a_spec_always_returns_the_bytes_it_was_built_from(header in ".{0,40}") {
        let spec = RangeSpec::new(&header);
        prop_assert_eq!(spec.as_str(), header.as_str());
    }
}

proptest! {
    /// A satisfied range is always inside the object and never empty.
    #[test]
    fn a_satisfied_range_stays_inside_the_object(
        first in 0u64..1000,
        last in 0u64..1000,
        len in 1u64..1000,
    ) {
        let header = format!("bytes={first}-{last}");
        let outcome = RangeParse::parse(&header).resolve(len);
        if let RangeOutcome::Satisfied { start, end_inclusive } = outcome {
            prop_assert!(start <= end_inclusive);
            prop_assert!(end_inclusive < len);
            prop_assert_eq!(outcome.content_length(len), end_inclusive - start + 1);
        }
    }

    /// A suffix range never asks for more bytes than the object holds.
    #[test]
    fn a_suffix_range_never_overshoots(length in 0u64..2000, len in 1u64..1000) {
        let outcome = RangeParse::parse(&format!("bytes=-{length}")).resolve(len);
        if let RangeOutcome::Satisfied { start, end_inclusive } = outcome {
            prop_assert_eq!(end_inclusive, len - 1);
            prop_assert!(end_inclusive - start < length.min(len));
        }
    }
}
