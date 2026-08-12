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

//! The precondition and range contract, asserted as a pure function.
//!
//! Responsible for: every conditional outcome the object and copy families depend on, the two
//! points where S3 answers differently from RFC 9110, and the range decision including the
//! boundaries a fuzzer would find — 17 positive and 27 negative tests, plus three properties.
//! NOT responsible for: the wire binding, which reaches these values through the generated
//! decoder, and the storage race behind `Conflict`, which no pure function can observe.
//! Upstream: `rustfs_gateway_core::ops::shared`. Downstream: nothing.

use http::{Method, StatusCode};
use proptest::prelude::*;
use rustfs_gateway_core::ops::shared::etag::{ConditionalHeader, EtagComparison, etag_matches, parse_conditional_etag};
use rustfs_gateway_core::ops::shared::precondition::{
    ConditionalOutcome, IfRange, ObjectValidators, Preconditions, RangeDecision, RangeSelectors, RequestKind, evaluate,
    evaluate_range,
};
use rustfs_gateway_core::{BodyAllowance, body_allowance};
use rustfs_gateway_types::{ETag, ErrorCode, Timestamp, TimestampFormat};

fn tag(value: &'static str) -> ETag {
    ETag::new(value).expect("a test entity tag is well formed by construction")
}

fn weak_tag(value: &'static str) -> ETag {
    ETag::new_weak(value).expect("a test entity tag is well formed by construction")
}

fn at(value: &str) -> Timestamp {
    Timestamp::parse(value, TimestampFormat::HttpDate).expect("a test date is a valid HTTP-date by construction")
}

/// An object of `len` bytes with entity tag `E1`, modified on the fixed test date.
fn present() -> ObjectValidators {
    ObjectValidators {
        exists: true,
        etag: Some(tag("E1")),
        last_modified: Some(at("Fri, 02 Jan 2026 03:04:05 GMT")),
    }
}

fn absent() -> ObjectValidators {
    ObjectValidators::default()
}

// ── If-Match ────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_matching_if_match_proceeds() {
    let conditions = Preconditions {
        if_match: Some(tag("E1")),
        ..Preconditions::default()
    };
    assert_eq!(evaluate(&conditions, &present(), RequestKind::Read), Ok(ConditionalOutcome::Proceed));
}

#[test]
fn quoting_never_decides_a_match() {
    // The stored tag is bare and the header quoted, or the other way round. A comparison over
    // `String` gets this wrong in both directions, and clients that send the bare form are common
    // enough that the failure looks like "conditional requests are broken", not like a quoting bug.
    let quoted = parse_conditional_etag("\"E1\"").expect("quoted form parses");
    let bare = parse_conditional_etag("E1").expect("bare form parses");
    assert!(etag_matches(EtagComparison::Strong, &quoted, &tag("E1")));
    assert!(etag_matches(EtagComparison::Strong, &bare, &tag("E1")));
    assert!(etag_matches(EtagComparison::Strong, &quoted, &bare));
}

#[test]
fn a_bare_copy_source_entity_tag_is_not_a_bad_request() {
    let parsed = parse_conditional_etag("abc123").expect("SDKs send this form and it must be accepted");
    assert_eq!(parsed.opaque_tag(), "abc123");
    assert!(etag_matches(ConditionalHeader::CopySourceIfMatch.comparison(), &parsed, &tag("abc123")));
}

#[test]
fn a_failing_if_match_is_a_412_and_not_a_404() {
    let conditions = Preconditions {
        if_match: Some(tag("E2")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Write),
        Ok(ConditionalOutcome::PreconditionFailed)
    );
}

#[test]
fn if_match_against_a_missing_object_always_fails() {
    for requested in [tag("E1"), ETag::ANY] {
        let conditions = Preconditions {
            if_match: Some(requested),
            ..Preconditions::default()
        };
        assert_eq!(
            evaluate(&conditions, &absent(), RequestKind::Write),
            Ok(ConditionalOutcome::PreconditionFailed),
            "with no representation there is nothing for If-Match to match, wildcard included"
        );
    }
}

#[test]
fn a_weak_stored_tag_never_satisfies_if_match() {
    let validators = ObjectValidators {
        etag: Some(weak_tag("E1")),
        ..present()
    };
    let conditions = Preconditions {
        if_match: Some(tag("E1")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &validators, RequestKind::Write),
        Ok(ConditionalOutcome::PreconditionFailed),
        "If-Match is a compare-and-swap guard, and a weak validator cannot carry that promise"
    );
}

#[test]
fn an_object_with_no_entity_tag_fails_if_match() {
    let validators = ObjectValidators {
        exists: true,
        etag: None,
        last_modified: None,
    };
    let conditions = Preconditions {
        if_match: Some(tag("E1")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &validators, RequestKind::Read),
        Ok(ConditionalOutcome::PreconditionFailed)
    );
}

// ── If-None-Match ───────────────────────────────────────────────────────────────────────────

#[test]
fn if_none_match_wildcard_on_a_missing_object_proceeds() {
    // The create-if-absent primitive. A wildcard that failed to parse would turn every
    // conditional create into a 400, which is the regression this case pins.
    let conditions = Preconditions {
        if_none_match: Some(parse_conditional_etag("*").expect("the wildcard is a value, not a malformed tag")),
        ..Preconditions::default()
    };
    assert!(conditions.if_none_match.as_ref().is_some_and(ETag::is_any));
    assert_eq!(evaluate(&conditions, &absent(), RequestKind::Write), Ok(ConditionalOutcome::Proceed));
}

#[test]
fn if_none_match_wildcard_on_an_existing_object_is_a_412() {
    let conditions = Preconditions {
        if_none_match: Some(ETag::ANY),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Write),
        Ok(ConditionalOutcome::PreconditionFailed),
        "whoever loses the compare-and-create must be told the key was taken, not that the write succeeded"
    );
}

#[test]
fn a_matching_if_none_match_read_is_a_304_with_no_body() {
    let conditions = Preconditions {
        if_none_match: Some(tag("E1")),
        ..Preconditions::default()
    };
    let outcome = evaluate(&conditions, &present(), RequestKind::Read).expect("well-formed request");
    assert_eq!(outcome, ConditionalOutcome::NotModified);
    assert_eq!(outcome.status(), Some(StatusCode::NOT_MODIFIED));
    assert_eq!(
        body_allowance(&Method::GET, outcome.status().expect("the not-modified outcome has a status")),
        BodyAllowance::Bodyless,
        "a 304 carries no body and no Content-Length"
    );
    assert_eq!(outcome.error_code(), None, "a 304 is not an error and carries no error document");
}

#[test]
fn a_weak_request_tag_still_revalidates() {
    // `W/"E1"` against a strong `"E1"`: If-None-Match uses weak comparison, so this is a 304.
    let conditions = Preconditions {
        if_none_match: Some(weak_tag("E1")),
        ..Preconditions::default()
    };
    assert_eq!(evaluate(&conditions, &present(), RequestKind::Read), Ok(ConditionalOutcome::NotModified));
}

#[test]
fn a_matching_if_none_match_write_is_a_412_and_never_a_304() {
    let conditions = Preconditions {
        if_none_match: Some(tag("E1")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Write),
        Ok(ConditionalOutcome::PreconditionFailed),
        "a 304 on a write tells the client its object is unchanged when it was never written"
    );
}

// ── date conditions ─────────────────────────────────────────────────────────────────────────

#[test]
fn an_if_modified_since_before_the_object_serves_it() {
    let conditions = Preconditions {
        if_modified_since: Some(at("Thu, 01 Jan 2026 00:00:00 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(evaluate(&conditions, &present(), RequestKind::Read), Ok(ConditionalOutcome::Proceed));
}

#[test]
fn an_if_unmodified_since_after_the_object_serves_it() {
    let conditions = Preconditions {
        if_unmodified_since: Some(at("Sun, 01 Feb 2026 00:00:00 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(evaluate(&conditions, &present(), RequestKind::Read), Ok(ConditionalOutcome::Proceed));
}

#[test]
fn the_second_boundary_is_decided_the_same_way_every_time() {
    // Equality at the second is the case a replay has to reproduce, so it is pinned in both
    // directions rather than left to whichever comparison operator was typed.
    let same = at("Fri, 02 Jan 2026 03:04:05 GMT");
    let modified_since = Preconditions {
        if_modified_since: Some(same),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&modified_since, &present(), RequestKind::Read),
        Ok(ConditionalOutcome::NotModified),
        "not modified *since* an instant equal to the last modification"
    );
    let unmodified_since = Preconditions {
        if_unmodified_since: Some(same),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&unmodified_since, &present(), RequestKind::Write),
        Ok(ConditionalOutcome::Proceed),
        "unmodified since an instant equal to the last modification"
    );
}

#[test]
fn an_if_unmodified_since_before_the_object_is_a_412() {
    let conditions = Preconditions {
        if_unmodified_since: Some(at("Thu, 01 Jan 2026 00:00:00 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Write),
        Ok(ConditionalOutcome::PreconditionFailed)
    );
}

#[test]
fn an_if_modified_since_in_the_future_is_ignored() {
    let conditions = Preconditions {
        if_modified_since: Some(at("Sun, 01 Feb 2026 00:00:00 GMT")),
        observed_at: Some(at("Fri, 02 Jan 2026 03:04:05 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Read),
        Ok(ConditionalOutcome::Proceed),
        "a client whose clock runs fast must still receive the object, not a 304 it cannot use"
    );
}

#[test]
fn a_date_condition_is_not_evaluated_on_a_write() {
    // If-Modified-Since applies to GET and HEAD only; a write that honoured it would answer 304.
    let conditions = Preconditions {
        if_modified_since: Some(at("Fri, 02 Jan 2026 03:04:05 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(evaluate(&conditions, &present(), RequestKind::Write), Ok(ConditionalOutcome::Proceed));
}

// ── the two S3 deviations from RFC 9110 ─────────────────────────────────────────────────────

#[test]
fn a_matching_if_match_overrides_a_failing_if_modified_since() {
    let conditions = Preconditions {
        if_match: Some(tag("E1")),
        if_modified_since: Some(at("Fri, 02 Jan 2026 03:04:05 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Read),
        Ok(ConditionalOutcome::Proceed),
        "RFC 9110 would answer 304 here; S3 answers 200, and clients are written against S3"
    );
}

#[test]
fn a_missed_if_none_match_with_a_satisfied_if_unmodified_since_is_a_304() {
    let conditions = Preconditions {
        if_none_match: Some(tag("E2")),
        if_unmodified_since: Some(at("Sun, 01 Feb 2026 00:00:00 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Read),
        Ok(ConditionalOutcome::NotModified),
        "RFC 9110 would serve the representation here; S3 answers 304"
    );
}

#[test]
fn the_second_deviation_does_not_leak_into_writes() {
    let conditions = Preconditions {
        if_none_match: Some(tag("E2")),
        if_unmodified_since: Some(at("Sun, 01 Feb 2026 00:00:00 GMT")),
        ..Preconditions::default()
    };
    assert_eq!(
        evaluate(&conditions, &present(), RequestKind::Write),
        Ok(ConditionalOutcome::Proceed),
        "a write is never answered with 304, whichever read deviation would have applied"
    );
}

// ── malformed conditional requests ──────────────────────────────────────────────────────────

#[test]
fn the_two_entity_tag_conditions_cannot_be_sent_together() {
    let conditions = Preconditions {
        if_match: Some(tag("E1")),
        if_none_match: Some(ETag::ANY),
        ..Preconditions::default()
    };
    let rejection = evaluate(&conditions, &present(), RequestKind::Write).expect_err("S3 refuses the combination");
    assert_eq!(rejection.code(), &ErrorCode::INVALID_REQUEST);
    assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
    assert!(!rejection.reason().is_empty());
}

#[test]
fn a_repeated_entity_tag_header_is_refused_rather_than_reduced() {
    // Two values arrive joined by the field-value comma rule. Taking the first would let a client
    // that sent two different conditions believe the one it cared about was evaluated.
    for value in ["\"E1\", \"E2\"", "E1,E2", "*, \"E1\""] {
        assert!(
            parse_conditional_etag(value).is_err(),
            "{value} carries more than one entity tag and must not be silently reduced"
        );
    }
}

#[test]
fn a_malformed_entity_tag_is_a_parse_error_and_not_a_panic() {
    for value in ["\"unterminated", "unopened\"", "", "\"", "W/", "\"\""] {
        assert!(parse_conditional_etag(value).is_err(), "{value} is not an entity tag");
    }
}

#[test]
fn conditional_outcomes_carry_the_status_and_code_the_client_branches_on() {
    assert_eq!(ConditionalOutcome::Proceed.status(), None);
    assert_eq!(ConditionalOutcome::PreconditionFailed.error_code(), Some(ErrorCode::PRECONDITION_FAILED));
    assert_eq!(ConditionalOutcome::PreconditionFailed.status(), Some(StatusCode::PRECONDITION_FAILED));
    let conflict = ConditionalOutcome::Conflict;
    assert_eq!(conflict.status(), Some(StatusCode::CONFLICT));
    assert_eq!(conflict.error_code(), Some(ErrorCode::CONDITIONAL_REQUEST_CONFLICT));
    assert_eq!(
        conflict.error_code().map(|code| code.default_status()),
        Some(StatusCode::CONFLICT),
        "the racing conditional write is a retryable 409, not a 412 the client will give up on"
    );
    assert_eq!(
        body_allowance(&Method::PUT, conflict.status().expect("the conflict outcome has a status")),
        BodyAllowance::Content
    );
}

// ── ranges ──────────────────────────────────────────────────────────────────────────────────

fn ranged(header: &str, object_len: u64) -> RangeDecision {
    evaluate_range(
        &RangeSelectors {
            range: Some(header),
            ..RangeSelectors::default()
        },
        &present(),
        object_len,
    )
    .expect("a lone Range header is never a rejection")
}

#[test]
fn a_satisfied_range_is_a_206_with_a_content_range() {
    let decision = ranged("bytes=0-4", 10);
    assert_eq!(
        decision,
        RangeDecision::Partial {
            start: 0,
            end_inclusive: 4,
            total: 10
        }
    );
    assert_eq!(decision.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(decision.content_range().as_deref(), Some("bytes 0-4/10"));
    assert_eq!(decision.content_length(10), 5, "the length is end - start + 1");
}

#[test]
fn a_range_running_past_the_end_is_clamped_and_not_refused() {
    let decision = ranged("bytes=5-100", 10);
    assert_eq!(decision.content_range().as_deref(), Some("bytes 5-9/10"));
    assert_eq!(decision.content_length(10), 5);
    assert_eq!(
        decision.status(),
        StatusCode::PARTIAL_CONTENT,
        "resumable downloads routinely ask for more than is there; refusing them breaks resume"
    );
}

#[test]
fn the_suffix_form_returns_the_last_bytes() {
    let decision = ranged("bytes=-5", 10);
    assert_eq!(decision.content_range().as_deref(), Some("bytes 5-9/10"));
    assert_eq!(decision.content_length(10), 5);
}

#[test]
fn the_open_ended_form_runs_to_the_end() {
    let decision = ranged("bytes=3-", 10);
    assert_eq!(decision.content_range().as_deref(), Some("bytes 3-9/10"));
    assert_eq!(decision.content_length(10), 7);
}

#[test]
fn a_suffix_longer_than_the_object_yields_the_whole_object_as_a_206() {
    let decision = ranged("bytes=-100", 10);
    assert_eq!(decision.content_range().as_deref(), Some("bytes 0-9/10"));
    assert_eq!(decision.content_length(10), 10);
    assert_eq!(decision.status(), StatusCode::PARTIAL_CONTENT);
}

#[test]
fn a_ten_byte_copy_source_range_declares_ten_bytes() {
    // `bytes=0-9` is ten bytes. Declaring nine is the classic off-by-one, and the client sees a
    // truncated object rather than an error.
    assert_eq!(ranged("bytes=0-9", 20).content_length(20), 10);
}

#[test]
fn a_part_number_read_is_a_206_without_a_content_range() {
    let decision = evaluate_range(
        &RangeSelectors {
            part_number: Some(2),
            ..RangeSelectors::default()
        },
        &present(),
        10,
    )
    .expect("partNumber alone is well formed");
    assert_eq!(decision, RangeDecision::Part { part_number: 2 });
    assert_eq!(decision.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(decision.content_range(), None);
}

#[test]
fn a_multi_range_request_is_answered_with_the_whole_object() {
    let decision = ranged("bytes=0-1,5-6", 10);
    assert_eq!(
        decision,
        RangeDecision::Whole,
        "S3 does not implement multipart/byteranges; it is neither a 206 nor a 416"
    );
    assert_eq!(decision.status(), StatusCode::OK);
    assert_eq!(decision.content_range(), None);
}

#[test]
fn a_range_starting_past_the_end_is_a_416_that_reports_the_real_size() {
    let decision = ranged("bytes=20-30", 10);
    assert_eq!(
        decision,
        RangeDecision::Unsatisfiable {
            actual_object_size: 10,
            range_requested: "bytes=20-30".to_owned()
        }
    );
    assert_eq!(decision.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(decision.content_range().as_deref(), Some("bytes */10"));
    assert_eq!(decision.content_length(10), 0);
}

#[test]
fn an_unusable_range_header_is_ignored_and_never_panics() {
    for header in [
        "bytes=abc",
        "",
        "items=0-1",
        "bytes=",
        "bytes=-",
        "bytes=1-2-3",
        "bytes=0-1,,",
    ] {
        assert_eq!(
            ranged(header, 10),
            RangeDecision::Whole,
            "{header} is not a usable range, and RFC 9110 says to ignore it rather than fail"
        );
    }
}

#[test]
fn a_descending_range_is_ignored_rather_than_answered() {
    assert_eq!(
        ranged("bytes=5-3", 10),
        RangeDecision::Whole,
        "start greater than end is syntactically valid and semantically empty; one behaviour, pinned"
    );
}

#[test]
fn the_u64_boundary_neither_overflows_nor_panics() {
    assert_eq!(
        ranged("bytes=0-18446744073709551615", 10),
        RangeDecision::Partial {
            start: 0,
            end_inclusive: 9,
            total: 10
        }
    );
    assert_eq!(ranged("bytes=18446744073709551615-", 10).status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(ranged("bytes=-18446744073709551615", 10).content_length(10), 10);
    assert_eq!(
        ranged("bytes=0-18446744073709551616", 10),
        RangeDecision::Whole,
        "a value beyond u64 is not a range at all, so it is ignored"
    );
}

#[test]
fn every_range_of_an_empty_object_is_unsatisfiable() {
    for header in ["bytes=0-0", "bytes=0-", "bytes=-1"] {
        assert_eq!(
            ranged(header, 0),
            RangeDecision::Unsatisfiable {
                actual_object_size: 0,
                range_requested: header.to_owned()
            },
            "{header} against a zero-byte object"
        );
    }
}

#[test]
fn range_and_part_number_together_are_refused() {
    let rejection = evaluate_range(
        &RangeSelectors {
            range: Some("bytes=0-4"),
            part_number: Some(1),
            if_range: None,
        },
        &present(),
        10,
    )
    .expect_err("the two select bytes by different mechanisms");
    assert_eq!(rejection.code(), &ErrorCode::INVALID_REQUEST);
    assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_partial_read_suppresses_the_whole_object_checksum() {
    assert!(ranged("bytes=0-4", 10).suppresses_object_checksum());
    assert!(RangeDecision::Part { part_number: 1 }.suppresses_object_checksum());
    assert!(
        !RangeDecision::Whole.suppresses_object_checksum(),
        "a full read still carries the object's checksum; suppressing it there breaks verification"
    );
    assert!(
        !RangeDecision::Unsatisfiable {
            actual_object_size: 10,
            range_requested: "bytes=20-30".to_owned()
        }
        .suppresses_object_checksum()
    );
}

#[test]
fn a_repeated_range_header_serves_the_whole_object() {
    // Two `Range` headers arrive joined by a comma, which is not a range set S3 can parse. The
    // outcome is fixed as the whole object so that no ambiguity survives into the response.
    assert_eq!(ranged("bytes=0-4, bytes=9-10", 20), RangeDecision::Whole);
}

// ── If-Range ────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_matching_if_range_keeps_the_range() {
    let if_range = IfRange::Tag(tag("E1"));
    let decision = evaluate_range(
        &RangeSelectors {
            range: Some("bytes=0-4"),
            part_number: None,
            if_range: Some(&if_range),
        },
        &present(),
        10,
    )
    .expect("well-formed request");
    assert_eq!(decision.status(), StatusCode::PARTIAL_CONTENT);
}

#[test]
fn a_stale_if_range_drops_the_range_and_serves_the_whole_object() {
    for if_range in [IfRange::Tag(tag("E2")), IfRange::Date(at("Thu, 01 Jan 2026 00:00:00 GMT"))] {
        let decision = evaluate_range(
            &RangeSelectors {
                range: Some("bytes=0-4"),
                part_number: None,
                if_range: Some(&if_range),
            },
            &present(),
            10,
        )
        .expect("If-Range is a switch and never an error");
        assert_eq!(
            decision,
            RangeDecision::Whole,
            "a client resuming against a changed object must be sent the new object, not a slice of it"
        );
    }
}

#[test]
fn a_weak_if_range_tag_never_keeps_the_range() {
    let if_range = IfRange::Tag(weak_tag("E1"));
    let decision = evaluate_range(
        &RangeSelectors {
            range: Some("bytes=0-4"),
            part_number: None,
            if_range: Some(&if_range),
        },
        &present(),
        10,
    )
    .expect("If-Range is a switch and never an error");
    assert_eq!(
        decision,
        RangeDecision::Whole,
        "a weak validator cannot promise the bytes on both sides of the range came from one representation"
    );
}

// ── If-Range, read off the wire ──────────────────────────────────────────────────────────────
//
// `IfRange::parse` is the grammar a backend would otherwise write for itself, and it is total on
// purpose: a fallible one hands a caller an `Option` whose `None` is indistinguishable from "the
// client sent no If-Range", which honours the range against a representation nobody checked.

/// Positive — the two forms RFC 9110 §13.1.5 defines, told apart by their first characters.
#[test]
fn the_two_if_range_forms_are_read_as_themselves() {
    assert_eq!(IfRange::parse("\"E1\""), IfRange::Tag(tag("E1")));
    assert_eq!(
        IfRange::parse("Thu, 01 Jan 2026 00:00:00 GMT"),
        IfRange::Date(at("Thu, 01 Jan 2026 00:00:00 GMT"))
    );
    assert_eq!(
        IfRange::parse("  \"E1\"  "),
        IfRange::Tag(tag("E1")),
        "surrounding whitespace is not part of the tag"
    );
}

/// Negative — a validator that is neither form reads as `Unrecognised`, and `Unrecognised` drops
/// the range. Every entry here would otherwise be a resumed download spliced out of two objects.
#[test]
fn n_an_unreadable_if_range_drops_the_range_instead_of_honouring_it() {
    for value in [
        "",
        "garbage",
        "\"unterminated",
        "W/",
        "Thu, 99 Xxx 2026 00:00:00 GMT",
        "*",
        "\"E1\", \"E2\"",
    ] {
        let if_range = IfRange::parse(value);
        assert_eq!(if_range, IfRange::Unrecognised, "{value:?} is not a validator");
        let decision = evaluate_range(
            &RangeSelectors {
                range: Some("bytes=0-4"),
                part_number: None,
                if_range: Some(&if_range),
            },
            &present(),
            10,
        )
        .expect("If-Range is a switch and never an error");
        assert_eq!(decision, RangeDecision::Whole, "{value:?} must not be allowed to confirm anything");
    }
}

/// Negative — a weak tag survives the parse and loses at the comparison, not at the grammar.
/// Refusing it in the parser would make `W/"E1"` and a typo indistinguishable to anyone reading a
/// trace, and it is the comparison that has the reason.
#[test]
fn n_a_weak_if_range_tag_parses_and_then_loses() {
    let if_range = IfRange::parse("W/\"E1\"");
    assert_eq!(if_range, IfRange::Tag(weak_tag("E1")));
    let decision = evaluate_range(
        &RangeSelectors {
            range: Some("bytes=0-4"),
            part_number: None,
            if_range: Some(&if_range),
        },
        &present(),
        10,
    )
    .expect("If-Range is a switch and never an error");
    assert_eq!(decision, RangeDecision::Whole);
}

// ── properties ──────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the header and the length, a 206 names a span that is inside the object.
    #[test]
    fn a_partial_range_always_lies_inside_the_object(header in "[a-z=,0-9-]{0,24}", total in 0u64..1_000_000) {
        let decision = evaluate_range(
            &RangeSelectors { range: Some(header.as_str()), ..RangeSelectors::default() },
            &ObjectValidators::default(),
            total,
        ).expect("a lone Range header is never a rejection");
        if let RangeDecision::Partial { start, end_inclusive, total: reported } = decision {
            prop_assert!(start <= end_inclusive, "{header}: {start} > {end_inclusive}");
            prop_assert!(end_inclusive < total, "{header}: {end_inclusive} is outside {total} bytes");
            prop_assert_eq!(reported, total);
            prop_assert_eq!(
                decision.content_length(total),
                end_inclusive - start + 1,
                "the served length is end - start + 1"
            );
        }
    }

    /// A well-formed byte range never produces a rejection, and never a 416 for a satisfiable span.
    #[test]
    fn a_range_inside_the_object_is_always_satisfiable(start in 0u64..1000, extra in 0u64..1000, total in 1u64..1000) {
        prop_assume!(start < total);
        let header = format!("bytes={start}-{}", start.saturating_add(extra));
        let decision = evaluate_range(
            &RangeSelectors { range: Some(header.as_str()), ..RangeSelectors::default() },
            &ObjectValidators::default(),
            total,
        ).expect("a lone Range header is never a rejection");
        prop_assert_eq!(decision.status(), StatusCode::PARTIAL_CONTENT, "{}", header);
    }

    /// Evaluation is total: no combination of conditions panics, and a write is never a 304.
    #[test]
    fn evaluation_is_total_and_never_answers_a_write_with_304(
        has_match in any::<bool>(),
        has_none_match in any::<bool>(),
        has_ims in any::<bool>(),
        has_ius in any::<bool>(),
        exists in any::<bool>(),
        matching in any::<bool>(),
    ) {
        let conditions = Preconditions {
            if_match: has_match.then(|| if matching { tag("E1") } else { tag("E2") }),
            if_none_match: has_none_match.then(|| if matching { tag("E1") } else { ETag::ANY }),
            if_modified_since: has_ims.then(|| at("Fri, 02 Jan 2026 03:04:05 GMT")),
            if_unmodified_since: has_ius.then(|| at("Fri, 02 Jan 2026 03:04:05 GMT")),
            observed_at: None,
        };
        let validators = if exists { present() } else { absent() };
        if let Ok(outcome) = evaluate(&conditions, &validators, RequestKind::Write) {
            prop_assert_ne!(outcome, ConditionalOutcome::NotModified);
        }
        let _ = evaluate(&conditions, &validators, RequestKind::Read);
    }
}
