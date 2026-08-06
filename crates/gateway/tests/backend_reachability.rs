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

//! Every argument of the range contract, built out of a decoded request and nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call* the range contract —
//! not that the contract is exported, which `facade_probe.rs` already covers, but that each
//! argument of each exported entry point can be produced from what a request actually hands it.
//! NOT responsible for: what the rules decide, which is `rustfs-gateway-core`'s
//! `tests/precondition_range.rs`, or assembling a service, which is `tests/pipeline.rs`.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Because a contract can be exported, documented, reachable by `grep` — and still impossible to
//! invoke, and nothing in this repository noticed. `HandlerError::unsatisfiable_range(requested,
//! len)` shipped with `requested` meaning "the `Range` header as it arrived"; the codec had parsed
//! that header into a value with no way back to its own bytes, so the first argument could only
//! ever be supplied by a literal. `evaluate_range` took an `IfRange` no DTO declared, so its third
//! selector could only ever be `None`. Both read correctly in review. Both failed the only test
//! that matters, which is trying to make the call (issue #15, issue #17).
//!
//! So the rule this file enforces: **every argument comes from the request.** Nothing below is
//! allowed to spell a wire value as a literal — the header text, the validator, the length all
//! arrive through `decode`. An argument that cannot be reached that way is the defect, and it
//! shows up here as code that does not compile rather than as a case that stays red.

use rustfs_gateway::{
    ETag, ErrorDetail, HandlerError, IfRange, Limits, MetaView, ObjectValidators, OperationCodec, RangeDecision, RangeSelectors,
    RequestBody, TargetKind, Timestamp, WireRequest, dto, evaluate_range,
};

/// A request as it reaches a decoder, with whatever header lines the case needs.
///
/// Repeated names are appended rather than replaced: two `Range` lines is a shape the wire allows
/// and one of the cases below is about.
fn accepted(headers: &[(&'static str, &'static str)]) -> WireRequest<()> {
    let mut request = http::Request::builder()
        .method("GET")
        .uri("http://host.invalid/conf-range/ten")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    for (name, value) in headers {
        request
            .headers_mut()
            .append(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// What a backend has after `decode`, and the only thing these cases are allowed to read.
fn decoded(headers: &[(&'static str, &'static str)]) -> dto::GetObjectInput {
    let request = accepted(headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::GetObject::decode(&view, RequestBody::None).expect("a range request is not a refusal")
}

/// The selectors, assembled the way a backend assembles them: out of the input, in two lines.
///
/// This function *is* the assertion. It compiles only while every selector can be reached from a
/// decoded request; the `Option<&IfRange>` in particular has to borrow from something the caller
/// owns, which is why the validator is threaded through rather than built inside.
/// `RangeSpec` is not named anywhere below, and could not be: the facade does not re-export it.
/// A backend does not need the name — it has the value, and the value answers.
fn selectors<'a>(input: &'a dto::GetObjectInput, if_range: &'a Option<IfRange>) -> RangeSelectors<'a> {
    RangeSelectors {
        range: input.range.as_ref().map(|range| range.as_str()),
        part_number: None,
        if_range: if_range.as_ref(),
    }
}

/// The validator a backend reads off the input. Total, so there is no `None` to flatten into
/// "the client sent no `If-Range`".
fn validator(input: &dto::GetObjectInput) -> Option<IfRange> {
    input.if_range.as_deref().map(IfRange::parse)
}

/// A ten-byte object whose entity tag is the one `c-range-0018` sends.
fn ten_bytes() -> ObjectValidators {
    ObjectValidators {
        exists: true,
        etag: ETag::new("781e5e245d69b566979b86e28d23f2c7").ok(),
        last_modified: Some(Timestamp::from_secs(1_767_322_445)),
    }
}

/// The `<RangeRequested>` element of a refusal, or `None` when it carries none.
fn quoted_range(error: &HandlerError) -> Option<String> {
    error.details().iter().find_map(|detail| match detail {
        ErrorDetail::RangeRequested(text) => Some(text.as_ref().to_owned()),
        _ => None,
    })
}

// ---------------------------------------------------------------------------------------------
// The four arguments
// ---------------------------------------------------------------------------------------------

/// Negative — the case the API was written for, and the one that could not be made.
///
/// `bytes=20-30` against ten bytes is unsatisfiable, and the refusal has to quote the header. The
/// text is taken from the decision, which took it from the input, which took it from the wire: no
/// step re-spells it. `c-range-0010` asserts the resulting document byte for byte.
#[test]
fn n_an_unsatisfiable_range_quotes_the_header_it_was_given() {
    let input = decoded(&[("range", "bytes=20-30")]);
    let if_range = validator(&input);
    let decision = evaluate_range(&selectors(&input, &if_range), &ten_bytes(), 10).expect("well-formed request");

    let RangeDecision::Unsatisfiable {
        actual_object_size,
        range_requested,
    } = decision
    else {
        panic!("a range past the end of a ten-byte object is unsatisfiable");
    };
    assert_eq!(range_requested, "bytes=20-30");

    let error = HandlerError::unsatisfiable_range(range_requested, actual_object_size);
    assert_eq!(quoted_range(&error), Some("bytes=20-30".to_owned()));
}

/// Negative — the pair that proves the text is carried and not derived.
///
/// Both headers are unsatisfiable against ten bytes and both resolve to the same outcome, so a
/// server reconstructing the element from the parse would answer them identically. Only one of the
/// two is what each client wrote.
#[test]
fn n_two_unsatisfiable_spellings_are_quoted_apart() {
    let mut quoted = Vec::new();
    for header in ["bytes=20-", "bytes=20-99999"] {
        let request = accepted(&[("range", header)]);
        let view = MetaView::of(&request, TargetKind::Object).expect("view");
        let input = dto::GetObject::decode(&view, RequestBody::None).expect("decodes");
        let if_range = validator(&input);
        let decision = evaluate_range(&selectors(&input, &if_range), &ten_bytes(), 10).expect("well-formed request");
        let RangeDecision::Unsatisfiable { range_requested, .. } = decision else {
            panic!("{header} starts past the end of a ten-byte object");
        };
        quoted.push(range_requested);
    }
    assert_eq!(quoted, vec!["bytes=20-".to_owned(), "bytes=20-99999".to_owned()]);
}

/// Negative — a stale `If-Range` drops the range, reached from the header rather than from a value
/// the test built. This is the selector no DTO declared, so this call could not be made at all.
/// `c-range-0018` is the case.
#[test]
fn n_a_stale_if_range_read_off_the_wire_drops_the_range() {
    let input = decoded(&[("range", "bytes=0-4"), ("if-range", "\"0000000000000000000000000000dead\"")]);
    let if_range = validator(&input);
    assert!(if_range.is_some(), "the header arrived, so the selector is populated");
    let decision = evaluate_range(&selectors(&input, &if_range), &ten_bytes(), 10).expect("If-Range is never an error");
    assert_eq!(
        decision,
        RangeDecision::Whole,
        "a resumed download must get the new object, not a slice of it"
    );
}

/// Negative — an `If-Range` this server cannot read also drops the range. The failure mode of a
/// fallible parse is the opposite one, and it is silent.
#[test]
fn n_an_unreadable_if_range_read_off_the_wire_also_drops_the_range() {
    let input = decoded(&[("range", "bytes=0-4"), ("if-range", "not-a-validator")]);
    let if_range = validator(&input);
    assert_eq!(if_range, Some(IfRange::Unrecognised));
    let decision = evaluate_range(&selectors(&input, &if_range), &ten_bytes(), 10).expect("If-Range is never an error");
    assert_eq!(decision, RangeDecision::Whole);
}

/// Negative — two `Range` lines reach the decoder joined, and the join is served as the whole
/// object. Acceptance used to refuse the pair with a 400, so no backend was asked (`c-range-0017`).
#[test]
fn n_two_range_lines_reach_the_backend_and_serve_the_whole_object() {
    let input = decoded(&[("range", "bytes=0-4"), ("range", "bytes=9-9")]);
    let range = input.range.as_ref().expect("the header arrived");
    assert_eq!(range.as_str(), "bytes=0-4, bytes=9-9", "RFC 9110 §5.3 joins the field lines");

    let if_range = validator(&input);
    let decision = evaluate_range(&selectors(&input, &if_range), &ten_bytes(), 10).expect("well-formed request");
    assert_eq!(decision, RangeDecision::Whole);
    assert_eq!(decision.content_range(), None, "and no Content-Range travels with a 200");
}

/// Positive — the ordinary path still resolves, from the same two lines.
#[test]
fn a_matching_if_range_keeps_the_range_it_was_sent() {
    let input = decoded(&[("range", "bytes=0-4"), ("if-range", "\"781e5e245d69b566979b86e28d23f2c7\"")]);
    let if_range = validator(&input);
    let decision = evaluate_range(&selectors(&input, &if_range), &ten_bytes(), 10).expect("well-formed request");
    assert_eq!(
        decision,
        RangeDecision::Partial {
            start: 0,
            end_inclusive: 4,
            total: 10
        }
    );
    assert_eq!(decision.content_range().as_deref(), Some("bytes 0-4/10"));
}
