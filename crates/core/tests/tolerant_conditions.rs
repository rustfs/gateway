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

//! The one header family this codec is required to ignore rather than refuse.
//!
//! Responsible for: RFC 9110 §13.1.3 and §13.1.4 over the two date conditions and the two read
//! operations, and over the two copy-source date conditions of CopyObject and UploadPartCopy —
//! that an unreadable value drops the condition and does not fail the decode, that a readable one
//! still binds, and that the tolerance did not spread to a member that must stay strict.
//! NOT responsible for: how a bound condition is then evaluated (`tests/precondition_range.rs`).
//! Upstream: the generated codecs. Downstream: nothing.
//!
//! # What "ignored" has to mean, and why it is not `None`
//!
//! Absence and unreadability produce the same *response* here — that is the requirement. They must
//! not produce the same *value* on the way there, because `Option::None` meaning both is the
//! defect the `Range` binding was rewritten to remove (`if-range`, issue #15). So the decoder
//! reads into `DateCondition`, which names the second case, and `honoured()` is the single site
//! that collapses it.
//!
//! 4 positive / 12 negative.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use http::Request;
use rustfs_gateway_core::codec::value::{DateCondition, date_condition};
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{TimestampFormat, dto};

/// Values a client, a proxy or a log copy-and-paste actually produces, none of which is an
/// HTTP-date.
const NOT_DATES: &[&str] = &[
    "not-a-date",
    "",
    "0",
    "2026-01-02T03:04:05Z",
    "Fri, 02 Jan 2026 03:04:05",
    "Xri, 02 Jan 2026 03:04:05 GMT",
    "Fri, 32 Jan 2026 03:04:05 GMT",
    "\u{4e2d}\u{6587}",
    // What JavaScript's `new Date(undefined).toString()` renders, and what minio-js 8 sends.
    "Invalid Date",
];

/// One valid HTTP-date, in the spelling the fixture clock uses.
const A_DATE: &str = "Fri, 02 Jan 2026 03:04:05 GMT";

fn accepted(method: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri("http://host.invalid/conf-cond/dates/garbage")
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn get(headers: &[(&str, &str)]) -> dto::GetObjectInput {
    let request = accepted("GET", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::GetObject::decode(&view, RequestBody::None).expect("a date condition never fails a decode")
}

fn head(headers: &[(&str, &str)]) -> dto::HeadObjectInput {
    let request = accepted("HEAD", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::HeadObject::decode(&view, RequestBody::None).expect("a date condition never fails a decode")
}

// ---------------------------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------------------------

/// Negative — no unreadable `If-Modified-Since` fails the decode, and every one of them drops the
/// condition.
///
/// This is `c-cond-0020` at the codec, over eight spellings instead of one: the case pins
/// `not-a-date`, and a decoder that special-cased that string would satisfy it.
#[test]
fn no_unreadable_modified_since_refuses_the_request() {
    for spelling in NOT_DATES {
        let input = get(&[("if-modified-since", spelling)]);
        assert!(input.if_modified_since.is_none(), "{spelling:?} bound a condition it cannot have meant");
    }
}

/// Negative — the same for `If-Unmodified-Since`, which RFC 9110 §13.1.4 states separately.
///
/// Separately asserted because the two conditions are separate members with separate quirk
/// references: attaching the tolerance to one and not the other compiles and passes every
/// modified-since assertion above.
#[test]
fn no_unreadable_unmodified_since_refuses_the_request() {
    for spelling in NOT_DATES {
        let input = get(&[("if-unmodified-since", spelling)]);
        assert!(input.if_unmodified_since.is_none(), "{spelling:?}");
    }
}

/// Negative — a HEAD answers as its GET does.
///
/// `head_mirrors` derives the response headers and nothing about the request, so the two request
/// surfaces can drift. One header with two answers decided by the method is worse than either
/// answer.
#[test]
fn a_head_is_no_stricter_than_the_get_beside_it() {
    for spelling in NOT_DATES {
        let input = head(&[("if-modified-since", spelling), ("if-unmodified-since", spelling)]);
        assert!(input.if_modified_since.is_none(), "{spelling:?}");
        assert!(input.if_unmodified_since.is_none(), "{spelling:?}");
    }
}

/// Negative — an unreadable condition beside a readable one drops only itself.
///
/// A tolerance implemented by abandoning the whole conditional block would pass every assertion
/// above and silently serve a request whose `If-Match` should have refused it.
#[test]
fn an_unreadable_date_does_not_drop_the_conditions_beside_it() {
    let input = get(&[
        ("if-modified-since", "not-a-date"),
        ("if-unmodified-since", A_DATE),
        ("if-match", "\"0000000000000000000000000000dead\""),
    ]);
    assert!(input.if_modified_since.is_none());
    assert!(input.if_unmodified_since.is_some(), "a readable sibling still binds");
    assert!(input.if_match.is_some(), "an entity-tag condition is not a date condition");
}

/// Negative — the tolerance did not spread to a member that is not a condition.
///
/// `ResponseExpires` is an override the caller asked for, bound to the same `HttpDate` format. A
/// tolerance keyed on the *type* rather than on the overlay's quirk would have swallowed a
/// malformed one and served a response the caller did not ask for.
#[test]
fn a_response_override_is_still_refused_when_it_is_not_a_date() {
    let request = Request::builder()
        .method("GET")
        .uri("http://host.invalid/conf-cond/dates/garbage?response-expires=not-a-date")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("acceptable");
    let view = MetaView::of(&accepted, TargetKind::Object).expect("the path has both labels");
    dto::GetObject::decode(&view, RequestBody::None).expect_err("a response override is not a condition");
}

/// An entity-tag condition remains present for the operation parser when its spelling is invalid.
///
/// The neighbouring member has the same optionality. If the emitter applied date tolerance by
/// binding rather than by quirk, it could drop this value before the operation saw it.
#[test]
fn an_entity_tag_condition_reaches_the_operation_parser_unchanged() {
    let request = accepted("GET", &[("if-match", "\"unterminated")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    let input = dto::GetObject::decode(&view, RequestBody::None).expect("the operation parser owns the entity-tag grammar");
    assert_eq!(input.if_match.as_deref(), Some("\"unterminated"));
}

/// Positive — a readable date still binds, on both members.
///
/// Without this the tolerance could be implemented by dropping every date, and every negative
/// assertion above would still pass.
#[test]
fn a_readable_date_still_binds() {
    let input = get(&[("if-modified-since", A_DATE), ("if-unmodified-since", A_DATE)]);
    assert!(input.if_modified_since.is_some());
    assert!(input.if_unmodified_since.is_some());
}

// ---------------------------------------------------------------------------------------------
// The shape, and the `if-range` defect it exists to avoid repeating
// ---------------------------------------------------------------------------------------------

/// Negative — the reader never loses the fact that a header arrived.
///
/// `honoured()` collapses the two cases; the value before it does not. That is the whole
/// difference between this and the binding that used to erase an unhonoured `Range`.
#[test]
fn an_unreadable_date_is_a_named_state_and_not_an_absence() {
    for spelling in NOT_DATES {
        let read = date_condition(spelling, TimestampFormat::HttpDate);
        assert_eq!(read, DateCondition::Unreadable, "{spelling:?}");
        assert!(read.was_unreadable(), "{spelling:?}");
        assert!(read.honoured().is_none(), "{spelling:?}");
    }
}

/// Negative — the collapse happens in exactly one place, and it is not the parse.
///
/// A readable date is not `Unreadable`, and an unreadable one is not silently a timestamp of zero
/// — which is the other way this could have been "tolerant" and would have made every request
/// unconditionally not-modified.
#[test]
fn a_readable_date_is_not_reported_as_unreadable() {
    let read = date_condition(A_DATE, TimestampFormat::HttpDate);
    assert!(!read.was_unreadable());
    assert!(matches!(read, DateCondition::At(_)));
    assert!(read.honoured().is_some());
}

/// Negative — the format the binding declares is still enforced.
///
/// Tolerance is about what happens when a value fails its format, not about accepting any format.
/// An ISO-8601 timestamp is a perfectly good date and is still not an HTTP-date.
#[test]
fn tolerance_is_not_a_second_accepted_format() {
    assert_eq!(
        date_condition("2026-01-02T03:04:05Z", TimestampFormat::HttpDate),
        DateCondition::Unreadable
    );
    assert!(matches!(
        date_condition("2026-01-02T03:04:05Z", TimestampFormat::Iso8601),
        DateCondition::At(_)
    ));
}

/// Positive — the two values a caller can reach are the two the type declares, and the readable
/// one carries the parse rather than a re-derived one.
#[test]
fn the_two_states_round_trip() {
    let readable = date_condition(A_DATE, TimestampFormat::HttpDate);
    let stamp = readable.honoured().expect("a readable date");
    assert_eq!(DateCondition::At(stamp), readable);
}

/// Positive — the generated decode reads the same function this file tests directly, so the two
/// halves cannot drift.
#[test]
fn the_generated_decode_and_the_shared_reader_agree() {
    for spelling in NOT_DATES.iter().chain(std::iter::once(&A_DATE)) {
        let through_codec = get(&[("if-modified-since", spelling)]).if_modified_since;
        let directly = date_condition(spelling, TimestampFormat::HttpDate).honoured();
        assert_eq!(through_codec, directly, "{spelling:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// The copy family: the same two conditions, evaluated against the source object
// ---------------------------------------------------------------------------------------------

const COPY_SOURCE: (&str, &str) = ("x-amz-copy-source", "/conf-copy/src/plain.txt");

fn copy_request(uri: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("host", "host.invalid")
        .header(COPY_SOURCE.0, COPY_SOURCE.1);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn copy(headers: &[(&str, &str)]) -> dto::CopyObjectInput {
    let request = copy_request("http://host.invalid/conf-copy/dst/key", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::CopyObject::decode(&view, RequestBody::None).expect("a copy-source date condition never fails a decode")
}

fn part_copy(headers: &[(&str, &str)]) -> dto::UploadPartCopyInput {
    let request = copy_request("http://host.invalid/conf-copy/dst/key?partNumber=1&uploadId=upload", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::UploadPartCopy::decode(&view, RequestBody::None).expect("a copy-source date condition never fails a decode")
}

/// Negative — no unreadable copy-source date refuses a CopyObject, on either member.
///
/// minio-js 8 sends `x-amz-copy-source-if-unmodified-since: Invalid Date` from its functional
/// suite; that request is the reason this test exists (rustfs/gateway#764).
#[test]
fn no_unreadable_copy_source_date_refuses_a_copy() {
    for spelling in NOT_DATES {
        let input = copy(&[
            ("x-amz-copy-source-if-modified-since", spelling),
            ("x-amz-copy-source-if-unmodified-since", spelling),
        ]);
        assert!(input.copy_source_if_modified_since.is_none(), "{spelling:?}");
        assert!(input.copy_source_if_unmodified_since.is_none(), "{spelling:?}");
    }
}

/// Negative — each member separately, so a tolerance attached to one of them alone goes red.
#[test]
fn each_copy_source_date_is_tolerant_on_its_own() {
    for header in ["x-amz-copy-source-if-modified-since", "x-amz-copy-source-if-unmodified-since"] {
        let input = copy(&[(header, "Invalid Date")]);
        assert!(input.copy_source_if_modified_since.is_none(), "{header}");
        assert!(input.copy_source_if_unmodified_since.is_none(), "{header}");
    }
}

/// Negative — UploadPartCopy shares the four copy-source conditions, and is no stricter.
#[test]
fn no_unreadable_copy_source_date_refuses_a_part_copy() {
    for spelling in NOT_DATES {
        for header in ["x-amz-copy-source-if-modified-since", "x-amz-copy-source-if-unmodified-since"] {
            let input = part_copy(&[(header, spelling)]);
            assert!(input.copy_source_if_modified_since.is_none(), "{header} {spelling:?}");
            assert!(input.copy_source_if_unmodified_since.is_none(), "{header} {spelling:?}");
        }
    }
}

/// Negative — an unreadable copy-source date drops only itself: a readable sibling and the
/// copy-source entity-tag condition still reach the operation.
#[test]
fn an_unreadable_copy_source_date_does_not_drop_the_conditions_beside_it() {
    let input = copy(&[
        ("x-amz-copy-source-if-modified-since", "Invalid Date"),
        ("x-amz-copy-source-if-unmodified-since", A_DATE),
        ("x-amz-copy-source-if-match", "\"0000000000000000000000000000dead\""),
    ]);
    assert!(input.copy_source_if_modified_since.is_none());
    assert!(input.copy_source_if_unmodified_since.is_some(), "a readable sibling still binds");
    assert!(input.copy_source_if_match.is_some(), "an entity-tag condition is not a date condition");
}

/// Positive — a readable copy-source date still binds on both operations and both members, so
/// the tolerance cannot be implemented by dropping every copy-source date.
#[test]
fn a_readable_copy_source_date_still_binds() {
    let dates = [
        ("x-amz-copy-source-if-modified-since", A_DATE),
        ("x-amz-copy-source-if-unmodified-since", A_DATE),
    ];
    let whole = copy(&dates);
    assert!(whole.copy_source_if_modified_since.is_some());
    assert!(whole.copy_source_if_unmodified_since.is_some());
    let part = part_copy(&dates);
    assert!(part.copy_source_if_modified_since.is_some());
    assert!(part.copy_source_if_unmodified_since.is_some());
}
