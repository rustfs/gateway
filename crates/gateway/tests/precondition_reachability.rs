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

//! Every argument of the precondition contract, built out of a decoded request and nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call* [`evaluate`] — not
//! that it is exported, which `facade_probe.rs` already covers, but that each of its arguments
//! (a [`Preconditions`], an [`ObjectValidators`] and a [`RequestKind`]) can be produced from what a
//! request actually hands a handler, for both a read (`GetObject`) and a write (`PutObject`), and
//! that the [`FailedCondition`] a `412` names survives a second, unrelated conditional header
//! riding along on the same request. NOT responsible for: what the rules decide, which is
//! `rustfs-gateway-core`'s `tests/precondition_range.rs`, or the range half of the same contract,
//! which `backend_reachability.rs` already covers.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15 found `evaluate_range` exported and uncallable, and left the rest of the surface open
//! with the acceptance bar: **every argument of every exported constructor must be constructible
//! from `Req<O>` alone.** `evaluate` was never checked against that bar. Its four inputs —
//! `if_match`, `if_none_match`, `if_modified_since`, `if_unmodified_since` — are wire strings on the
//! decoded `GetObjectInput`/`PutObjectInput`, not the typed `ETag`/`Timestamp` the contract wants,
//! so a backend has to reach `parse_conditional_etag` to bridge the gap. Nothing proved that bridge
//! compiles and answers correctly until this file.

use bytes::Bytes;
use rustfs_gateway::{
    ByteStream, ConditionalOutcome, ETag, FailedCondition, HandlerError, Limits, MetaView, ObjectValidators, OperationCodec,
    Preconditions, RequestBody, RequestKind, TargetKind, Timestamp, TimestampFormat, WireRequest, dto, evaluate,
    parse_conditional_etag,
};

/// A request as it reaches a decoder, with whatever header lines the case needs.
fn accepted(method: &'static str, headers: &[(&'static str, &'static str)]) -> WireRequest<()> {
    let mut request = http::Request::builder()
        .method(method)
        .uri("http://host.invalid/conf-precondition/hello")
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

/// What a backend has after decoding a conditional `GET` — the only thing the read cases below are
/// allowed to read.
fn decoded_get(headers: &[(&'static str, &'static str)]) -> dto::GetObjectInput {
    let request = accepted("GET", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::GetObject::decode(&view, RequestBody::None).expect("a conditional read is not a refusal")
}

/// What a backend has after decoding a conditional `PUT` — `PutObject` carries only the two
/// entity-tag conditions, matching real S3: there is no date-based conditional write.
fn decoded_put(headers: &[(&'static str, &'static str)]) -> dto::PutObjectInput {
    let mut all_headers = vec![("content-length", "0")];
    all_headers.extend_from_slice(headers);
    let request = accepted("PUT", &all_headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::PutObject::decode(&view, RequestBody::Stream(ByteStream::from_bytes(Bytes::new())))
        .expect("a conditional write is not a refusal")
}

/// The bridge a backend has to write itself: the contract wants a typed [`ETag`], the decoded
/// input only ever carries the wire string.
///
/// # Errors
///
/// A value the entity-tag grammar cannot carry, so a guard the server ignores does not become a
/// compare-and-swap the client believes it made.
fn tag_condition(raw: Option<&str>) -> Result<Option<ETag>, HandlerError> {
    let Some(raw) = raw else { return Ok(None) };
    parse_conditional_etag(raw)
        .map(Some)
        .map_err(|_| HandlerError::new(rustfs_gateway::ErrorCode::INVALID_ARGUMENT, "The ETag value provided is not valid."))
}

fn date(value: &str) -> Timestamp {
    Timestamp::parse(value, TimestampFormat::HttpDate).expect("a test date is a valid HTTP-date by construction")
}

const LAST_MODIFIED: &str = "Fri, 02 Jan 2026 03:04:05 GMT";
const CURRENT_ETAG: &str = "\"781e5e245d69b566979b86e28d23f2c7\"";
const STALE_ETAG: &str = "\"0000000000000000000000000000dead\"";

/// The object every case below evaluates its conditions against.
fn current_object() -> ObjectValidators {
    ObjectValidators {
        exists: true,
        etag: ETag::new("781e5e245d69b566979b86e28d23f2c7").ok(),
        last_modified: Some(date(LAST_MODIFIED)),
    }
}

// ---------------------------------------------------------------------------------------------
// Reads: RequestKind::Read, GetObject
// ---------------------------------------------------------------------------------------------

/// Negative — a stale `If-Match` on a read is a `412` naming itself, reached entirely from the
/// wire string the decoder handed back.
#[test]
fn n_a_stale_if_match_on_a_read_names_itself() {
    let input = decoded_get(&[("if-match", STALE_ETAG)]);
    let conditions = Preconditions {
        if_match: tag_condition(input.if_match.as_deref()).expect("a quoted tag parses"),
        if_none_match: tag_condition(input.if_none_match.as_deref()).expect("absent"),
        if_modified_since: input.if_modified_since,
        if_unmodified_since: input.if_unmodified_since,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &current_object(), RequestKind::Read).expect("a well-formed condition set");
    assert_eq!(outcome, ConditionalOutcome::PreconditionFailed(Some(FailedCondition::IfMatch)));
}

/// Negative — the case #445 fixed: a failed `If-Unmodified-Since` names itself even when a second,
/// unrelated conditional header rode along on the same request. Evaluation order is `If-Match`,
/// then `If-Unmodified-Since`, then `If-None-Match`/`If-Modified-Since` — so the request below must
/// stop at the second header and never reach the third, which also would have failed had it been
/// evaluated.
#[test]
fn n_a_failed_if_unmodified_since_names_itself_even_with_an_unrelated_condition_present() {
    let input = decoded_get(&[
        ("if-unmodified-since", "Thu, 01 Jan 2026 00:00:00 GMT"),
        ("if-none-match", STALE_ETAG),
    ]);
    let conditions = Preconditions {
        if_match: tag_condition(input.if_match.as_deref()).expect("absent"),
        if_none_match: tag_condition(input.if_none_match.as_deref()).expect("a quoted tag parses"),
        if_modified_since: input.if_modified_since,
        if_unmodified_since: input.if_unmodified_since,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &current_object(), RequestKind::Read).expect("a well-formed condition set");
    assert_eq!(
        outcome,
        ConditionalOutcome::PreconditionFailed(Some(FailedCondition::IfUnmodifiedSince)),
        "the unrelated If-None-Match must not be the header the 412 blames"
    );
}

/// Negative — a failed `If-None-Match` on a read is a `304`, not a `412`: the read branch of
/// `ConditionalOutcome` a backend must be able to reach, not just the write branch.
#[test]
fn n_a_current_if_none_match_on_a_read_is_not_modified() {
    let input = decoded_get(&[("if-none-match", CURRENT_ETAG)]);
    let conditions = Preconditions {
        if_match: tag_condition(input.if_match.as_deref()).expect("absent"),
        if_none_match: tag_condition(input.if_none_match.as_deref()).expect("a quoted tag parses"),
        if_modified_since: input.if_modified_since,
        if_unmodified_since: input.if_unmodified_since,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &current_object(), RequestKind::Read).expect("a well-formed condition set");
    assert_eq!(outcome, ConditionalOutcome::NotModified);
}

/// Negative — an entity tag the grammar cannot carry is a `400`, reached from the same decoded
/// string the passing cases use: the refusal path is exported and callable, not just the success
/// path.
#[test]
fn n_a_malformed_if_match_on_a_read_is_refused_not_silently_dropped() {
    let input = decoded_get(&[("if-match", "not, a, valid, list")]);
    let result = tag_condition(input.if_match.as_deref());
    assert!(result.is_err(), "a list-form If-Match is not a single entity tag");
}

/// Positive — the ordinary read still resolves, from the same wire string.
#[test]
fn a_matching_if_match_on_a_read_proceeds() {
    let input = decoded_get(&[("if-match", CURRENT_ETAG)]);
    let conditions = Preconditions {
        if_match: tag_condition(input.if_match.as_deref()).expect("a quoted tag parses"),
        if_none_match: tag_condition(input.if_none_match.as_deref()).expect("absent"),
        if_modified_since: input.if_modified_since,
        if_unmodified_since: input.if_unmodified_since,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &current_object(), RequestKind::Read).expect("a well-formed condition set");
    assert_eq!(outcome, ConditionalOutcome::Proceed);
}

// ---------------------------------------------------------------------------------------------
// Writes: RequestKind::Write, PutObject — no date conditions exist on this DTO at all
// ---------------------------------------------------------------------------------------------

/// Negative — `If-None-Match: *` against an object that already exists is a `412` on a write,
/// reached from `PutObjectInput`, which the range contract never exercises.
#[test]
fn n_an_if_none_match_star_on_a_write_of_an_existing_object_names_itself() {
    let input = decoded_put(&[("if-none-match", "*")]);
    let conditions = Preconditions {
        if_match: tag_condition(input.if_match.as_deref()).expect("absent"),
        if_none_match: tag_condition(input.if_none_match.as_deref()).expect("the wildcard parses"),
        if_modified_since: None,
        if_unmodified_since: None,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &current_object(), RequestKind::Write).expect("a well-formed condition set");
    assert_eq!(outcome, ConditionalOutcome::PreconditionFailed(Some(FailedCondition::IfNoneMatch)));
}

/// Positive — a matching `If-Match` on a write proceeds, reached from `PutObjectInput` alone.
#[test]
fn a_matching_if_match_on_a_write_proceeds() {
    let input = decoded_put(&[("if-match", CURRENT_ETAG)]);
    let conditions = Preconditions {
        if_match: tag_condition(input.if_match.as_deref()).expect("a quoted tag parses"),
        if_none_match: tag_condition(input.if_none_match.as_deref()).expect("absent"),
        if_modified_since: None,
        if_unmodified_since: None,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &current_object(), RequestKind::Write).expect("a well-formed condition set");
    assert_eq!(outcome, ConditionalOutcome::Proceed);
}
