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

//! Preconditions and ranges, evaluated once for every operation that accepts them.
//!
//! Shares: precondition, etag, range
//! Members: GetObject, HeadObject, PutObject, CopyObject
//!
//! UploadPartCopy evaluates its copy-source conditions through
//! `copy_source`; CompleteMultipartUpload and DeleteObject accept conditional headers the
//! wire layer parses and nothing yet evaluates. None of them is named above, because
//! `Members:` records the use graph rather than the plan.
//!
//! Responsible for: the fixed order the four conditional headers are evaluated in, the two points
//! where S3 answers differently from RFC 9110, the conditional-write outcomes (412 and the racing
//! 409), and the range decision an operation turns into 200, 206 or 416 — including which response
//! headers a partial read must not carry.
//! NOT responsible for: parsing a `Range` header or resolving one against a length (that is
//! `rustfs-gateway-types`' `RangeParse`), entity-tag comparison ([`super::etag`]), reading any
//! header off the request (the generated decoder), and touching storage: every function here is
//! pure, so the facts it needs arrive as [`ObjectValidators`].
//! Upstream: `rustfs-gateway-types`' `ETag`, `Timestamp`, `RangeParse` and `ErrorCode`, and
//! [`super::etag`]. Downstream: the member operations above.
//!
//! # Why this is a pure function and not a method on a request
//!
//! Precondition evaluation is where a compare-and-swap either holds or is silently lost, and the
//! ways it has been got wrong are not exotic: a condition evaluated *after* the object was already
//! overwritten, a 304 emitted for a write, a 200 where a client was promised a 412. None of those
//! are observable from a unit test that needs a running service. Taking the request's conditions
//! and the object's validators as plain values, and returning a verdict, makes every one of them a
//! table-driven test, a `proptest` property, or a replayed differential — with no store in reach.
//!
//! # The two places S3 does not follow RFC 9110
//!
//! Both are hard-coded here rather than offered as a setting. A switch would not be a choice a
//! caller is qualified to make — S3 compatibility is not a spectrum — and it would double the case
//! matrix for a behaviour no deployment wants configured.
//!
//! | Request | RFC 9110 | S3 |
//! |---|---|---|
//! | `If-Match` matches, `If-Modified-Since` does not | 304 | 200 |
//! | `If-None-Match` does not match, `If-Unmodified-Since` does | 200 | 304 |
//!
//! # What the members declare, and the one thing none of them can
//!
//! `GetObject`, `HeadObject` and `PutObject` `use` this module and declare the facts about
//! themselves that it needs: a `CONDITION_KIND` ([`RequestKind`]) and a `CONDITIONS` list. That is
//! the shape `ops/list_objects.rs` already uses for `shared::pagination` — the operation owns what
//! is constant about it, this module owns the rules — and it is what makes the `Members:` line
//! above checkable against the `use` graph instead of being a claim nothing can test. The
//! remaining four members are still declaration-only.
//!
//! What no member can hold is the call to [`evaluate`]. An `impl Operation` is a static
//! [`crate::registry::OperationSpec`] and a security floor, both settled before a request is read,
//! while a precondition needs the representation the *handler* resolved. So the call site is the
//! backend's — and a backend outside this workspace cannot reach [`evaluate`] at all, because the
//! facade re-exports `ops::shared::copy_source` and nothing else from this directory.
//!
//! That is why the conformance fixture answers `If-Match` out of a private mirror of this file
//! rather than out of this file, and why the mirror disagrees with it on six outcomes. Closing the
//! gap is a facade export plus a backend edit, recorded in `crates/core/MAP.md` under "Open for
//! maintainer review".

use http::StatusCode;
use rustfs_gateway_types::{ETag, ErrorCode, RangeOutcome, RangeParse, Timestamp};

use super::etag::{ConditionalHeader, etag_matches};

/// The facts about the selected representation that a condition is evaluated against.
///
/// This is the whole interface to storage, and it is deliberately three fields wide: an evaluator
/// that could ask a store one more question would be an evaluator that runs before the answer is
/// known, which is the shape of the "condition checked after the write" defect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectValidators {
    /// Whether a representation exists at all.
    pub exists: bool,
    /// Its entity tag, when it has one.
    pub etag: Option<ETag>,
    /// Its last modification instant, truncated to the second the wire can carry.
    pub last_modified: Option<Timestamp>,
}

/// The conditional headers a request carried, already parsed.
///
/// A header that was present but unusable — an `If-Modified-Since` that is not an HTTP-date — must
/// arrive here as `None`. RFC 9110 requires such a field to be ignored, and turning it into a 400
/// breaks clients whose proxy rewrote the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions {
    /// `If-Match`, including the `*` wildcard.
    pub if_match: Option<ETag>,
    /// `If-None-Match`, including the `*` wildcard.
    pub if_none_match: Option<ETag>,
    /// `If-Modified-Since`.
    pub if_modified_since: Option<Timestamp>,
    /// `If-Unmodified-Since`.
    pub if_unmodified_since: Option<Timestamp>,
    /// The instant the server observed, when the caller injects a clock.
    ///
    /// Only one rule reads it: an `If-Modified-Since` in the server's own future is ignored, so a
    /// client with a fast clock is answered with the object rather than with a 304 it cannot use.
    /// `None` disables that rule instead of inventing a time, because nothing in this module is
    /// allowed to read one.
    pub observed_at: Option<Timestamp>,
}

/// Whether the request would read the representation or replace it.
///
/// The distinction decides one thing and decides it everywhere: a failed `If-None-Match` is a 304
/// for a read and a 412 for a write. A write answered with 304 tells a client its object is
/// unchanged when in fact it was never written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// `GET` or `HEAD`.
    Read,
    /// Anything that creates, replaces or removes the representation.
    Write,
}

/// The verdict on a request's preconditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionalOutcome {
    /// Every condition held; carry on with the operation.
    Proceed,
    /// `304`: the client's copy is current. Read requests only.
    NotModified,
    /// `412`: a condition was false.
    PreconditionFailed,
    /// `409`: the condition held when it was evaluated and another writer won the race.
    ///
    /// The framework only names this outcome. Detecting the race is the storage layer's job, and
    /// nothing here can see it — which is precisely why it is a distinct variant rather than a
    /// 412: a client that retries a 409 succeeds, and a client that retries a 412 does not.
    Conflict,
}

/// A conditional or range request the operation must refuse outright.
///
/// Distinct from [`ConditionalOutcome`] because these are malformed requests rather than
/// conditions that turned out false, and they are answered before anything is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionRejection {
    code: ErrorCode,
    reason: &'static str,
}

impl PreconditionRejection {
    /// The S3 error code to render.
    #[must_use]
    pub fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// A constant explanation. Never built from request bytes: a message assembled from the value
    /// that was rejected is a way to echo it back into a log or an error document.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// The status the code maps to.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.code.default_status()
    }
}

impl ConditionalOutcome {
    /// The status this outcome puts on the wire, or `None` when the operation proceeds and chooses
    /// its own.
    #[must_use]
    pub const fn status(self) -> Option<StatusCode> {
        match self {
            Self::Proceed => None,
            Self::NotModified => Some(StatusCode::NOT_MODIFIED),
            Self::PreconditionFailed => Some(StatusCode::PRECONDITION_FAILED),
            Self::Conflict => Some(StatusCode::CONFLICT),
        }
    }

    /// The error code for a failing outcome.
    ///
    /// `304` has none: it is not an error, and rendering an error document into it is what puts a
    /// body on a response that must not have one.
    #[must_use]
    pub fn error_code(self) -> Option<ErrorCode> {
        match self {
            Self::Proceed | Self::NotModified => None,
            Self::PreconditionFailed => Some(ErrorCode::PRECONDITION_FAILED),
            Self::Conflict => Some(ErrorCode::CONDITIONAL_REQUEST_CONFLICT),
        }
    }

    /// Whether the response may carry a body.
    ///
    /// A `304` carries the entity tag and no body at all — no `Content-Length`, no error document.
    /// A client that receives a length it will never be sent bytes for waits for them.
    #[must_use]
    pub const fn body_allowed(self) -> bool {
        !matches!(self, Self::NotModified)
    }
}

/// Evaluates a request's preconditions against the representation it selected.
///
/// The order is fixed — `If-Match`, `If-Unmodified-Since`, `If-None-Match`, `If-Modified-Since` —
/// with the two S3 overrides described in the module documentation applied on top. It never reads
/// a clock, never touches storage, and never allocates.
///
/// # Errors
///
/// Returns a [`PreconditionRejection`] when the request is malformed rather than unsatisfied: today
/// that is `If-Match` and `If-None-Match` sent together, which S3 refuses instead of silently
/// picking one of the two.
pub fn evaluate(
    conditions: &Preconditions,
    validators: &ObjectValidators,
    kind: RequestKind,
) -> Result<ConditionalOutcome, PreconditionRejection> {
    if conditions.if_match.is_some() && conditions.if_none_match.is_some() {
        return Err(PreconditionRejection {
            code: ErrorCode::INVALID_REQUEST,
            reason: "If-Match and If-None-Match cannot be evaluated together",
        });
    }

    if !validators.exists {
        // With no representation, `If-Match` is false for every value including `*`, and
        // `If-None-Match` is true for every value including `*` — which is what makes
        // `If-None-Match: *` the create-if-absent primitive.
        if conditions.if_match.is_some() {
            return Ok(ConditionalOutcome::PreconditionFailed);
        }
        return Ok(ConditionalOutcome::Proceed);
    }

    // Step 1: If-Match.
    let if_match_hit = match (&conditions.if_match, &validators.etag) {
        (None, _) => false,
        // `*` is a condition on the representation, not on its entity tag, and the existence check
        // above already answered it. A backend that reports no entity tag — because it has not
        // digested the object, or because the representation has none — must not turn `If-Match: *`
        // into a 412 for a resource that is plainly there. A *named* tag still fails: there is
        // nothing to compare it against.
        (Some(requested), None) => {
            if !requested.is_any() {
                return Ok(ConditionalOutcome::PreconditionFailed);
            }
            true
        }
        (Some(requested), Some(current)) => {
            let comparison = ConditionalHeader::IfMatch.comparison();
            if !etag_matches(comparison, requested, current) {
                return Ok(ConditionalOutcome::PreconditionFailed);
            }
            true
        }
    };

    // Step 2: If-Unmodified-Since, evaluated only when If-Match was absent.
    let unmodified_since_hit = if if_match_hit {
        false
    } else {
        match (conditions.if_unmodified_since, validators.last_modified) {
            (Some(bound), Some(modified)) => {
                if modified > bound {
                    return Ok(ConditionalOutcome::PreconditionFailed);
                }
                true
            }
            (Some(_), None) => return Ok(ConditionalOutcome::PreconditionFailed),
            (None, _) => false,
        }
    };

    // Step 3: If-None-Match.
    if let Some(requested) = &conditions.if_none_match {
        let comparison = ConditionalHeader::IfNoneMatch.comparison();
        // The same wildcard rule as step 1, and here it is the load-bearing one: `If-None-Match: *`
        // is the create-if-absent primitive, so a representation that exists must fail it whether
        // or not the backend reported an entity tag. Reading `*` through the tag would let a
        // conditional create silently overwrite exactly the objects a backend cannot digest.
        let hit = requested.is_any()
            || validators
                .etag
                .as_ref()
                .is_some_and(|current| etag_matches(comparison, requested, current));
        if hit {
            return Ok(match kind {
                RequestKind::Read => ConditionalOutcome::NotModified,
                RequestKind::Write => ConditionalOutcome::PreconditionFailed,
            });
        }
        // S3 deviation: a missed `If-None-Match` alongside a satisfied `If-Unmodified-Since` is a
        // 304, where RFC 9110 would serve the representation.
        if unmodified_since_hit && kind == RequestKind::Read {
            return Ok(ConditionalOutcome::NotModified);
        }
        return Ok(ConditionalOutcome::Proceed);
    }

    // Step 4: If-Modified-Since. Reads only — RFC 9110 requires the field to be ignored on any
    // other method, and S3 skips it entirely once `If-Match` has matched.
    if kind == RequestKind::Read
        && !if_match_hit
        && let Some(bound) = conditions.if_modified_since
        && !is_in_the_future(bound, conditions.observed_at)
        && let Some(modified) = validators.last_modified
        && modified <= bound
    {
        return Ok(ConditionalOutcome::NotModified);
    }

    Ok(ConditionalOutcome::Proceed)
}

/// Whether a client-supplied instant lies after the instant the server observed.
fn is_in_the_future(bound: Timestamp, observed_at: Option<Timestamp>) -> bool {
    observed_at.is_some_and(|now| bound > now)
}

/// What a request asked for on the range axis, before it meets the object's length.
#[derive(Debug, Clone, Copy, Default)]
pub struct RangeSelectors<'a> {
    /// The raw `Range` header value, or `x-amz-copy-source-range` for a part copy.
    pub range: Option<&'a str>,
    /// The `partNumber` query parameter.
    pub part_number: Option<u32>,
    /// `If-Range`, which turns a range request into a whole-object request when it does not match.
    pub if_range: Option<&'a IfRange>,
}

/// The `If-Range` validator, in whichever of its two forms the client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfRange {
    /// An entity tag. Compared strongly: a weak validator cannot promise that the bytes either
    /// side of the range are from the same representation.
    Tag(ETag),
    /// An HTTP-date.
    Date(Timestamp),
}

/// What an operation should serve for a range request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeDecision {
    /// `200` with the whole object. Also the answer to a multi-range request, to an unparseable
    /// `Range`, and to an `If-Range` that did not match.
    Whole,
    /// `206` with `start..=end_inclusive` of an object of `total` bytes.
    Partial {
        /// First byte to send, inclusive.
        start: u64,
        /// Last byte to send, inclusive.
        end_inclusive: u64,
        /// The object's full length, which `Content-Range` reports.
        total: u64,
    },
    /// The request selected one part of a multipart object by `partNumber`.
    ///
    /// This variant is the *selector*, not a resolved window: [`evaluate_range`] is given the
    /// object's total length and nothing about where its parts begin and end, so it cannot say
    /// which bytes the part covers or how many parts there are. The operation resolves it against
    /// the part table and supplies `Content-Range` and `x-amz-mp-parts-count` itself.
    ///
    /// Until it does, [`RangeDecision::status`] answers `206` while
    /// [`RangeDecision::content_range`] answers `None`, and a `206` without a `Content-Range` is
    /// not a response RFC 9110 §15.3.7 allows. Recorded in `crates/core/MAP.md` under "Open for
    /// maintainer review" rather than papered over here: completing it changes this variant's
    /// shape, which is a contract decision and not a fix.
    Part {
        /// The requested part.
        part_number: u32,
    },
    /// `416`, with the two extra elements the S3 error document carries.
    Unsatisfiable {
        /// The object's real length.
        actual_object_size: u64,
        /// The range the client asked for, echoed back verbatim.
        range_requested: String,
    },
}

impl RangeDecision {
    /// The status this decision puts on the wire.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Whole => StatusCode::OK,
            Self::Partial { .. } | Self::Part { .. } => StatusCode::PARTIAL_CONTENT,
            Self::Unsatisfiable { .. } => StatusCode::RANGE_NOT_SATISFIABLE,
        }
    }

    /// The `Content-Range` value, or `None` when the response carries no such header.
    #[must_use]
    pub fn content_range(&self) -> Option<String> {
        match self {
            Self::Whole | Self::Part { .. } => None,
            Self::Partial {
                start,
                end_inclusive,
                total,
            } => RangeOutcome::Satisfied {
                start: *start,
                end_inclusive: *end_inclusive,
            }
            .content_range(*total),
            Self::Unsatisfiable { actual_object_size, .. } => RangeOutcome::Unsatisfiable {
                actual: *actual_object_size,
            }
            .content_range(*actual_object_size),
        }
    }

    /// The number of bytes the response body will carry, for an object of `object_len` bytes.
    ///
    /// A satisfied range is `end - start + 1` bytes. The off-by-one in the other direction is what
    /// makes a ranged copy declare one byte fewer than it sends, and the client sees a truncated
    /// object rather than an error.
    #[must_use]
    pub const fn content_length(&self, object_len: u64) -> u64 {
        match self {
            Self::Whole | Self::Part { .. } => object_len,
            Self::Partial {
                start, end_inclusive, ..
            } => end_inclusive.saturating_sub(*start).saturating_add(1),
            Self::Unsatisfiable { .. } => 0,
        }
    }

    /// Whether the encoder must drop the whole-object `x-amz-checksum-*` headers.
    ///
    /// A partial read that advertises the checksum of the *entire* object hands an SDK a digest
    /// that cannot match the bytes it received, and the SDKs that verify checksums by default then
    /// fail every ranged download. Only a checksum computed over what is actually being sent may
    /// travel with a 206.
    #[must_use]
    pub const fn suppresses_object_checksum(&self) -> bool {
        matches!(self, Self::Partial { .. } | Self::Part { .. })
    }
}

/// Decides what to serve for a request's range selectors.
///
/// `validators` is used for `If-Range` only; the object's length is passed separately because a
/// `HEAD` knows it without having a representation in hand.
///
/// # Errors
///
/// Returns a [`PreconditionRejection`] when `Range` and `partNumber` are sent together. They select
/// overlapping byte spans by two different mechanisms and S3 answers neither.
pub fn evaluate_range(
    selectors: &RangeSelectors<'_>,
    validators: &ObjectValidators,
    object_len: u64,
) -> Result<RangeDecision, PreconditionRejection> {
    if selectors.range.is_some() && selectors.part_number.is_some() {
        return Err(PreconditionRejection {
            code: ErrorCode::INVALID_REQUEST,
            reason: "Range and partNumber select bytes by two mechanisms and cannot be combined",
        });
    }

    if let Some(part_number) = selectors.part_number {
        return Ok(RangeDecision::Part { part_number });
    }

    let Some(header) = selectors.range else {
        return Ok(RangeDecision::Whole);
    };

    // `If-Range` is a switch, not a condition: when it does not match, the range is dropped and
    // the whole object is served with a 200. It never produces an error of its own.
    if let Some(if_range) = selectors.if_range
        && !if_range_matches(if_range, validators)
    {
        return Ok(RangeDecision::Whole);
    }

    Ok(match RangeParse::parse(header).resolve(object_len) {
        RangeOutcome::Full => RangeDecision::Whole,
        RangeOutcome::Satisfied { start, end_inclusive } => RangeDecision::Partial {
            start,
            end_inclusive,
            total: object_len,
        },
        RangeOutcome::Unsatisfiable { actual } => RangeDecision::Unsatisfiable {
            actual_object_size: actual,
            range_requested: header.trim().to_owned(),
        },
    })
}

/// Whether an `If-Range` validator still describes the selected representation.
fn if_range_matches(if_range: &IfRange, validators: &ObjectValidators) -> bool {
    match if_range {
        IfRange::Tag(requested) => validators
            .etag
            .as_ref()
            .is_some_and(|current| etag_matches(ConditionalHeader::IfMatch.comparison(), requested, current)),
        IfRange::Date(bound) => validators.last_modified.is_some_and(|modified| modified <= *bound),
    }
}

/// The wildcard against a representation whose entity tag the backend did not report.
///
/// `crates/core/tests/precondition_range.rs` covers the table with an entity tag in hand; these
/// six live here because they are about the one input shape [`ObjectValidators`] allows and that
/// table never builds — `exists: true` with `etag: None`, which is what a backend answers for a
/// representation it has not digested. `*` is defined against the *representation*, so it must not
/// change its mind when the tag is missing, and two of the six pin that a *named* tag does not
/// inherit the widening.
#[cfg(test)]
mod wildcard_without_an_entity_tag {
    use super::{ConditionalOutcome, ObjectValidators, Preconditions, RequestKind, evaluate};
    use rustfs_gateway_types::{ETag, Timestamp};

    /// A representation that exists and reports no entity tag.
    fn untagged() -> ObjectValidators {
        ObjectValidators {
            exists: true,
            etag: None,
            last_modified: None,
        }
    }

    /// A tag that names a value rather than the wildcard.
    ///
    /// `unwrap_or_default` and not `expect`: this crate denies `clippy::expect_used` in every
    /// module, test modules included. The fallback is the empty *strong* tag, which is still a
    /// named tag — the only property the two tests below ask of it.
    fn named() -> ETag {
        ETag::new("E1").unwrap_or_default()
    }

    #[test]
    fn if_none_match_wildcard_still_refuses_the_write() {
        let conditions = Preconditions {
            if_none_match: Some(ETag::ANY),
            ..Preconditions::default()
        };
        assert_eq!(
            evaluate(&conditions, &untagged(), RequestKind::Write),
            Ok(ConditionalOutcome::PreconditionFailed),
            "create-if-absent guards the key, not the entity tag; proceeding here overwrites the \
             object the client asked us not to touch"
        );
    }

    #[test]
    fn if_none_match_wildcard_still_answers_a_read_with_304() {
        let conditions = Preconditions {
            if_none_match: Some(ETag::ANY),
            ..Preconditions::default()
        };
        assert_eq!(evaluate(&conditions, &untagged(), RequestKind::Read), Ok(ConditionalOutcome::NotModified));
    }

    #[test]
    fn a_named_if_none_match_still_misses() {
        let conditions = Preconditions {
            if_none_match: Some(named()),
            ..Preconditions::default()
        };
        assert_eq!(
            evaluate(&conditions, &untagged(), RequestKind::Read),
            Ok(ConditionalOutcome::Proceed),
            "a named tag has nothing to compare against, and the wildcard rule must not widen to it"
        );
    }

    #[test]
    fn if_match_wildcard_holds_against_the_representation() {
        let conditions = Preconditions {
            if_match: Some(ETag::ANY),
            ..Preconditions::default()
        };
        assert_eq!(
            evaluate(&conditions, &untagged(), RequestKind::Write),
            Ok(ConditionalOutcome::Proceed),
            "`*` asks whether a representation exists, and one does"
        );
    }

    #[test]
    fn a_named_if_match_still_fails() {
        let conditions = Preconditions {
            if_match: Some(named()),
            ..Preconditions::default()
        };
        assert_eq!(
            evaluate(&conditions, &untagged(), RequestKind::Write),
            Ok(ConditionalOutcome::PreconditionFailed)
        );
    }

    #[test]
    fn a_matching_if_match_wildcard_still_suppresses_if_modified_since() {
        let conditions = Preconditions {
            if_match: Some(ETag::ANY),
            if_modified_since: Some(Timestamp::from_secs(0)),
            ..Preconditions::default()
        };
        assert_eq!(
            evaluate(&conditions, &untagged(), RequestKind::Read),
            Ok(ConditionalOutcome::Proceed),
            "the S3 deviation keys off a satisfied If-Match, whichever form satisfied it"
        );
    }
}
