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

//! RFC 9110 conditional requests for `GetObject`, `HeadObject` and `PutObject` (rustfs/gateway#808).
//!
//! Responsible for: turning the request's `If-Match`, `If-None-Match`, `If-Modified-Since` and
//! `If-Unmodified-Since` into the contract's [`Preconditions`], and turning the contract's verdict
//! against the selected representation — or against its absence — into this backend's answer.
//! NOT responsible for: the evaluation order or the verdicts themselves (`rustfs-gateway`'s
//! `evaluate`), selecting the representation (`super::reads`), the write itself
//! (`super::versioning`), or CopyObject's copy-source conditions (`super::copy`).
//! Upstream: `rustfs-gateway`'s precondition contract. Downstream: `super::reads`,
//! `super::versioning`.

use rustfs_gateway::{
    ConditionalOutcome, ETag, ErrorCode, FailedCondition, HandlerError, ObjectValidators, PRECONDITION_FAILED_MESSAGE,
    Preconditions, RequestKind, Timestamp, evaluate, parse_conditional_etag,
};

use super::reads::Representation;

fn conditional_etag(value: Option<&str>) -> Result<Option<ETag>, HandlerError> {
    value
        .map(parse_conditional_etag)
        .transpose()
        .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "The ETag value provided is not valid."))
}

/// The request's conditions. `observed_at` is this server's clock, which only the rule that ignores
/// an `If-Modified-Since` in the server's own future reads.
pub(super) fn conditions(
    if_match: Option<&str>,
    if_unmodified_since: Option<Timestamp>,
    if_none_match: Option<&str>,
    if_modified_since: Option<Timestamp>,
    observed_at: Timestamp,
) -> Result<Preconditions, HandlerError> {
    Ok(Preconditions {
        if_match: conditional_etag(if_match)?,
        if_none_match: conditional_etag(if_none_match)?,
        if_modified_since,
        if_unmodified_since,
        observed_at: Some(observed_at),
    })
}

/// Whether the request carries any condition at all, so an unconditional request pays nothing.
pub(super) const fn any(conditions: &Preconditions) -> bool {
    conditions.if_match.is_some()
        || conditions.if_none_match.is_some()
        || conditions.if_modified_since.is_some()
        || conditions.if_unmodified_since.is_some()
}

fn validators(selected: Option<&Representation>) -> ObjectValidators {
    match selected {
        None => ObjectValidators::default(),
        Some(representation) => ObjectValidators {
            exists: true,
            etag: Some(representation.e_tag.clone()),
            last_modified: Some(representation.last_modified),
        },
    }
}

fn precondition_failed(failed: Option<FailedCondition>) -> HandlerError {
    match failed {
        Some(failed) => HandlerError::precondition_failed(failed.as_str()),
        None => HandlerError::new(ErrorCode::PRECONDITION_FAILED, PRECONDITION_FAILED_MESSAGE),
    }
}

fn conflict() -> HandlerError {
    HandlerError::new(
        ErrorCode::CONDITIONAL_REQUEST_CONFLICT,
        "The conditional request cannot succeed due to a conflicting operation against this resource.",
    )
}

/// The verdict on a read: [`ConditionalOutcome::Proceed`] or [`ConditionalOutcome::NotModified`],
/// with a false condition already turned into its `412`.
///
/// `selected` is `None` for an absent key, which is evaluated rather than skipped: `If-Match`
/// against a key that is not there fails the condition, so the answer is `412`, not `404`.
pub(super) fn guard_read(
    selected: Option<&Representation>,
    conditions: &Preconditions,
) -> Result<ConditionalOutcome, HandlerError> {
    match evaluate(conditions, &validators(selected), RequestKind::Read)
        .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?
    {
        outcome @ (ConditionalOutcome::Proceed | ConditionalOutcome::NotModified) => Ok(outcome),
        ConditionalOutcome::PreconditionFailed(failed) => Err(precondition_failed(failed)),
        ConditionalOutcome::Conflict => Err(conflict()),
    }
}

/// The verdict on a write. A write is never answered `304`: a false `If-None-Match` is a `412`,
/// because a `304` would tell the client its object is unchanged when it was never written.
///
/// The caller holds the version lock from this check to the publication it guards, so the
/// representation judged here is the one the write replaces.
pub(super) fn guard_write(selected: Option<&Representation>, conditions: &Preconditions) -> Result<(), HandlerError> {
    match evaluate(conditions, &validators(selected), RequestKind::Write)
        .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?
    {
        ConditionalOutcome::Proceed => Ok(()),
        ConditionalOutcome::NotModified => Err(precondition_failed(None)),
        ConditionalOutcome::PreconditionFailed(failed) => Err(precondition_failed(failed)),
        ConditionalOutcome::Conflict => Err(conflict()),
    }
}
