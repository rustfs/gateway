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

//! Every argument of the copy-source contract, built out of a `Req<O>` and nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call* the whole copy-source
//! contract from what a handler is handed — [`ResolvedCopySource`] through the read proof,
//! [`classify_self_copy`] and [`SelfCopy::rejection`], the four `x-amz-copy-source-if-*` conditions
//! through [`parse_conditional_etag`] and [`evaluate`] as a read, the two contract constants
//! [`copy_source_if_match_miss_proceeds`] and [`copy_source_guards_before_target_write`], and
//! [`resolve_copy_range`] for `UploadPartCopy` — using only the facade, never a literal.
//! NOT responsible for: what the rules decide, which is `rustfs-gateway-core`'s
//! `ops/shared/copy_source.rs` and `precondition.rs` inline tests, or the authorization of the
//! source, which `authz_consumption.rs` pins.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15 found `evaluate_range` exported and uncallable, and left the rest of the exported
//! surface open with the acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** Its last handoff named the copy-source conditions as the
//! known gap: the four `x-amz-copy-source-if-*` headers are not `Preconditions` fields, the
//! conformance fixture parses them by hand, and the fs backend's `copy.rs` bridges them privately.
//! Nothing proved a backend with only the facade could do the same until this file. The handler
//! below is that backend: it reads no fixture, imports nothing from `core`, and answers every case
//! from the contract's own verdicts.

use crate::support;

use std::sync::{Arc, Mutex};

use rustfs_gateway::{
    ConditionalOutcome, CopyRange, ETag, ErrorCode, Handler, HandlerError, HandlerResult, ObjectValidators,
    PRECONDITION_FAILED_MESSAGE, Preconditions, Req, RequestKind, Resp, SelfCopy, Timestamp, TimestampFormat, classify_self_copy,
    copy_source_guards_before_target_write, copy_source_if_match_miss_proceeds, dto, evaluate, parse_conditional_etag,
    resolve_copy_range,
};
use support::{exchange, fixed_clock, signed_with, wired};

/// The source object every case copies from, as the backend knows it.
const SOURCE_ETAG: &str = "781e5e245d69b566979b86e28d23f2c7";
const SOURCE_LEN: u64 = 12;
const SOURCE_LAST_MODIFIED: &str = "Thu, 01 Jan 2026 00:00:00 GMT";
const STALE_ETAG: &str = "\"0000000000000000000000000000dead\"";

/// What the backend derived from the request, for the assertions to read back.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Derived {
    source: Option<(String, String, Option<String>)>,
    self_copy: Option<SelfCopy>,
    range: Option<Option<CopyRange>>,
}

struct CopyBackend(Arc<Mutex<Derived>>);

impl CopyBackend {
    fn service(&self) -> (rustfs_gateway::S3Service, Arc<Mutex<Derived>>) {
        let derived = Arc::clone(&self.0);
        let service = wired()
            .clock_with_skew_ack(
                fixed_clock(),
                rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .register::<dto::CopyObject, _>(Arc::new(CopyBackend(Arc::clone(&self.0))))
            .register::<dto::UploadPartCopy, _>(Arc::new(CopyBackend(Arc::clone(&self.0))))
            .build()
            .expect("a complete copy assembly");
        (service, derived)
    }
}

/// The source the backend holds, as the validators the read-side contract compares against.
fn source_validators() -> ObjectValidators {
    ObjectValidators {
        exists: true,
        etag: ETag::new(SOURCE_ETAG).ok(),
        last_modified: Timestamp::parse(SOURCE_LAST_MODIFIED, TimestampFormat::HttpDate).ok(),
    }
}

/// The bridge a backend writes itself: the decoded input carries the four conditions as wire
/// strings and timestamps, the contract wants typed entity tags.
fn tag_condition(raw: Option<&str>) -> Result<Option<ETag>, HandlerError> {
    raw.map(parse_conditional_etag)
        .transpose()
        .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "a copy-source condition has an invalid entity tag"))
}

/// Guards the source exactly as the contract states it: all four conditions evaluated as a read,
/// a lone `If-Match` miss let through when the contract says so, and either negative verdict the
/// write's `412`.
fn guard_source(
    if_match: Option<&str>,
    if_none_match: Option<&str>,
    if_modified_since: Option<Timestamp>,
    if_unmodified_since: Option<Timestamp>,
) -> Result<(), HandlerError> {
    assert!(copy_source_guards_before_target_write(), "the contract orders the guard before the write");
    let conditions = Preconditions {
        if_match: tag_condition(if_match)?,
        if_none_match: tag_condition(if_none_match)?,
        if_modified_since,
        if_unmodified_since,
        observed_at: None,
    };
    let outcome = evaluate(&conditions, &source_validators(), RequestKind::Read)
        .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
    let only_if_match =
        if_match.is_some() && if_none_match.is_none() && if_modified_since.is_none() && if_unmodified_since.is_none();
    if only_if_match && copy_source_if_match_miss_proceeds() {
        return Ok(());
    }
    match outcome {
        ConditionalOutcome::Proceed => Ok(()),
        // Not `HandlerError::precondition_failed`: its `<Condition>` detail admits only the four
        // plain header names, and a copy-source condition is none of them, so the copy's `412`
        // carries the code and the standard message alone — as the fs backend's does.
        ConditionalOutcome::NotModified | ConditionalOutcome::PreconditionFailed(_) => {
            Err(HandlerError::new(ErrorCode::PRECONDITION_FAILED, PRECONDITION_FAILED_MESSAGE))
        }
        ConditionalOutcome::Conflict => Err(HandlerError::internal_error("a copy source cannot race a read")),
    }
}

impl Handler<dto::CopyObject> for CopyBackend {
    async fn call(&self, request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        let source = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("the proof does not cover the source"))?;
        let input = request.input();
        let changes_something = input.metadata_directive.as_ref() == Some(&dto::MetadataDirective::REPLACE)
            || input.storage_class.is_some()
            || input.server_side_encryption.is_some();
        let self_copy = classify_self_copy(&source, &input.bucket, &input.key, changes_something);
        if let Some(rejection) = self_copy.rejection() {
            return Err(HandlerError::new(rejection.code().clone(), rejection.reason()));
        }
        guard_source(
            input.copy_source_if_match.as_deref(),
            input.copy_source_if_none_match.as_deref(),
            input.copy_source_if_modified_since,
            input.copy_source_if_unmodified_since,
        )?;
        let mut derived = self.0.lock().expect("the record is never poisoned");
        derived.source = Some((
            source.bucket().expect("source names a bucket").as_str().to_owned(),
            source.key().as_str().to_owned(),
            source.version_id().map(str::to_owned),
        ));
        derived.self_copy = Some(self_copy);
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }
}

impl Handler<dto::UploadPartCopy> for CopyBackend {
    async fn call(&self, request: Req<dto::UploadPartCopy>) -> HandlerResult<dto::UploadPartCopy> {
        let source = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("the proof does not cover the source"))?;
        let input = request.input();
        guard_source(
            input.copy_source_if_match.as_deref(),
            input.copy_source_if_none_match.as_deref(),
            input.copy_source_if_modified_since,
            input.copy_source_if_unmodified_since,
        )?;
        let range = resolve_copy_range(input.copy_source_range.as_deref(), SOURCE_LEN)
            .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
        let mut derived = self.0.lock().expect("the record is never poisoned");
        derived.source = Some((
            source.bucket().expect("source names a bucket").as_str().to_owned(),
            source.key().as_str().to_owned(),
            source.version_id().map(str::to_owned),
        ));
        derived.range = Some(range);
        Ok(Resp::new(dto::UploadPartCopyOutput::default()))
    }
}

fn backend() -> CopyBackend {
    CopyBackend(Arc::new(Mutex::new(Derived::default())))
}

async fn copy(headers: &[(&str, &str)]) -> (http::StatusCode, String, Derived) {
    let (service, derived) = backend().service();
    let (status, body) = exchange(&service, signed_with(http::Method::PUT, "/destination/object", headers)).await;
    let derived = derived.lock().expect("the record is never poisoned").clone();
    (status, body, derived)
}

async fn part_copy(headers: &[(&str, &str)]) -> (http::StatusCode, String, Derived) {
    let (service, derived) = backend().service();
    let target = "/destination/object?partNumber=1&uploadId=upload-one";
    let (status, body) = exchange(&service, signed_with(http::Method::PUT, target, headers)).await;
    let derived = derived.lock().expect("the record is never poisoned").clone();
    (status, body, derived)
}

/// Positive control — the whole contract runs on a plain copy: the source resolves through the
/// proof with its bucket, key and no version, and the copy is not a self copy.
#[tokio::test]
async fn a_plain_copy_resolves_its_source_through_the_proof() {
    let (status, body, derived) = copy(&[("x-amz-copy-source", "/source/secret")]).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(derived.source, Some(("source".to_owned(), "secret".to_owned(), None)));
    assert_eq!(derived.self_copy, Some(SelfCopy::No));
}

/// Positive — a versioned source hands the backend the version it asked for, decoded once.
#[tokio::test]
async fn a_versioned_source_reaches_the_backend_with_its_version() {
    let (status, body, derived) = copy(&[("x-amz-copy-source", "/source/secret?versionId=v1")]).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(derived.source, Some(("source".to_owned(), "secret".to_owned(), Some("v1".to_owned()))));
}

/// Negative — a copy onto itself that changes nothing is the contract's own `InvalidRequest`,
/// classified from the resolved source and the destination the input names.
#[tokio::test]
async fn n_a_self_copy_that_changes_nothing_is_refused_by_the_contract() {
    let (status, body, derived) = copy(&[("x-amz-copy-source", "/destination/object")]).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");
    assert_eq!(derived, Derived::default(), "the handler answered before deriving anything");
}

/// Positive — the same self copy with a replacing metadata directive is the legal rewrite.
#[tokio::test]
async fn a_self_copy_replacing_metadata_is_the_legal_rewrite() {
    let (status, body, derived) = copy(&[
        ("x-amz-copy-source", "/destination/object"),
        ("x-amz-metadata-directive", "REPLACE"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(derived.self_copy, Some(SelfCopy::RewriteMetadata));
}

/// Negative — a stale `x-amz-copy-source-if-unmodified-since` fails the read-side evaluation and
/// the write answers `412`, the condition having been built from the decoded timestamp alone.
#[tokio::test]
async fn n_a_stale_copy_source_if_unmodified_since_is_precondition_failed() {
    let (status, body, derived) = copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-if-unmodified-since", "Wed, 31 Dec 2025 00:00:00 GMT"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::PRECONDITION_FAILED, "{body}");
    assert_eq!(derived.source, None, "the guard ran before the source was recorded");
}

/// Negative — a current `x-amz-copy-source-if-none-match` is `NotModified` as a read and therefore
/// the write's `412`: the contract's read verdict is mapped, not re-derived.
#[tokio::test]
async fn n_a_current_copy_source_if_none_match_is_precondition_failed() {
    let (status, body, _) = copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-if-none-match", &format!("\"{SOURCE_ETAG}\"")),
    ])
    .await;
    assert_eq!(status, http::StatusCode::PRECONDITION_FAILED, "{body}");
}

/// Negative — a `x-amz-copy-source-if-match` in the RFC 9110 list form is refused at the bridge,
/// `InvalidArgument`, before the contract is asked anything: S3 evaluates one entity tag, and the
/// bridge refuses the list rather than quietly keeping its first member. A bare unquoted tag, by
/// contrast, is one of the three spellings the bridge admits, so it is not a bridge refusal.
#[tokio::test]
async fn n_a_copy_source_if_match_list_is_invalid_argument() {
    let (status, body, derived) = copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-if-match", &format!("\"{SOURCE_ETAG}\", {STALE_ETAG}")),
    ])
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    assert_eq!(derived.source, None, "the bridge refused before the source was recorded");
}

/// The lone stale `If-Match` case follows whichever answer the contract constant gives, so the
/// backend cannot hard-code either: with the constant true the copy proceeds, with it false the
/// copy is `412`.
#[tokio::test]
async fn a_lone_stale_copy_source_if_match_follows_the_contract_constant() {
    let (status, body, _) = copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-if-match", STALE_ETAG),
    ])
    .await;
    let expected = if copy_source_if_match_miss_proceeds() {
        http::StatusCode::OK
    } else {
        http::StatusCode::PRECONDITION_FAILED
    };
    assert_eq!(status, expected, "{body}");
}

/// Negative — the same stale `If-Match` beside a second condition is no longer the lone case, and
/// the read verdict stands: `412`.
#[tokio::test]
async fn n_a_stale_copy_source_if_match_beside_another_condition_is_precondition_failed() {
    let (status, body, _) = copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-if-match", STALE_ETAG),
        ("x-amz-copy-source-if-modified-since", "Wed, 31 Dec 2025 00:00:00 GMT"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::PRECONDITION_FAILED, "{body}");
}

/// Positive — a part copy without a range copies the whole source: the contract answers `None`,
/// not a span, and the backend records exactly that.
#[tokio::test]
async fn a_part_copy_without_a_range_copies_the_whole_source() {
    let (status, body, derived) = part_copy(&[("x-amz-copy-source", "/source/secret")]).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(derived.range, Some(None));
    assert_eq!(derived.source, Some(("source".to_owned(), "secret".to_owned(), None)));
}

/// Positive — a satisfiable `x-amz-copy-source-range` resolves to the inclusive span.
#[tokio::test]
async fn a_part_copy_range_resolves_to_its_inclusive_span() {
    let (status, body, derived) = part_copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-range", "bytes=2-6"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(
        derived.range,
        Some(Some(CopyRange {
            start: 2,
            end_inclusive: 6
        }))
    );
}

/// Negative — a span past the source's length is `InvalidArgument` from the contract, and the
/// handler never records a range it could not copy.
#[tokio::test]
async fn n_a_part_copy_range_past_the_source_is_invalid_argument() {
    let (status, body, derived) = part_copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-range", "bytes=0-12"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    assert_eq!(derived.range, None);
}

/// Negative — a multi-range value is refused the same way: a part is one span.
#[tokio::test]
async fn n_a_multi_range_part_copy_is_invalid_argument() {
    let (status, body, _) = part_copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-range", "bytes=0-3,5-7"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
}

/// Negative — the source conditions guard a part copy too, before its range is resolved.
#[tokio::test]
async fn n_a_part_copy_with_a_stale_source_condition_is_precondition_failed() {
    let (status, body, derived) = part_copy(&[
        ("x-amz-copy-source", "/source/secret"),
        ("x-amz-copy-source-if-unmodified-since", "Wed, 31 Dec 2025 00:00:00 GMT"),
        ("x-amz-copy-source-range", "bytes=0-1"),
    ])
    .await;
    assert_eq!(status, http::StatusCode::PRECONDITION_FAILED, "{body}");
    assert_eq!(derived.range, None, "the guard ran before the range was resolved");
}
