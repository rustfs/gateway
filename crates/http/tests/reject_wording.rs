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

//! What a refusal is allowed to say to a client, and what it must not.
//!
//! Responsible for: the disjointness of [`WireReject::message`] and [`WireReject::label`], the
//! shape of every message, the `LimitKind` to error-code mapping, and the derivation that keeps
//! this crate's ceilings above the ceilings the operations own.
//! NOT responsible for: whether a request is refused at all — `framing_smuggling.rs`,
//! `header_and_query.rs` and `host_ambiguity.rs` cover that.
//! Upstream: `rustfs-gateway-http`. Downstream: nothing.
//!
//! 3 positive / 13 negative. The negative half is the point: every one of them names a string, a
//! character class or a code that must **not** appear, because the defect this file exists for
//! shipped a response body that was correct in every respect a positive assertion checks — it had
//! a code, a status, and a non-empty `<Message>`.

use rustfs_gateway_http::{HostError, LimitKind, Limits, MetadataReject, WireReject};
use rustfs_gateway_types::ErrorCode;

/// Every ceiling this crate enforces.
const KINDS: &[LimitKind] = &[
    LimitKind::HeaderCount,
    LimitKind::HeaderBytes,
    LimitKind::UriBytes,
    LimitKind::QueryBytes,
    LimitKind::QueryParams,
    LimitKind::HostBytes,
    LimitKind::BodyBytes,
    LimitKind::ChunkSizeLine,
];

/// One refusal of every shape the type can take.
///
/// Written out rather than derived: a variant added without a row here is a variant whose message
/// nobody chose, and the count assertion below is what says so.
fn every_reject() -> Vec<WireReject> {
    let header = http::HeaderName::from_static("x-amz-meta-one");
    let mut all = vec![
        WireReject::ContentLengthTransferEncodingConflict,
        WireReject::TransferEncodingMalformed,
        WireReject::TransferEncodingOnHttp2,
        WireReject::DuplicateContentLength,
        WireReject::MalformedContentLength,
        WireReject::MalformedChunkFraming,
        WireReject::DuplicateSingleValuedHeader("authorization"),
        WireReject::DuplicateSingleValuedQuery("versionId"),
        WireReject::AmbiguousQueryParameterName,
        WireReject::NonUtf8SignificantHeader(header.clone()),
        WireReject::MalformedHeaderValue(header),
        WireReject::MalformedMetadata(MetadataReject::ControlCharacterAfterDecoding),
        WireReject::MalformedRequestTarget,
        WireReject::MalformedQuery,
        WireReject::Host(HostError::Duplicate),
    ];
    all.extend(KINDS.iter().copied().map(WireReject::LimitExceeded));
    all
}

// ---------------------------------------------------------------------------------------------
// The leak this file exists for
// ---------------------------------------------------------------------------------------------

/// Negative — no client-facing message is any refusal's internal label.
///
/// The shipped defect in one assertion: `<Message>limit-exceeded</Message>` reached callers,
/// because the renderer read the label. Every label is checked against every message, not each
/// against its own, so a variant that borrows a sibling's label is caught too.
#[test]
fn no_internal_label_is_reachable_through_a_message() {
    let labels: Vec<&str> = every_reject().iter().map(WireReject::label).collect();
    for reject in every_reject() {
        let message = reject.message();
        for label in &labels {
            assert!(
                !message.contains(label),
                "the message for {reject:?} carries the internal label {label:?}"
            );
        }
    }
}

/// Negative — no message is spelled the way an identifier in this source tree is spelled.
///
/// A label is lowercase words joined by hyphens and holds no space; an identifier is
/// `CamelCase` or `snake_case`. A message that matched either would be a name leaking, whether or
/// not it is a name that exists today.
#[test]
fn no_message_is_shaped_like_an_identifier() {
    for reject in every_reject() {
        let message = reject.message();
        assert!(
            message.contains(' '),
            "{reject:?}: a message with no space is a token, not a sentence: {message:?}"
        );
        assert!(
            !message.contains('_'),
            "{reject:?}: an underscore is a Rust identifier, not prose: {message:?}"
        );
        for word in message.split_whitespace() {
            assert!(
                !word.contains('-') || word.chars().any(|c| c.is_uppercase()),
                "{reject:?}: {word:?} is spelled like an internal label"
            );
        }
    }
}

/// Negative — no message names a ceiling, a count, or how far over the request was.
///
/// The `LimitKind` documentation calls that a probing oracle for the budget. A digit in a message
/// is the cheapest way for one to come back.
#[test]
fn no_message_carries_a_number() {
    for reject in every_reject() {
        assert!(
            !reject.message().chars().any(|c| c.is_ascii_digit()),
            "{reject:?}: a number in a refusal message is a ceiling a peer can binary-search: {:?}",
            reject.message()
        );
    }
}

/// Negative — the eight ceilings are not eight distinguishable sentences.
///
/// Splitting the codes was the fix; splitting the prose would have put the enumeration surface
/// straight back, one refusal at a time.
#[test]
fn the_ceilings_do_not_produce_one_message_each() {
    let mut messages: Vec<&str> = KINDS
        .iter()
        .copied()
        .map(|kind| WireReject::LimitExceeded(kind).message())
        .collect();
    messages.sort_unstable();
    messages.dedup();
    assert!(
        messages.len() < KINDS.len(),
        "one message per ceiling is the enumeration surface the coarse mapping exists to close"
    );
}

/// Positive — every message is a sentence a human can read: it starts with a capital and ends in a
/// full stop.
#[test]
fn every_message_is_a_sentence() {
    for reject in every_reject() {
        let message = reject.message();
        assert!(message.ends_with('.'), "{reject:?}: {message:?}");
        let first = message.chars().next().expect("a non-empty message");
        assert!(first.is_uppercase(), "{reject:?}: {message:?}");
    }
}

/// Positive — every variant has a label, and the labels are all distinct, which is what makes one
/// useful in a metric.
#[test]
fn every_label_is_distinct() {
    let mut labels: Vec<&str> = every_reject().iter().map(WireReject::label).collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total, "two refusals share a label");
}

// ---------------------------------------------------------------------------------------------
// The mapping
// ---------------------------------------------------------------------------------------------

/// Positive — the three ceilings whose answer is not "your request was too big" keep their own
/// codes.
#[test]
fn the_ceilings_that_are_not_size_complaints_have_their_own_codes() {
    assert_eq!(WireReject::LimitExceeded(LimitKind::BodyBytes).error_code(), ErrorCode::ENTITY_TOO_LARGE);
    assert_eq!(
        WireReject::LimitExceeded(LimitKind::ChunkSizeLine).error_code(),
        ErrorCode::INVALID_REQUEST
    );
    assert_eq!(WireReject::LimitExceeded(LimitKind::HostBytes).error_code(), ErrorCode::INVALID_REQUEST);
}

/// Negative — a chunk-size line over its ceiling is not answered as a size complaint, and it is
/// answered exactly as the malformed chunk line beside it.
///
/// The two are one verdict reached by two routes. A caller told to shrink its request would go and
/// change the thing that was never wrong.
#[test]
fn an_over_long_chunk_line_is_not_a_size_complaint() {
    let over_long = WireReject::LimitExceeded(LimitKind::ChunkSizeLine);
    assert_ne!(over_long.error_code(), ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED);
    assert_eq!(over_long.error_code(), WireReject::MalformedChunkFraming.error_code());
    assert_eq!(over_long.message(), WireReject::MalformedChunkFraming.message());
}

/// Negative — an over-long host is not a size complaint either, and reads as the rest of the host
/// decision table.
#[test]
fn an_over_long_host_reads_as_a_host_failure() {
    let over_long = WireReject::LimitExceeded(LimitKind::HostBytes);
    assert_ne!(over_long.error_code(), ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED);
    assert_eq!(over_long.message(), WireReject::Host(HostError::Missing).message());
}

/// Negative — no ceiling produces a code AWS does not publish, and none of them is a 5xx.
///
/// A minted code such as `QueryStringTooLong` compiles, reads well, and no S3 client has a branch
/// for it.
#[test]
fn no_ceiling_mints_a_code() {
    for kind in KINDS {
        let reject = WireReject::LimitExceeded(*kind);
        let code = reject.error_code();
        assert!(code.is_known(), "{kind:?} produced the unpublished code {code}");
        assert!(reject.to_status().is_client_error(), "{kind:?}");
    }
}

/// Negative — no refusal in this layer is a `403`.
///
/// Stated again here rather than only in `reject.rs`'s prose: an authentication-shaped status on a
/// malformed request is what makes an attack indistinguishable from a broken SDK in a dashboard.
#[test]
fn no_refusal_is_an_authentication_outcome() {
    for reject in every_reject() {
        assert_eq!(reject.to_status(), http::StatusCode::BAD_REQUEST, "{reject:?}");
        assert!(!reject.may_read_body(), "{reject:?}");
        assert!(reject.must_close_connection(), "{reject:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// The derivation
// ---------------------------------------------------------------------------------------------

/// Negative — the query budget is not below the ceiling the listing operations enforce on a
/// cursor.
///
/// The `c-list-0030` defect in one assertion. A 4 KiB continuation token has to reach the codec
/// for the codec to be able to call it invalid; a budget under that length answers "too big" and
/// the codec never runs. The number 2048 is `rustfs_gateway_core::codec::value::MAX_TOKEN_LEN`,
/// restated in `crates/core/tests/limit_layering.rs` from the side that can see both crates.
#[test]
fn the_query_budget_leaves_room_for_a_cursor_the_codec_must_refuse() {
    let limits = Limits::default();
    let refusable_cursor = 2 * 2048;
    let query = "list-type=2&continuation-token=".len() + refusable_cursor;
    assert!(
        limits.query_bytes() > query,
        "a {query}-byte query is refused at the wire budget of {}, so the cursor ceiling never answers",
        limits.query_bytes()
    );
}

/// Negative — the target budget does not shadow the query budget.
///
/// The same defect one layer up: a target ceiling below the query ceiling makes the query ceiling
/// unreachable, and the refusal a client reads names the wrong thing again.
#[test]
fn the_target_budget_does_not_shadow_the_query_budget() {
    let limits = Limits::default();
    assert!(
        limits.max_uri_bytes > limits.query_bytes(),
        "a target budget of {} cannot admit a query of {}",
        limits.max_uri_bytes,
        limits.query_bytes()
    );
}

/// Negative — the query budget stays under the `u16` ceiling the query index imposes, so the
/// derivation cannot silently truncate an offset.
#[test]
fn the_derived_budget_is_still_representable() {
    // `query_bytes()` clamps at the `u16` ceiling, so the two assertions together say the
    // derivation is honoured in full rather than silently trimmed to fit an offset.
    assert_eq!(Limits::default().query_bytes(), Limits::DEFAULT_MAX_QUERY_BYTES);
    assert_eq!(
        Limits::DEFAULT_MAX_QUERY_BYTES.min(Limits::QUERY_BYTES_CEILING),
        Limits::DEFAULT_MAX_QUERY_BYTES
    );
}

/// Negative — the resource ceiling did not evaporate. A cursor far past anything the protocol can
/// describe is still refused here, and still as a size complaint.
#[test]
fn an_absurd_query_is_still_refused_at_the_wire() {
    let limits = Limits::default();
    let absurd = 1024 * 1024;
    assert!(
        absurd > limits.query_bytes(),
        "raising the budget must not raise it past the point where size is the real complaint"
    );
    assert_eq!(
        WireReject::LimitExceeded(LimitKind::QueryBytes).error_code(),
        ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED
    );
}
