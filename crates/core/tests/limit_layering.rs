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

//! Which layer answers when two layers both have a ceiling for the same value.
//!
//! Responsible for: pinning `rustfs-gateway-http`'s resource budget above the protocol ceiling on
//! a server-minted cursor, and proving that an overlong but transport-safe token reaches the
//! operation parser instead of being refused by the wire or the generated codec.
//! NOT responsible for: the wording of either refusal (`crates/http/tests/reject_wording.rs`) or
//! the cursor grammar itself (the operation that consumes the opaque token).
//! Upstream: `rustfs-gateway-http`, `rustfs-gateway-core`. Downstream: nothing.
//!
//! # Why this file exists at all
//!
//! The cursor ceiling lives in the operation layer, while `crates/http` repeats it in the query
//! budget derivation because that lower ring cannot import core. This file is the lowest place in
//! the tree that can see both numbers, so it asserts the relationship between them.
//!
//! The relationship is deliberately an *inequality*, not an equality. The wire budget must leave
//! room for a cursor the operation has to be able to call invalid; it must not be pinned to the
//! cursor ceiling, because it is a sum over every query value S3 can carry and the cursor is one
//! term of it.
//!
//! 1 positive / 5 negative.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use http::Request;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::pagination::MAX_CURSOR_BYTES;
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{LimitKind, Limits, WireReject, WireRequest};
use rustfs_gateway_types::{ErrorCode, dto};

/// A `ListObjectsV2` request whose continuation token is `token_len` bytes long.
fn listing_with_token(token_len: usize) -> Request<()> {
    let token = "A".repeat(token_len);
    Request::builder()
        .method("GET")
        .uri(format!("http://host.invalid/conf-list?list-type=2&continuation-token={token}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed")
}

/// The refusal a token of `token_len` bytes actually produces, from whichever layer answers first.
enum Refused {
    /// The wire budget answered.
    Wire(WireReject),
    /// The operation's own ceiling answered.
    Codec(ErrorCode),
    /// Nothing refused it.
    Accepted,
}

fn refuse(token_len: usize) -> Refused {
    let accepted = match WireRequest::accept(listing_with_token(token_len), &Limits::default()) {
        Ok(request) => request,
        Err(reject) => return Refused::Wire(reject),
    };
    let view = MetaView::of(&accepted, TargetKind::Bucket).expect("a bucket route needs only a bucket");
    match dto::ListObjectsV2::decode(&view, RequestBody::None) {
        Ok(_) => Refused::Accepted,
        Err(error) => Refused::Codec(error.code().clone()),
    }
}

/// Negative — the wire budget does not sit under the cursor ceiling.
///
/// The whole of the `c-list-0030` defect, expressed over the two numbers rather than over a
/// response. A cursor this service will not accept has to be able to *arrive*, or the layer that
/// knows why it is unacceptable never runs.
#[test]
fn the_wire_budget_is_above_the_cursor_ceiling() {
    // `max` rather than a bare comparison: both sides are constants, and clippy is right that a
    // constant assertion is a compile-time fact dressed up as a test. The relationship is what is
    // asserted either way, and this spelling reports both numbers when it fails.
    assert_eq!(
        Limits::DEFAULT_MAX_QUERY_BYTES.max(MAX_CURSOR_BYTES),
        Limits::DEFAULT_MAX_QUERY_BYTES,
        "a query budget of {} cannot admit a cursor of {MAX_CURSOR_BYTES} plus the parameters around it",
        Limits::DEFAULT_MAX_QUERY_BYTES
    );
    // Percent-encoding is worst-case three bytes to one, and the derivation says so; a budget that
    // only admitted the unencoded form would refuse a conforming client's spelling of the same
    // cursor.
    let encoded = 3 * MAX_CURSOR_BYTES;
    assert_eq!(Limits::DEFAULT_MAX_QUERY_BYTES.max(encoded), Limits::DEFAULT_MAX_QUERY_BYTES);
}

/// A cursor one byte past the protocol ceiling reaches the operation parser, not a lower-layer
/// refusal.
///
/// The boundary matters more than the 4 KiB the conformance case uses: it is the first length at
/// which the two layers could disagree about who answers.
#[test]
fn a_cursor_one_byte_over_reaches_the_operation_parser() {
    match refuse(MAX_CURSOR_BYTES + 1) {
        Refused::Accepted => {}
        Refused::Codec(code) => panic!("the generated codec answered first with {code}"),
        Refused::Wire(reject) => panic!("the wire answered first with {:?}", reject.error_code()),
    }
}

/// The four-kibibyte token of `c-list-0030` also reaches the operation parser, where the
/// conformance case pins its `InvalidArgument` response.
#[test]
fn the_conformance_token_reaches_the_operation_parser() {
    match refuse(4096) {
        Refused::Accepted => {}
        Refused::Codec(code) => panic!("the generated codec answered first with {code}"),
        Refused::Wire(reject) => panic!("the wire answered first with {:?}", reject.error_code()),
    }
}

/// Positive — a cursor at the ceiling is a cursor this service could have minted, and it decodes.
///
/// Without this the inequality above could be satisfied by refusing everything, and both negative
/// cases would still pass.
#[test]
fn a_cursor_at_the_ceiling_still_decodes() {
    match refuse(MAX_CURSOR_BYTES) {
        Refused::Accepted => {}
        Refused::Codec(code) => panic!("a cursor at the ceiling was refused with {code}"),
        Refused::Wire(reject) => panic!("a cursor at the ceiling was refused with {:?}", reject.error_code()),
    }
}

/// Negative — the resource ceiling has not been raised out of existence.
///
/// Raising a wire budget to unblock a protocol ceiling is the change that quietly removes the
/// defence it was there for. A cursor far past anything the protocol can describe is still refused
/// before any operation sees it.
///
/// Forty kibibytes rather than a mebibyte: `http::Uri` refuses to hold a target above `u16::MAX`
/// of its own accord, so a larger fixture never reaches the code under test and would assert
/// nothing about it.
#[test]
fn an_absurd_cursor_is_still_refused_at_the_wire() {
    match refuse(40 * 1024) {
        Refused::Wire(WireReject::LimitExceeded(kind)) => {
            assert!(matches!(kind, LimitKind::QueryBytes | LimitKind::UriBytes), "{kind:?}");
        }
        Refused::Wire(other) => panic!("refused, but not at a ceiling: {other:?}"),
        Refused::Codec(code) => panic!("a mebibyte of cursor reached the codec and was refused with {code}"),
        Refused::Accepted => panic!("a mebibyte of cursor was accepted"),
    }
}

/// Negative — the wire's answer to an absurd cursor is still the coarse size complaint, and never
/// the operation's code.
///
/// The two layers keep different answers on purpose. If the wire started answering
/// `InvalidArgument` the distinction this file is about would be gone in the other direction.
#[test]
fn the_two_layers_do_not_converge_on_one_code() {
    let wire = WireReject::LimitExceeded(LimitKind::QueryBytes).error_code();
    assert_eq!(wire, ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED);
    assert_ne!(wire, ErrorCode::INVALID_ARGUMENT);
}
