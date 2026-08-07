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

//! What a refusal does to the connection it arrived on, checked where the decision is carried.
//!
//! Two flags — `WireReject::must_close_connection` and `ChunkReject::must_close_connection` — were
//! declared, returned a constant, and were dropped by the renderer, so no response ever carried
//! `Connection: close` and no assertion that read either one could fail. That is
//! <https://github.com/rustfs/gateway/issues/20>. The suite below pins the three halves of the
//! repair separately, because they fail independently:
//!
//! 1. the flag branches (`crates/http`'s own suites, and `rustfs_gateway::close`'s unit tests);
//! 2. the renderer carries it onto the response, in the extensions — this file;
//! 3. a transport reads it and turns it into `Connection: close` on a socket it then closes.
//!    `crate::adapt` does the header half for the hyper and tower paths; nothing in this crate does
//!    the socket half, because nothing in this crate owns a socket.
//!
//! # Why the verdict is not a header until a transport says so
//!
//! `Connection` is hop-by-hop. `render` used to write it, which made this crate a second writer
//! behind whatever transport was already writing its own — and a response reached the wire carrying
//! `Connection: close` *and* `Connection: keep-alive`. The verdict now travels in the response's
//! extensions, which never reach the wire, and exactly one place turns it into a header.
//!
//! # What this file deliberately does not claim
//!
//! Nothing below asserts that a connection closed. A test in this crate that said so would be
//! reporting the service's intention as an observation, which is the defect class the issue was
//! opened about and which this suite has now produced six times. Every assertion here is about a
//! value or a header, and is worded as one.

use rustfs_gateway::{ConnectionIntent, FixedTrace, RequestTrace, S3Error, TraceSource, connection_intent_of, render};
use rustfs_gateway_http::{ChunkReject, HostError, LimitKind, ModeConfusion, WireReject};
use rustfs_gateway_sig::AuthError;

fn trace() -> RequestTrace {
    FixedTrace::at(0x0123_4567_89AB_CDEF, 0).mint()
}

/// The verdict a rendered refusal carries, as a transport would read it.
fn carried_verdict(error: &S3Error) -> Option<ConnectionIntent> {
    connection_intent_of(&render(error, &trace()))
}

/// Whether the rendered response carries a close verdict a transport would act on.
fn announces_close(error: &S3Error) -> bool {
    carried_verdict(error).is_some_and(ConnectionIntent::must_close)
}

// ---------------------------------------------------------------------------------------------
// The renderer carries the decision
// ---------------------------------------------------------------------------------------------

/// Negative — the acceptance layer's flag reaches the response instead of being dropped.
///
/// This is finding 2 of issue #20 in one assertion: `From<WireReject> for S3Error` computed
/// `must_close_connection()` and discarded it, so a framing conflict — the one refusal RFC 9112
/// §6.1 names by name — answered a client with a connection it was not allowed to reuse.
#[test]
fn a_framing_conflict_reaches_the_response_as_a_close() {
    let error = S3Error::from(WireReject::ContentLengthTransferEncodingConflict);
    assert!(error.must_close_connection());
    assert!(announces_close(&error));
}

/// Negative — and the flag that says otherwise reaches the response as *no* header.
///
/// The pair is the test. If the renderer wrote `Connection: close` unconditionally, or if the flag
/// were still a constant, both halves would read identically to a passing test while measuring
/// nothing.
#[test]
fn a_head_verdict_reaches_the_response_without_one() {
    let error = S3Error::from(WireReject::Host(HostError::Duplicate));
    assert!(!error.must_close_connection());
    assert!(!announces_close(&error));
}

/// Negative — the body-size ceiling closes, and it is the one `LimitKind` that does.
///
/// A refusal issued *because* the body was too large cannot then drain that body; RFC 9112 §9.3
/// leaves no third option. The other ceilings are head-shaped and keep the connection, which is
/// what stops this from being "every limit closes" wearing a branch.
#[test]
fn the_body_ceiling_closes_and_the_head_ceilings_do_not() {
    assert!(S3Error::from(WireReject::LimitExceeded(LimitKind::BodyBytes)).must_close_connection());
    for kind in [
        LimitKind::HeaderCount,
        LimitKind::HeaderBytes,
        LimitKind::UriBytes,
        LimitKind::QueryBytes,
        LimitKind::QueryParams,
        LimitKind::HostBytes,
    ] {
        assert!(!S3Error::from(WireReject::LimitExceeded(kind)).must_close_connection(), "{kind:?}");
    }
}

/// Negative — the chunk layer's flag reaches the response too, and branches there.
#[test]
fn the_chunk_flag_reaches_the_response_and_branches() {
    let truncated = S3Error::from(ChunkReject::TruncatedStream);
    assert!(truncated.must_close_connection());
    assert!(announces_close(&truncated));

    let syntax = S3Error::from(ChunkReject::LeadingZeros);
    assert!(!syntax.must_close_connection());
    assert!(!announces_close(&syntax));

    let no_length = S3Error::from(ChunkReject::ModeConfusion(ModeConfusion::WireLengthMissing));
    assert!(no_length.must_close_connection());
}

// ---------------------------------------------------------------------------------------------
// The third leg
// ---------------------------------------------------------------------------------------------

/// Negative — an authentication failure closes, though it is neither wire nor chunk refusal.
///
/// `c-sig-0001` is an `AuthError`. Issue #20's acceptance criteria asked for both existing flags to
/// be read and could not have reached it: there was no flag on this path to read. The verdict is a
/// policy row — see `rustfs_gateway::close::after_auth_failure` — and the reason it is worth having
/// is that draining an unverified peer's body is the work the case exists to prove is not done.
#[test]
fn an_authentication_failure_closes_the_connection() {
    for error in [
        AuthError::SignatureDoesNotMatch,
        AuthError::InvalidAccessKeyId,
        AuthError::RequestTimeTooSkewed,
    ] {
        let rendered = S3Error::from(error);
        assert!(rendered.must_close_connection(), "{error:?}");
        assert!(announces_close(&rendered), "{error:?}");
    }
}

/// Negative — an authorisation denial does not, though it shares a status with one of them.
///
/// Two `403`s, two connection verdicts: `c-sig-0001` is `SignatureDoesNotMatch` and asserts
/// `closed`, while `c-copy-0019`, `c-copy-0020` and `c-copy-0021` are `AccessDenied` and assert
/// `open`. A rule written on the status would get all four wrong in one direction or the other;
/// what separates them is whether the caller was ever established.
#[test]
fn an_authorisation_denial_keeps_the_connection() {
    let denied = S3Error::from(rustfs_gateway::Denial::access_denied());
    assert_eq!(denied.status(), http::StatusCode::FORBIDDEN);
    assert!(!denied.must_close_connection());
    assert!(!announces_close(&denied));

    let unverified = S3Error::from(AuthError::SignatureDoesNotMatch);
    assert_eq!(unverified.status(), http::StatusCode::FORBIDDEN);
    assert!(unverified.must_close_connection());
}

// ---------------------------------------------------------------------------------------------
// The intent cannot be weakened
// ---------------------------------------------------------------------------------------------

/// Negative — a stage that decided to close is not talked out of it by a later stage.
///
/// `closing` is reachable from anywhere in the crate, so the arithmetic matters: the reason for a
/// close — undrained octets on the wire — does not stop being true because a subsequent stage had
/// nothing to say about the connection.
#[test]
fn a_close_cannot_be_downgraded_by_a_later_stage() {
    let error = S3Error::from(AuthError::SignatureDoesNotMatch).closing(ConnectionIntent::MayKeepAlive);
    assert!(error.must_close_connection());
}

/// Positive — a refusal that says nothing about the connection keeps it, and renders exactly the
/// head it rendered before this capability existed.
///
/// The second assertion is the layering one: `render` writes no `Connection` header for any
/// refusal, closing or not. Two writers of a hop-by-hop header put two contradictory values on one
/// response, which is the shape `WireReject::DuplicateContentLength` refuses on the way in.
#[test]
fn an_ordinary_refusal_keeps_the_connection_and_no_refusal_writes_the_header() {
    let ordinary = S3Error::new(rustfs_gateway::ErrorCode::NO_SUCH_KEY, "the key does not exist");
    assert_eq!(ordinary.connection_intent(), ConnectionIntent::MayKeepAlive);
    assert_eq!(carried_verdict(&ordinary), Some(ConnectionIntent::MayKeepAlive));

    for error in [ordinary, S3Error::from(AuthError::SignatureDoesNotMatch)] {
        assert!(
            render(&error, &trace()).headers().get(http::header::CONNECTION).is_none(),
            "`render` must leave the hop-by-hop header to the transport"
        );
    }
}

/// Negative — the announcement and the decision are two separate reads, and the accessor is the
/// one a transport is meant to use.
///
/// A transport that parsed the header it had just been handed would be reading its own claim back;
/// worse, a response that acquires a `Connection` header some other way would then decide the
/// socket. The value travels beside the response, not inside it.
#[test]
fn the_decision_is_readable_without_parsing_the_response() {
    let error = S3Error::from(WireReject::MalformedChunkFraming);
    assert_eq!(error.connection_intent(), ConnectionIntent::Close);
    // And the same error rendered twice answers the same way both times: the intent is a property
    // of the refusal, not of the rendering.
    assert_eq!(carried_verdict(&error), Some(ConnectionIntent::Close));
    assert_eq!(carried_verdict(&error), Some(ConnectionIntent::Close));
    assert_eq!(error.connection_intent(), ConnectionIntent::Close);
}

/// Negative — a response that carried no refusal carries no verdict either, so a transport cannot
/// read a default off a successful answer and act on it.
#[test]
fn a_response_no_refusal_produced_carries_no_verdict() {
    let plain: http::Response<rustfs_gateway::Body> = http::Response::new(rustfs_gateway::Body::empty());
    assert_eq!(connection_intent_of(&plain), None);
}
