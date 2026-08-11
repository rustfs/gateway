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

//! Direct checks for the facade's private typed refusal converters.
//!
//! Responsible for: exhaustively pinning converter output that cannot be constructed through the
//! public `S3Error` API after ADR-0008. NOT responsible for: proving the public service reaches
//! these converters; the integration suites retain that real request-path evidence. Upstream:
//! `crate::render`. Downstream: the gateway library test target only.

#![allow(clippy::expect_used, clippy::panic)]

use super::*;
use rustfs_gateway_core::RegionLabel;
use rustfs_gateway_http::{ChunkReject, HostError, LimitKind, MetadataReject, ModeConfusion};

fn trace() -> RequestTrace {
    RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0)
}

fn carried_verdict(error: &S3Error) -> Option<ConnectionIntent> {
    connection_intent_of(&render(error, &trace()))
}

fn announces_close(error: &S3Error) -> bool {
    carried_verdict(error).is_some_and(ConnectionIntent::must_close)
}

#[test]
fn a_framing_conflict_reaches_the_response_as_a_close() {
    let error = from_wire_reject(WireReject::ContentLengthTransferEncodingConflict);
    assert!(error.must_close_connection());
    assert!(announces_close(&error));
}

#[test]
fn a_head_verdict_reaches_the_response_without_one() {
    let error = from_wire_reject(WireReject::Host(HostError::Duplicate));
    assert!(!error.must_close_connection());
    assert!(!announces_close(&error));
}

#[test]
fn the_body_ceiling_closes_and_the_head_ceilings_do_not() {
    assert!(from_wire_reject(WireReject::LimitExceeded(LimitKind::BodyBytes)).must_close_connection());
    for kind in [
        LimitKind::HeaderCount,
        LimitKind::HeaderBytes,
        LimitKind::UriBytes,
        LimitKind::QueryBytes,
        LimitKind::QueryParams,
        LimitKind::HostBytes,
    ] {
        assert!(!from_wire_reject(WireReject::LimitExceeded(kind)).must_close_connection(), "{kind:?}");
    }
}

#[test]
fn the_chunk_flag_reaches_the_response_and_branches() {
    let truncated = from_chunk_reject(ChunkReject::TruncatedStream);
    assert!(truncated.must_close_connection());
    assert!(announces_close(&truncated));

    let syntax = from_chunk_reject(ChunkReject::LeadingZeros);
    assert!(!syntax.must_close_connection());
    assert!(!announces_close(&syntax));

    let no_length = from_chunk_reject(ChunkReject::ModeConfusion(ModeConfusion::WireLengthMissing));
    assert!(no_length.must_close_connection());
}

#[test]
fn an_authentication_failure_closes_the_connection() {
    for error in [
        AuthError::SignatureDoesNotMatch,
        AuthError::InvalidAccessKeyId,
        AuthError::RequestTimeTooSkewed,
    ] {
        let rendered = from_auth(error, ResponseKind::Other);
        assert!(rendered.must_close_connection(), "{error:?}");
        assert!(announces_close(&rendered), "{error:?}");
    }
}

#[test]
fn closed_scope_contexts_preserve_authentication_teardown() {
    let malformed = from_auth_context(
        AuthError::AuthorizationHeaderMalformed,
        ErrorContext::authorization_scope_malformed(),
        ResponseKind::Other,
    );
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(malformed.details().is_empty());
    assert!(malformed.must_close_connection());

    let region = RegionLabel::new("eu-west-1").expect("valid configured region");
    let mismatch = from_auth_context(
        AuthError::AuthorizationHeaderMalformed,
        ErrorContext::authorization_region_mismatch(region),
        ResponseKind::Other,
    );
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mismatch.details().len(), 1);
    assert!(mismatch.must_close_connection());
}

#[test]
fn an_authorisation_denial_keeps_the_connection() {
    let denied = from_denial(Denial::access_denied(), ResponseKind::Other);
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied.must_close_connection());
    assert!(!announces_close(&denied));

    let unverified = from_auth(AuthError::SignatureDoesNotMatch, ResponseKind::Other);
    assert_eq!(unverified.status(), StatusCode::FORBIDDEN);
    assert!(unverified.must_close_connection());
}

#[test]
fn a_close_cannot_be_downgraded_by_a_later_stage() {
    let error = with_connection(
        from_auth(AuthError::SignatureDoesNotMatch, ResponseKind::Other),
        ConnectionIntent::MayKeepAlive,
    );
    assert!(error.must_close_connection());
}

#[test]
fn an_ordinary_refusal_keeps_the_connection_and_no_refusal_writes_the_header() {
    let ordinary = from_handler(
        HandlerError::new(ErrorCode::NO_SUCH_UPLOAD, "the upload does not exist"),
        ResponseKind::Other,
        ConnectionIntent::MayKeepAlive,
    );
    assert_eq!(ordinary.connection_intent(), ConnectionIntent::MayKeepAlive);
    assert_eq!(carried_verdict(&ordinary), Some(ConnectionIntent::MayKeepAlive));

    for error in [ordinary, from_auth(AuthError::SignatureDoesNotMatch, ResponseKind::Other)] {
        assert!(
            render(&error, &trace()).headers().get(http::header::CONNECTION).is_none(),
            "render must leave the hop-by-hop header to the transport"
        );
    }
}

#[test]
fn the_decision_is_readable_without_parsing_the_response() {
    let error = from_wire_reject(WireReject::MalformedChunkFraming);
    assert_eq!(error.connection_intent(), ConnectionIntent::Close);
    assert_eq!(carried_verdict(&error), Some(ConnectionIntent::Close));
    assert_eq!(carried_verdict(&error), Some(ConnectionIntent::Close));
    assert_eq!(error.connection_intent(), ConnectionIntent::Close);
}

#[test]
fn a_response_no_refusal_produced_carries_no_verdict() {
    let plain: http::Response<Body> = http::Response::new(Body::empty());
    assert_eq!(connection_intent_of(&plain), None);
}

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
    all.extend(LIMIT_KINDS.iter().copied().map(WireReject::LimitExceeded));
    all
}

const LIMIT_KINDS: &[LimitKind] = &[
    LimitKind::HeaderCount,
    LimitKind::HeaderBytes,
    LimitKind::UriBytes,
    LimitKind::QueryBytes,
    LimitKind::QueryParams,
    LimitKind::HostBytes,
    LimitKind::BodyBytes,
    LimitKind::ChunkSizeLine,
];

#[test]
fn no_operator_label_appears_in_a_rendered_refusal() {
    let trace = trace();
    let labels: Vec<&str> = every_reject().iter().map(WireReject::label).collect();
    for reject in every_reject() {
        let rendered = document(&from_wire_reject(reject.clone()), &trace);
        for label in &labels {
            assert!(
                !rendered.contains(label),
                "the document for {reject:?} contains the operator label {label:?}:\n{rendered}"
            );
        }
    }
}

#[test]
fn a_rendered_refusal_carries_the_client_message() {
    let trace = trace();
    for reject in every_reject() {
        let rendered = document(&from_wire_reject(reject.clone()), &trace);
        assert!(
            rendered.contains(&format!("<Message>{}</Message>", reject.message())),
            "the document for {reject:?} does not carry its client message:\n{rendered}"
        );
    }
}
