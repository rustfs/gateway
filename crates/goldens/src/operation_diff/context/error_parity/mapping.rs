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

//! The RustFS-adapter mapping of s3s handler errors, for the two operations M1 moves (PutObject,
//! GetBucketLocation), and the seam's refusals by member name.
//!
//! Responsible for: proving that each error a RustFS body returns reaches the client with the
//! status, code and message the s3s service writes today, and that the seam's lists of codes the
//! gateway resolves only from facts are exactly the codes the gateway refuses bare.
//! NOT responsible for: the refusals a stack makes before its handler (`super::matrix`).
//! Upstream: `super`, `super::matrix`, `compat::error`. Downstream: nothing.
//!
//! PutObject rows send an empty body: a body the app refuses without reading is rd-err-0004's own
//! row, and here the mapping alone is measured.

use super::super::super::SEAM_REVISION;
use super::super::super::seam::error::{CONTEXTUAL_CODES, MAX_MESSAGE_BYTES, NEEDS_FACTS_CODES, Refusal, refusal_from_s3s};
use super::matrix::{Expect, location, object_put, refused_alike};
use super::s3s;
use super::{AppBody, Scenario};
use http::{HeaderMap, HeaderValue, StatusCode};
use rustfs_gateway::{ErrorCode, ErrorContext, HandlerError};
use rustfs_gateway_types::compat::OracleRevision;
use s3s::{S3Error, S3ErrorCode};

/// One RustFS body error, and the status and code both stacks must answer it with.
pub(super) type AppBodyError = (fn() -> S3Error, u16, &'static str);

/// Errors the RustFS PutObject and GetBucketLocation bodies return, spelled as RustFS spells them
/// (`rustfs/src/error.rs` `error_code_to_message`, `app/object/shared.rs` `parse_expires_header`).
pub(super) const APP_BODY_ERRORS: [AppBodyError; 11] = [
    (|| S3Error::with_message(S3ErrorCode::AccessDenied, "Access Denied."), 403, "AccessDenied"),
    (
        || S3Error::with_message(S3ErrorCode::InvalidArgument, "Invalid Expires header"),
        400,
        "InvalidArgument",
    ),
    (
        || S3Error::with_message(S3ErrorCode::InvalidStorageClass, "Invalid storage class."),
        400,
        "InvalidStorageClass",
    ),
    (
        || {
            S3Error::with_message(
                S3ErrorCode::EntityTooLarge,
                "Your proposed upload exceeds the maximum allowed object size.",
            )
        },
        400,
        "EntityTooLarge",
    ),
    (
        || S3Error::with_message(S3ErrorCode::BadDigest, "The Content-Md5 you specified did not match what we received."),
        400,
        "BadDigest",
    ),
    (
        || S3Error::with_message(S3ErrorCode::InternalError, "We encountered an internal error, please try again."),
        500,
        "InternalError",
    ),
    (
        || {
            S3Error::with_message(
                S3ErrorCode::NotImplemented,
                "A header you provided implies functionality that is not implemented",
            )
        },
        501,
        "NotImplemented",
    ),
    (|| S3Error::new(S3ErrorCode::SlowDown), 503, "SlowDown"),
    (
        || S3Error::with_message(S3ErrorCode::ServiceUnavailable, "The service is unavailable. Please retry."),
        503,
        "ServiceUnavailable",
    ),
    (quota_exceeded, 403, "XRustfsQuotaExceeded"),
    (conflicting_request, 409, "InvalidRequest"),
];

/// A code s3s does not declare, with the status the body chose.
fn quota_exceeded() -> S3Error {
    let code = S3ErrorCode::from_bytes(b"XRustfsQuotaExceeded").unwrap_or(S3ErrorCode::InternalError);
    let mut error = S3Error::with_message(code, "Bucket quota exceeded");
    error.set_status_code(StatusCode::FORBIDDEN);
    error
}

/// A declared code at a status other than its own.
fn conflicting_request() -> S3Error {
    let mut error = S3Error::with_message(S3ErrorCode::InvalidRequest, "Object is WORM protected and cannot be overwritten");
    error.set_status_code(StatusCode::CONFLICT);
    error
}

#[test]
fn every_app_body_error_crosses_the_adapter_with_the_s3s_status_code_and_message() {
    for (error, status, code) in APP_BODY_ERRORS {
        for request in [location(), object_put(b"")] {
            let scenario = Scenario::new(request.signed("us-east-1")).app_refuses(error);
            let pair = refused_alike(&scenario, Expect::app_body(status, code));
            if SEAM_REVISION == OracleRevision::Candidate {
                assert!(
                    pair.gateway.message().is_some_and(|message| !message.is_empty()),
                    "0.17.0 names a message for every code: {pair:#?}"
                );
            }
        }
    }
}

#[test]
fn the_missing_resource_codes_map_to_the_gateways_typed_context() {
    for (code, expected) in [
        (S3ErrorCode::NoSuchBucket, Refusal::MissingBucket),
        (S3ErrorCode::NoSuchKey, Refusal::MissingKey),
        (S3ErrorCode::NoSuchVersion, Refusal::MissingVersion),
    ] {
        assert_eq!(refusal_from_s3s(&S3Error::new(code)), Ok(expected));
    }
}

/// The seam's two lists are the gateway's own: every code on them is refused as a bare
/// `HandlerError` (a `500` through the adapter), and every other code the RustFS bodies return is
/// admitted. Bare — with no header — the seam maps the three missing-resource codes and refuses the
/// rest by name, or by the header carrying the fact it lacks.
#[test]
fn the_seams_fact_lists_are_exactly_the_codes_the_gateway_refuses_bare() {
    for name in CONTEXTUAL_CODES.iter().chain(NEEDS_FACTS_CODES.iter()) {
        let code = ErrorCode::known(name).unwrap_or_else(|| panic!("{name} is a gateway code"));
        assert!(ErrorContext::ordinary(HandlerError::new(code, "m")).is_err(), "{name} is admitted bare");
        let seam = S3ErrorCode::from_bytes(name.as_bytes()).map(|code| refusal_from_s3s(&S3Error::new(code)));
        match seam {
            Some(Ok(Refusal::MissingBucket | Refusal::MissingKey | Refusal::MissingVersion)) => {
                assert!(["NoSuchBucket", "NoSuchKey", "NoSuchVersion"].contains(name), "{name}");
            }
            // Bare, the two codes whose facts ride in a header are refused by that header.
            Some(Err(error)) => {
                let lacking = match *name {
                    "NotModified" => "etag",
                    "InvalidRange" => "content-range",
                    _ => "code",
                };
                assert_eq!(error.field, lacking, "{name}");
            }
            other => panic!("{name}: the seam answered {other:?}"),
        }
    }
    for (error, _, name) in APP_BODY_ERRORS {
        let Ok(Refusal::Ordinary { code, message }) = refusal_from_s3s(&error()) else {
            panic!("{name} is not ordinary");
        };
        assert!(ErrorContext::ordinary(HandlerError::new(code, message)).is_ok(), "{name} is refused bare");
    }
}

/// Both directions over a fixed probe of gateway codes, written out here rather than read from the
/// seam, so a code dropped from a seam list is caught even when another rule would still refuse it
/// (NotModified is also a 3xx).
#[test]
fn a_code_is_on_a_seam_list_exactly_when_the_gateway_refuses_it_bare() {
    const PROBE: [&str; 23] = [
        "NoSuchKey",
        "NoSuchVersion",
        "NoSuchBucket",
        "PermanentRedirect",
        "TemporaryRedirect",
        "NotModified",
        "AuthorizationHeaderMalformed",
        "MethodNotAllowed",
        "BucketAlreadyOwnedByYou",
        "AccessForbidden",
        "InvalidRange",
        "AccessDenied",
        "InvalidArgument",
        "InvalidRequest",
        "PreconditionFailed",
        "SlowDown",
        "InternalError",
        "EntityTooLarge",
        "BadDigest",
        "InvalidDigest",
        "MalformedXML",
        "NotImplemented",
        "RequestTimeTooSkewed",
    ];
    for name in PROBE {
        let code = ErrorCode::known(name).unwrap_or_else(|| panic!("{name} is a gateway code"));
        let refused_bare = ErrorContext::ordinary(HandlerError::new(code, "m")).is_err();
        let listed = CONTEXTUAL_CODES.contains(&name) || NEEDS_FACTS_CODES.contains(&name);
        assert_eq!(refused_bare, listed, "{name}");
    }
}

#[test]
fn n_a_status_other_than_the_codes_own_becomes_a_custom_code_carrying_it() {
    let Ok(Refusal::Ordinary { code, .. }) = refusal_from_s3s(&conflicting_request()) else {
        panic!("a known code at another status is ordinary");
    };
    assert_eq!((code.as_str(), code.default_status()), ("InvalidRequest", StatusCode::CONFLICT));
    assert_ne!(code, ErrorCode::INVALID_REQUEST);
}

#[test]
fn n_a_code_that_is_not_an_identifier_is_refused_by_name() {
    let code = S3ErrorCode::from_bytes(b"Not-An-Identifier").unwrap_or(S3ErrorCode::InternalError);
    let refused = refusal_from_s3s(&S3Error::with_message(code, "m")).map_err(|error| error.field);
    assert_eq!(refused, Err("code"));
}

#[test]
fn n_a_status_that_is_not_a_refusal_is_refused_by_name() {
    let mut error = S3Error::with_message(S3ErrorCode::InvalidRequest, "m");
    error.set_status_code(StatusCode::FOUND);
    assert_eq!(refusal_from_s3s(&error).map_err(|error| error.field), Err("status_code"));
}

#[test]
fn n_text_xml_cannot_carry_is_refused_by_name() {
    let error = S3Error::with_message(S3ErrorCode::InvalidArgument, "Invalid argument: \u{1}");
    assert_eq!(refusal_from_s3s(&error).map_err(|error| error.field), Err("message"));
}

/// The cut lands on a character boundary: 1023 ASCII bytes and a two-byte character keep 1023.
#[test]
fn n_a_message_past_the_gateway_bound_is_cut_on_a_character_boundary() {
    let text = format!("{}é", "a".repeat(MAX_MESSAGE_BYTES - 1));
    let Ok(Refusal::Ordinary { message, .. }) = refusal_from_s3s(&S3Error::with_message(S3ErrorCode::InvalidArgument, text))
    else {
        panic!("a long message is ordinary");
    };
    assert_eq!(message.len(), MAX_MESSAGE_BYTES - 1);
}

/// RustFS re-adds `Content-Type` to an error's header map because s3s replaces the head with it;
/// the gateway writes that header itself. Any other header has no gateway member.
#[test]
fn n_response_headers_other_than_content_type_are_refused_by_name() {
    let with = |name: &'static str| {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static("x"));
        let mut error = S3Error::with_message(S3ErrorCode::AccessDenied, "Access Denied.");
        error.set_headers(headers);
        refusal_from_s3s(&error).map(|_| ()).map_err(|error| error.field)
    };
    assert_eq!(with("content-type"), Ok(()));
    assert_eq!(with("x-amz-delete-marker"), Err("headers"));
    assert_eq!(with("retry-after"), Err("headers"));
}

/// The harness's success path is exercised too, so a scenario that refuses is never a harness that
/// cannot answer.
#[test]
fn a_body_that_succeeds_is_answered_200_by_both_stacks() {
    let scenario = Scenario::new(location().signed("us-east-1"));
    assert!(matches!(scenario.body, AppBody::Succeeds));
    let pair = super::both(&scenario).expect("both stacks answer");
    assert_eq!((pair.gateway.status, pair.oracle.status), (200, 200), "{pair:#?}");
}
