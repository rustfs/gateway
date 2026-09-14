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

//! The named error-document divergences (rd-err): where the two answers to one refused request
//! differ, each pinned by one test carrying its register id.
//!
//! Responsible for: observing each divergence on both stacks, and, where the seam cannot carry a
//! refusal, the answer the gateway gives once the adapter supplies the facts.
//! NOT responsible for: the rulings (`migration_inventory/request_divergences.rs`), or the rows
//! both stacks answer alike (`super::matrix`, `super::mapping`).
//! Upstream: `super`, `super::matrix`. Downstream: the request-divergence register guard.

use super::super::{ContextRequest, PATH_HOST};
use super::matrix::{
    Expect, NOT_ALLOWED, NOT_AUTHENTICATED, SKEWED, UNREPRESENTABLE, identifiers, location, object_get, object_put, refused_alike,
};
use super::s3s;
use super::{Pair, SEAM_REFUSED, Scenario, both};
use http::{HeaderMap, HeaderValue};
use rustfs_gateway::{ETag, HandlerError, HandlerErrorContext};
use s3s::{S3Error, S3ErrorCode};

fn answered(scenario: &Scenario) -> Pair {
    both(scenario).expect("both stacks answer")
}

fn unrepresentable_query() -> Scenario {
    Scenario::new(ContextRequest::get(PATH_HOST, "/photos/a.txt", "response-expires=notadate").signed("us-east-1"))
}

// ── the named divergences (rd-err) ────────────────────────────────────────────────────────────

/// The gateway puts one request id and one host id in the head and, last, in the document; the
/// s3s service writes neither (RustFS adds the header in a layer outside it).
///
/// Ruling: `rd-err-0001`
#[test]
fn only_the_gateway_identifies_the_request_in_its_head_and_document() {
    let pair = answered(&Scenario::new(location()));
    assert_eq!((pair.gateway.status, pair.oracle.status), (403, 403), "{pair:#?}");
    identifiers(&pair.gateway, &pair.oracle);
}

/// Ruling: `rd-err-0002`
#[test]
fn a_missing_key_is_named_in_the_document_only_by_the_gateway() {
    let scenario = Scenario::new(object_get().signed("us-east-1"))
        .app_refuses(|| S3Error::with_message(S3ErrorCode::NoSuchKey, "The specified key does not exist."));
    let pair = refused_alike(&scenario, Expect::app_body(404, "NoSuchKey"));
    assert_eq!(pair.gateway.elements(), ["Code", "Message", "Key", "RequestId", "HostId"], "{pair:#?}");
    assert_eq!(pair.gateway.element("Key"), Some("a.txt"));
    assert_eq!(pair.oracle.elements(), ["Code", "Message"], "{pair:#?}");
}

/// A failed signature with a body still owed: the same refusal on both, and a close only the
/// gateway states. With nothing owed the gateway keeps the connection too.
///
/// Ruling: `rd-err-0003`
#[test]
fn a_refusal_that_leaves_its_body_owed_closes_only_on_the_gateway() {
    let forged = Expect::gateway_first(403, "SignatureDoesNotMatch", NOT_AUTHENTICATED, false);
    let owed = Scenario::new(object_put(b"hello world").signed("us-east-1").forged());
    let pair = refused_alike(&owed, Expect { closes: true, ..forged });
    assert!(!pair.oracle.headers.contains_key("connection"), "{pair:#?}");
    refused_alike(&Scenario::new(object_put(b"").signed("us-east-1").forged()), forged);
}

/// The RustFS body refuses a non-empty PutObject without reading it. In process the gateway's
/// body verdict replaces the refusal; with nothing to read the refusal crosses as itself.
///
/// Ruling: `rd-err-0004`
#[test]
fn the_app_bodys_refusal_before_reading_a_put_body_is_replaced_in_process() {
    let refused = || S3Error::with_message(S3ErrorCode::AccessDenied, "Access Denied.");
    let pair = answered(&Scenario::new(object_put(b"hello").signed("us-east-1")).app_refuses(refused));
    assert!(pair.gateway.reached, "{pair:#?}");
    assert_eq!(
        (pair.gateway.status, pair.gateway.code(), pair.gateway.closes),
        (400, Some("IncompleteBody"), Some(true)),
        "{pair:#?}"
    );
    assert_eq!((pair.oracle.status, pair.oracle.code()), (403, Some("AccessDenied")), "{pair:#?}");
    refused_alike(
        &Scenario::new(object_put(b"").signed("us-east-1")).app_refuses(refused),
        Expect::app_body(403, "AccessDenied"),
    );
}

/// RustFS answers `304` with no entity tag; the seam cannot hand over what the error does not
/// carry, so the adapter answers `500`. Given the tag, the gateway writes the AWS `304`.
///
/// Ruling: `rd-err-0005`
#[test]
fn a_not_modified_from_the_app_body_needs_its_entity_tag_to_cross() {
    let request = object_get().header("if-none-match", b"\"abc\"").signed("us-east-1");
    let pair = answered(&Scenario::new(request.clone()).app_refuses(|| S3Error::new(S3ErrorCode::NotModified)));
    assert_eq!((pair.oracle.status, pair.oracle.header("etag")), (304, None), "{pair:#?}");
    assert_eq!(
        (pair.gateway.status, pair.gateway.code(), pair.gateway.message()),
        (500, Some("InternalError"), Some(SEAM_REFUSED)),
        "the seam, not the gateway's resolution, refused: {pair:#?}"
    );

    let native = answered(
        &Scenario::new(request).gateway_native(|| HandlerErrorContext::not_modified(ETag::new("abc").expect("a tag")).into()),
    );
    let gateway = &native.gateway;
    assert_eq!((gateway.status, gateway.header("etag")), (304, Some("\"abc\"")), "{native:#?}");
    assert!(gateway.body.is_empty() && gateway.header("content-type").is_none(), "{native:#?}");
}

/// RustFS answers `416` without `Content-Range`; the gateway renders one only with the complete
/// length, so through the seam it is a `500`. Given the length, the gateway writes the AWS `416`.
///
/// Ruling: `rd-err-0006`
#[test]
fn an_unsatisfiable_range_from_the_app_body_needs_its_length_to_cross() {
    let request = object_get().header("range", b"bytes=100-200").signed("us-east-1");
    let refused = || S3Error::with_message(S3ErrorCode::InvalidRange, "The requested range is not satisfiable");
    let pair = answered(&Scenario::new(request.clone()).app_refuses(refused));
    assert_eq!(
        (pair.oracle.status, pair.oracle.code(), pair.oracle.header("content-range")),
        (416, Some("InvalidRange"), None),
        "{pair:#?}"
    );
    assert_eq!(
        (pair.gateway.status, pair.gateway.code(), pair.gateway.message()),
        (500, Some("InternalError"), Some(SEAM_REFUSED)),
        "the seam, not the gateway's resolution, refused: {pair:#?}"
    );

    let native = answered(&Scenario::new(request).gateway_native(|| HandlerError::unsatisfiable_range("bytes=100-200", 10)));
    let gateway = &native.gateway;
    assert_eq!((gateway.status, gateway.code()), (416, Some("InvalidRange")), "{native:#?}");
    assert_eq!(gateway.header("content-range"), Some("bytes */10"), "{native:#?}");
    assert_eq!(gateway.element("RangeRequested"), Some("bytes=100-200"), "{native:#?}");
}

/// Ruling: `rd-err-0007`
#[test]
fn a_message_past_1024_bytes_is_cut_only_on_the_gateway() {
    let long = || S3Error::with_message(S3ErrorCode::InvalidArgument, format!("Invalid argument: {}", "x".repeat(1500)));
    let pair = answered(&Scenario::new(location().signed("us-east-1")).app_refuses(long));
    assert_eq!((pair.gateway.status, pair.oracle.status), (400, 400), "{pair:#?}");
    let whole = pair.oracle.message().expect("s3s writes the message");
    assert_eq!(whole.len(), 1518);
    assert_eq!(pair.gateway.message(), whole.get(..1024), "{pair:#?}");
}

fn delete_marker_miss() -> S3Error {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/xml"));
    headers.insert("x-amz-delete-marker", HeaderValue::from_static("true"));
    headers.insert("x-amz-version-id", HeaderValue::from_static("null"));
    let mut error = S3Error::with_message(S3ErrorCode::NoSuchKey, "The specified key does not exist.");
    error.set_headers(headers);
    error
}

/// Ruling: `rd-err-0008`
#[test]
fn an_error_carrying_delete_marker_headers_needs_typed_facts_to_cross() {
    let pair = answered(&Scenario::new(object_get().signed("us-east-1")).app_refuses(delete_marker_miss));
    assert_eq!(
        (pair.oracle.status, pair.oracle.header("x-amz-delete-marker")),
        (404, Some("true")),
        "{pair:#?}"
    );
    assert_eq!(
        (pair.gateway.status, pair.gateway.code(), pair.gateway.message()),
        (500, Some("InternalError"), Some(SEAM_REFUSED)),
        "the seam, not the gateway's resolution, refused: {pair:#?}"
    );
}

/// The same code, the gateway's fixed sentence against the s3s description — which, for the query
/// member, repeats what the caller sent.
///
/// Ruling: `rd-err-0009`
#[test]
fn a_refusal_before_the_handler_carries_the_gateways_own_sentence() {
    let rows = [
        (
            Scenario::new(location().signed("us-east-1")).signed_at_offset(-1200),
            "RequestTimeTooSkewed",
            SKEWED,
            "request time is too far from server time",
        ),
        (
            Scenario::new(object_get().signed("us-east-1"))
                .presigned(60)
                .signed_at_offset(-3600),
            "AccessDenied",
            NOT_ALLOWED,
            "Request has expired",
        ),
        (
            unrepresentable_query(),
            "InvalidArgument",
            UNREPRESENTABLE,
            "invalid query: response-expires: notadate",
        ),
    ];
    for (scenario, code, sentence, s3s_says) in rows {
        let pair = answered(&scenario);
        assert_eq!((pair.gateway.code(), pair.oracle.code()), (Some(code), Some(code)), "{pair:#?}");
        assert_eq!(
            (pair.gateway.message(), pair.oracle.message()),
            (Some(sentence), Some(s3s_says)),
            "{pair:#?}"
        );
        assert!(!pair.gateway.body.contains("notadate"), "{pair:#?}");
    }
}

/// Ruling: `rd-err-0010`
#[test]
fn a_codec_refusal_names_its_member_as_the_resource_only_on_the_gateway() {
    let expect = Expect {
        resource: Some("ResponseExpires"),
        ..Expect::gateway_first(400, "InvalidArgument", UNREPRESENTABLE, false)
    };
    let pair = refused_alike(&unrepresentable_query(), expect);
    assert_eq!(
        pair.gateway.elements(),
        ["Code", "Message", "Resource", "RequestId", "HostId"],
        "{pair:#?}"
    );
    assert_eq!(pair.oracle.elements(), ["Code", "Message"], "{pair:#?}");
}
