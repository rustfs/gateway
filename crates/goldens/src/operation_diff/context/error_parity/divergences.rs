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
//! Responsible for: observing each divergence on both stacks, and, for a refusal whose facts ride
//! in the s3s error's headers, the error RustFS writes today that cannot cross without them.
//! NOT responsible for: the rulings (`migration_inventory/request_divergences.rs`), or the rows
//! both stacks answer alike (`super::matrix`, `super::mapping`).
//! Upstream: `super`, `super::matrix`. Downstream: the request-divergence register guard.

use super::super::{ContextRequest, PATH_HOST};
use super::facts;
use super::matrix::{
    Expect, NOT_ALLOWED, NOT_AUTHENTICATED, SKEWED, UNREPRESENTABLE, identifiers, location, object_get, object_head, object_put,
    part_put, refused_alike,
};
use super::s3s;
use super::{Pair, SEAM_REFUSED, Scenario, both};
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

/// The RustFS body refuses a non-empty PutObject or UploadPart without reading it, as it does for
/// a missing bucket, its own access check, quota and throttling. Both stacks answer the body's
/// refusal, and the gateway keeps the connection: the unread octets are the transport's to linger
/// over, not a framing fault to close on. The empty body is the control that never had a body to
/// drop.
///
/// Ruling: `rd-err-0004`
#[test]
fn the_app_bodys_refusal_before_reading_a_streaming_body_is_the_answer_on_both_stacks() {
    let refused = || S3Error::with_message(S3ErrorCode::AccessDenied, "Access Denied.");
    for request in [object_put(b"hello"), part_put(b"hello"), object_put(b"")] {
        refused_alike(
            &Scenario::new(request.signed("us-east-1")).app_refuses(refused),
            Expect::app_body(403, "AccessDenied"),
        );
    }
}

/// The entity tag rides in the error's `ETag` header, where s3s already writes it from; the seam
/// hands it over and both stacks answer the AWS `304`, on GET and on HEAD. RustFS today attaches no
/// tag, and that error cannot cross: the gateway would have to invent the validator.
///
/// Ruling: `rd-err-0005`
#[test]
fn a_not_modified_carrying_its_entity_tag_is_304_with_it_on_both_stacks() {
    for request in [object_get(), object_head()] {
        let request = request.header("if-none-match", b"\"abc\"").signed("us-east-1");
        let pair = answered(&Scenario::new(request.clone()).app_refuses(facts::not_modified));
        for reply in [&pair.gateway, &pair.oracle] {
            assert_eq!((reply.status, reply.header("etag")), (304, Some("\"abc\"")), "{pair:#?}");
        }
        // The pinned s3s writes an error document on a 304 that hyper then drops from the wire; the
        // gateway writes none to drop.
        let gateway = &pair.gateway;
        assert!(gateway.body.is_empty() && gateway.header("content-type").is_none(), "{pair:#?}");

        let today = answered(&Scenario::new(request).app_refuses(|| S3Error::new(S3ErrorCode::NotModified)));
        assert_eq!((today.oracle.status, today.oracle.header("etag")), (304, None), "{today:#?}");
        assert_eq!(today.gateway.status, 500, "the seam, not the gateway, refused: {today:#?}");
    }
}

/// The complete length rides in the error's unsatisfied `Content-Range`; both stacks answer `416`
/// with it, and the gateway adds the AWS document elements naming the range and the length. RustFS
/// today writes no `Content-Range`, and that error cannot cross.
///
/// Ruling: `rd-err-0006`
#[test]
fn an_invalid_range_carrying_its_length_is_416_with_content_range_on_both_stacks() {
    let request = object_get().header("range", b"bytes=100-200").signed("us-east-1");
    let pair = answered(&Scenario::new(request.clone()).app_refuses(facts::unsatisfiable));
    for reply in [&pair.gateway, &pair.oracle] {
        assert_eq!(
            (reply.status, reply.code(), reply.header("content-range")),
            (416, Some("InvalidRange"), Some("bytes */10")),
            "{pair:#?}"
        );
    }
    assert_eq!(pair.gateway.element("RangeRequested"), Some("bytes=100-200"), "{pair:#?}");
    assert_eq!(pair.oracle.element("RangeRequested"), None, "{pair:#?}");

    let today = || S3Error::with_message(S3ErrorCode::InvalidRange, "The requested range is not satisfiable");
    let today = answered(&Scenario::new(request).app_refuses(today));
    assert_eq!((today.oracle.status, today.oracle.header("content-range")), (416, None), "{today:#?}");
    assert_eq!(
        (today.gateway.status, today.gateway.message()),
        (500, Some(SEAM_REFUSED)),
        "the seam, not the gateway, refused: {today:#?}"
    );

    // A 416 names the range it refused; with no `Range` on the request there is none to name.
    let rangeless = answered(&Scenario::new(object_get().signed("us-east-1")).app_refuses(facts::unsatisfiable));
    assert_eq!((rangeless.gateway.status, rangeless.oracle.status), (500, 416), "{rangeless:#?}");
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

/// Both marker reads cross with the marker flag and the instant on both stacks: the `404` a read
/// naming no version gets, and the `405` a read naming the marker's version id gets. Only s3s writes
/// the version id, which the gateway's marker refusals do not carry yet (rustfs/gateway#899). RustFS
/// today writes no `Last-Modified` on the current-marker `404`, and that error cannot cross.
///
/// Ruling: `rd-err-0008`
#[test]
fn an_error_carrying_delete_marker_headers_crosses_as_the_marker_read() {
    let versioned_query = format!("versionId={}", facts::MARKER_VERSION);
    let rows = [
        (object_get(), facts::current_marker as fn() -> S3Error, 404, "NoSuchKey"),
        (object_head(), facts::current_marker, 404, "NoSuchKey"),
        (
            ContextRequest::get(PATH_HOST, "/photos/a.txt", &versioned_query),
            facts::versioned_marker,
            405,
            "MethodNotAllowed",
        ),
    ];
    for (request, error, status, code) in rows {
        let head = request.method == http::Method::HEAD;
        let pair = answered(&Scenario::new(request.signed("us-east-1")).app_refuses(error));
        for reply in [&pair.gateway, &pair.oracle] {
            assert_eq!(reply.status, status, "{pair:#?}");
            assert_eq!(reply.header("x-amz-delete-marker"), Some("true"), "{pair:#?}");
            assert_eq!(reply.header("last-modified"), Some(facts::MARKER_WRITTEN), "{pair:#?}");
        }
        // A HEAD answer has no document on the gateway; s3s writes one hyper drops from the wire.
        if head {
            assert!(pair.gateway.body.is_empty(), "{pair:#?}");
        } else {
            assert_eq!((pair.gateway.code(), pair.oracle.code()), (Some(code), Some(code)), "{pair:#?}");
        }
        assert_eq!(
            (pair.gateway.header("x-amz-version-id"), pair.oracle.header("x-amz-version-id")),
            (None, Some(facts::MARKER_VERSION)),
            "{pair:#?}"
        );
    }

    let today = || {
        let mut error = facts::current_marker();
        let mut headers = error.headers().cloned().unwrap_or_default();
        headers.remove("last-modified");
        error.set_headers(headers);
        error
    };
    let today = answered(&Scenario::new(object_get().signed("us-east-1")).app_refuses(today));
    assert_eq!(
        (today.oracle.status, today.oracle.header("x-amz-delete-marker")),
        (404, Some("true")),
        "{today:#?}"
    );
    assert_eq!(
        (today.gateway.status, today.gateway.message()),
        (500, Some(SEAM_REFUSED)),
        "the seam, not the gateway, refused: {today:#?}"
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
