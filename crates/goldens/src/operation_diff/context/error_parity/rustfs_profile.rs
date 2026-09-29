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

//! The RustFS profile's answers to a RustFS body's errors (rustfs/gateway#1148): the adapter reads
//! each error as the legacy stack writes it (`refusal_from_legacy`) and answers it as that
//! (`HandlerErrorContext::legacy_rustfs`), so both stacks write the same status, the same fact
//! headers and the same document.
//!
//! Responsible for: every error shape legacy RustFS returns on the read path and beyond — the
//! conditional `GET` and `HEAD` `304`s, the `416` without `Content-Range`, both delete-marker reads
//! with and without their instant, a message past 1024 bytes, contextual codes, an absent
//! `<Message>`, and every error the mapping rows carry — answered alike; and the controls: the same
//! errors through the typed reading answer `500` where the typed verdict cannot state them, and a
//! shape the legacy reading refuses answers `500` on the gateway where the legacy stack answers.
//! NOT responsible for: the typed reading's rows and rulings (`super::divergences`, rd-err-0005 to
//! rd-err-0008), the request id and host id only the gateway stamps (rd-err-0001, compared there),
//! or a `HEAD` answer's `Content-Length` and `Content-Type` (the RustFS profile's `HEAD` rule,
//! rustfs/gateway#1120).
//! Upstream: `super`, `super::legacy_reading`, `super::mapping`. Downstream: nothing.

use super::super::super::SEAM_REVISION;
use super::super::ContextRequest;
use super::legacy_reading::{legacy_marker, legacy_not_modified};
use super::mapping::APP_BODY_ERRORS;
use super::matrix::{location, object_get, object_head, object_put};
use super::s3s;
use super::{Pair, Reply, SEAM_REFUSED, Scenario, both};
use http::StatusCode;
use rustfs_gateway_types::compat::OracleRevision;
use s3s::{S3Error, S3ErrorCode};

/// The fact headers a RustFS error states, compared line for line.
const FACTS: [&str; 5] = [
    "etag",
    "last-modified",
    "content-range",
    "x-amz-delete-marker",
    "x-amz-version-id",
];

/// A RustFS body's error, spelled as the body builds it.
type BodyError = fn() -> S3Error;

/// The two elements only the gateway writes, last in its document (rd-err-0001).
const STAMPED: [&str; 2] = ["RequestId", "HostId"];

/// Both answers to one request, and whether it was a `HEAD`.
#[derive(Debug)]
struct Answers {
    pair: Pair,
    head: bool,
}

/// What one reply puts on the wire as its body: nothing for a `HEAD` or a bodyless status, which
/// hyper sends without the document the pinned legacy service may still have written (the baseline
/// revision writes one on a `304`, and both write one on a `HEAD` refusal).
fn wire_body(reply: &Reply, head: bool) -> Option<&str> {
    (!head && !matches!(reply.status, 100..=199 | 204 | 304)).then_some(reply.body.as_str())
}

/// Every way the two answers to one request differ beyond rd-err-0001: status, a fact header, the
/// document's type, its elements, and each element's text. A `HEAD` answer's own framing is the
/// RustFS profile's `HEAD` rule (rustfs/gateway#1120) and is not compared here.
fn differences(answers: &Answers) -> Vec<String> {
    let Pair { gateway, oracle } = &answers.pair;
    let mut found = Vec::new();
    if gateway.status != oracle.status {
        found.push(format!("status {} against {}", gateway.status, oracle.status));
    }
    let bodies = (wire_body(gateway, answers.head), wire_body(oracle, answers.head));
    for name in FACTS.into_iter().chain(bodies.1.is_some().then_some("content-type")) {
        if gateway.headers.get(name) != oracle.headers.get(name) {
            found.push(format!("{name}: {:?} against {:?}", gateway.headers.get(name), oracle.headers.get(name)));
        }
    }
    match bodies {
        (Some(_), Some(_)) => {
            let written: Vec<&str> = gateway
                .elements()
                .into_iter()
                .filter(|name| !STAMPED.contains(name))
                .collect();
            if written != oracle.elements() {
                found.push(format!("elements {written:?} against {:?}", oracle.elements()));
            }
            for name in oracle.elements() {
                if gateway.element(name) != oracle.element(name) {
                    found.push(format!("{name}: {:?} against {:?}", gateway.element(name), oracle.element(name)));
                }
            }
        }
        (None, None) if gateway.body.is_empty() => {}
        _ => found.push(format!("body {:?} against {:?}", gateway.body, oracle.body)),
    }
    found
}

/// Both stacks' answers to `request` when the RustFS body answers `error`, read as the RustFS
/// profile reads it.
fn answered(request: ContextRequest, error: BodyError) -> Answers {
    let head = request.method == http::Method::HEAD;
    let scenario = Scenario::new(request.signed("us-east-1")).rustfs_profile().app_refuses(error);
    Answers {
        pair: both(&scenario).expect("both stacks answer"),
        head,
    }
}

/// `request` answered alike on both stacks, and both answers.
fn same(request: ContextRequest, error: BodyError) -> Pair {
    let answers = answered(request, error);
    assert_eq!(differences(&answers), Vec::<String>::new(), "{answers:#?}");
    assert!(answers.pair.gateway.reached && answers.pair.oracle.reached, "{answers:#?}");
    answers.pair
}

/// A reply with no body and no framing of one.
fn bodyless(reply: &Reply) {
    assert!(reply.body.is_empty(), "{reply:#?}");
    assert_eq!((reply.header("content-type"), reply.header("content-length")), (None, None), "{reply:#?}");
}

// ── answered as legacy RustFS answers ─────────────────────────────────────────────────────────

/// The `304` of a conditional `GET` carries both validators on both stacks; the one of an
/// `If-Modified-Since` read of an object without an entity tag carries the instant alone; and the
/// `304` of a conditional `HEAD` carries neither, on both.
#[test]
fn every_not_modified_legacy_rustfs_writes_is_the_same_304() {
    let rows: [(ContextRequest, BodyError, bool, bool); 4] = [
        (
            object_get(),
            || legacy_not_modified(&[("etag", "\"abc\""), ("last-modified", "Fri, 02 Jan 2026 03:04:05 GMT")]),
            true,
            true,
        ),
        (
            object_get(),
            || legacy_not_modified(&[("last-modified", "Fri, 02 Jan 2026 03:04:05 GMT")]),
            false,
            true,
        ),
        (object_head(), || S3Error::new(S3ErrorCode::NotModified), false, false),
        (object_get(), || S3Error::new(S3ErrorCode::NotModified), false, false),
    ];
    for (request, error, etag, instant) in rows {
        let pair = same(request.header("if-none-match", b"\"abc\""), error);
        assert_eq!(pair.gateway.status, 304, "{pair:#?}");
        assert_eq!(
            (pair.gateway.header("etag").is_some(), pair.gateway.header("last-modified").is_some()),
            (etag, instant),
            "{pair:#?}"
        );
        bodyless(&pair.gateway);
        // The revision RustFS links writes no document and no type on a `304`; the baseline
        // oracle's own document is dropped on the wire, and its type is its own.
        if SEAM_REVISION == OracleRevision::Candidate {
            bodyless(&pair.oracle);
        }
    }
}

/// A `416` with no `Content-Range` and only `Code` and `Message` in its document, on both stacks;
/// the length crosses when the RustFS body states it, and no element is added.
#[test]
fn an_invalid_range_is_the_same_416_with_or_without_its_length() {
    let rows: [BodyError; 2] = [
        || S3Error::with_message(S3ErrorCode::InvalidRange, "The requested range is not satisfiable"),
        || super::facts::unsatisfiable(),
    ];
    for error in rows {
        let pair = same(object_get().header("range", b"bytes=100-200"), error);
        assert_eq!(pair.gateway.status, 416, "{pair:#?}");
        assert_eq!(pair.gateway.element("RangeRequested"), None, "{pair:#?}");
    }
    same(object_get(), || S3Error::with_message(S3ErrorCode::InvalidRange, "no range to name"));
}

/// A read of a key whose current version is a delete marker is the `404` with the flag and the
/// version id and no `Last-Modified`, on `GET` and `HEAD`; a read naming the marker's version is
/// the `405` with all three. A null marker keeps its `null` id.
#[test]
fn every_delete_marker_read_is_the_same_answer() {
    let rows: [(ContextRequest, BodyError, u16); 5] = [
        (
            object_get(),
            || legacy_marker(S3ErrorCode::NoSuchKey, super::facts::MARKER_VERSION, false),
            404,
        ),
        (
            object_head(),
            || legacy_marker(S3ErrorCode::NoSuchKey, super::facts::MARKER_VERSION, false),
            404,
        ),
        (object_get(), || legacy_marker(S3ErrorCode::NoSuchKey, "null", false), 404),
        (
            object_get(),
            || legacy_marker(S3ErrorCode::MethodNotAllowed, super::facts::MARKER_VERSION, true),
            405,
        ),
        (
            object_head(),
            || legacy_marker(S3ErrorCode::MethodNotAllowed, super::facts::MARKER_VERSION, true),
            405,
        ),
    ];
    for (request, error, status) in rows {
        let pair = same(request, error);
        assert_eq!((pair.gateway.status, pair.oracle.status), (status, status), "{pair:#?}");
        assert_eq!(pair.gateway.element("Key"), None, "{pair:#?}");
    }
}

/// A message longer than 1024 bytes crosses whole (rd-err-0007's typed reading cuts it).
#[test]
fn a_message_past_1024_bytes_is_written_whole_on_both_stacks() {
    let pair = same(location(), || {
        S3Error::with_message(S3ErrorCode::InvalidArgument, format!("Invalid argument: {}", "x".repeat(1500)))
    });
    assert_eq!(pair.gateway.message().map(str::len), Some(1518), "{pair:#?}");
}

/// Codes the gateway otherwise renders only from typed context, and a document with no
/// `<Message>`, cross exactly as legacy RustFS writes them.
#[test]
fn contextual_codes_and_absent_messages_are_the_same_answer() {
    let rows: [BodyError; 7] = [
        || {
            S3Error::with_message(
                S3ErrorCode::BucketAlreadyOwnedByYou,
                "Your previous request to create the named bucket succeeded and you already own it.",
            )
        },
        || {
            S3Error::with_message(
                S3ErrorCode::MethodNotAllowed,
                "The specified method is not allowed against this resource.",
            )
        },
        || S3Error::new(S3ErrorCode::NoSuchVersion),
        || S3Error::with_message(S3ErrorCode::NoSuchVersion, "The specified version does not exist."),
        || S3Error::new(S3ErrorCode::NoSuchBucket),
        || S3Error::with_message(S3ErrorCode::NoSuchKey, "The specified key does not exist."),
        || {
            S3Error::with_message(
                S3ErrorCode::AuthorizationHeaderMalformed,
                "The authorization header is malformed; the region is wrong; expecting 'us-east-1'.",
            )
        },
    ];
    for error in rows {
        for request in [object_get(), location()] {
            same(request, error);
        }
    }
}

/// Every error the mapping rows carry, through the RustFS profile, is the same answer.
#[test]
fn every_app_body_error_is_the_same_answer_in_the_rustfs_profile() {
    for (error, status, code) in APP_BODY_ERRORS {
        for request in [location(), object_put(b"")] {
            let pair = same(request, error);
            assert_eq!((pair.gateway.status, pair.gateway.code()), (status, Some(code)), "{pair:#?}");
        }
    }
}

// ── controls ──────────────────────────────────────────────────────────────────────────────────

/// Negative — the typed reading of the same errors answers `500` where its verdicts cannot state
/// them, so the rows above measure the RustFS profile's reading and nothing else.
#[test]
fn n_the_typed_reading_answers_the_same_errors_500() {
    let rows: [(ContextRequest, BodyError); 5] = [
        (object_get(), || {
            legacy_not_modified(&[("etag", "\"abc\""), ("last-modified", "Fri, 02 Jan 2026 03:04:05 GMT")])
        }),
        (object_head(), || S3Error::new(S3ErrorCode::NotModified)),
        (object_get(), || {
            S3Error::with_message(S3ErrorCode::InvalidRange, "The requested range is not satisfiable")
        }),
        (object_get(), || {
            legacy_marker(S3ErrorCode::NoSuchKey, super::facts::MARKER_VERSION, false)
        }),
        (location(), || S3Error::with_message(S3ErrorCode::BucketAlreadyOwnedByYou, "owned")),
    ];
    for (request, error) in rows {
        let head = request.method == http::Method::HEAD;
        let typed = both(&Scenario::new(request.clone().signed("us-east-1")).app_refuses(error)).expect("both stacks answer");
        assert_eq!(typed.gateway.status, 500, "{typed:#?}");
        assert_ne!(typed.oracle.status, 500, "{typed:#?}");
        let typed = Answers { pair: typed, head };
        assert!(differences(&typed).iter().any(|found| found.starts_with("status")), "{typed:#?}");
        same(request, error);
    }
}

/// Negative — a shape the legacy reading cannot write back the same way (an entity tag the gateway
/// would requote, an untyped document, an instant in another spelling) is the adapter's `500`,
/// never a different answer passed off as the legacy one.
#[test]
fn n_a_shape_the_gateway_cannot_write_alike_is_refused_not_rewritten() {
    let rows: [(ContextRequest, BodyError); 3] = [
        (object_get(), || legacy_not_modified(&[("etag", "abc")])),
        (object_get(), || {
            let mut error = S3Error::new(S3ErrorCode::NoSuchKey);
            let mut headers = http::HeaderMap::new();
            headers.insert("x-amz-delete-marker", http::HeaderValue::from_static("true"));
            headers.insert("x-amz-version-id", http::HeaderValue::from_static("v1"));
            error.set_headers(headers);
            error
        }),
        (object_get(), || legacy_not_modified(&[("last-modified", "Fri, 2 Jan 2026 03:04:05 GMT")])),
    ];
    for (request, error) in rows {
        let pair = answered(request, error).pair;
        assert_eq!(pair.gateway.status, 500, "{pair:#?}");
        assert_eq!(pair.gateway.message(), Some(SEAM_REFUSED), "{pair:#?}");
        assert_ne!(pair.oracle.status, 500, "{pair:#?}");
    }
}

/// Negative — the comparison itself sees each kind of difference: a status, a fact header, an
/// element and an element's text.
#[test]
fn n_the_comparison_names_every_kind_of_difference() {
    let base = answered(object_get(), || S3Error::with_message(S3ErrorCode::InvalidRange, "range"));
    assert_eq!(differences(&base), Vec::<String>::new(), "{base:#?}");
    let skew = |edit: fn(&mut Reply)| {
        let mut answers = answered(object_get(), || S3Error::with_message(S3ErrorCode::InvalidRange, "range"));
        edit(&mut answers.pair.gateway);
        differences(&answers)
    };
    let status = skew(|reply| reply.status = StatusCode::NOT_FOUND.as_u16());
    assert!(status.iter().any(|found| found.starts_with("status")), "{status:?}");
    let header = skew(|reply| {
        reply
            .headers
            .insert("content-range".to_owned(), vec!["bytes */10".to_owned()]);
    });
    assert!(header.iter().any(|found| found.starts_with("content-range")), "{header:?}");
    let element = skew(|reply| reply.body = reply.body.replace("<Message>", "<Key>k</Key><Message>"));
    assert!(element.iter().any(|found| found.starts_with("elements")), "{element:?}");
    let text = skew(|reply| reply.body = reply.body.replace("<Message>range", "<Message>other"));
    assert!(text.iter().any(|found| found.starts_with("Message")), "{text:?}");
}
