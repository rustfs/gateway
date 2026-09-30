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

//! The RustFS profile's reading of a RustFS body's error (`refusal_from_legacy`,
//! rustfs/gateway#1148): every value exactly as the legacy stack writes it, and a refusal by name of
//! every shape the gateway cannot write back the same way.
//!
//! Responsible for: the values read from the errors legacy RustFS returns — the two `304`s, the
//! `416`, both delete-marker reads with and without their instant, contextual codes, absent and
//! long messages — and each refusal: an unreadable code, a status the legacy answer cannot have, a
//! message XML cannot carry, a header its code does not state, an untyped document, and a fact
//! repeated or spelled otherwise than the gateway writes it.
//! NOT responsible for: the answers both stacks write for these (`super::rustfs_profile`), or the
//! typed reading every other assembly keeps (`super::facts`).
//! Upstream: `compat::error`. Downstream: nothing.

use super::super::super::seam::error::{LegacyRefusal, refusal_from_legacy};
use super::facts::{MARKER_VERSION, MARKER_WRITTEN, MARKER_WRITTEN_SECONDS, carrying};
use super::s3s;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rustfs_gateway::{ETag, ErrorCode};
use s3s::{S3Error, S3ErrorCode};

/// The `ETag` and `Last-Modified` legacy RustFS writes on the `304` of a conditional `GET`.
const VALIDATORS: [(&str, &str); 2] = [("etag", "\"abc\""), ("last-modified", MARKER_WRITTEN)];

/// `lines` as the error's whole header map, with no `Content-Type` re-added.
fn bare(code: S3ErrorCode, lines: &[(&'static str, &'static str)]) -> S3Error {
    let mut headers = HeaderMap::new();
    for (name, value) in lines {
        headers.append(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    let mut error = S3Error::new(code);
    error.set_headers(headers);
    error
}

/// The `304` legacy RustFS writes for a conditional `GET` (`ecfs_extend.rs:557-604`): its status
/// set, the message it names, the two validators and no `Content-Type`.
pub(super) fn legacy_not_modified(lines: &[(&'static str, &'static str)]) -> S3Error {
    let mut error = bare(S3ErrorCode::NotModified, lines);
    error.set_message("Not Modified");
    error.set_status_code(StatusCode::NOT_MODIFIED);
    error
}

/// A delete-marker read as `with_delete_marker_read_headers` writes it, `Last-Modified` included
/// only when `written` is.
pub(super) fn legacy_marker(code: S3ErrorCode, version_id: &'static str, written: bool) -> S3Error {
    let mut lines = vec![("x-amz-delete-marker", "true"), ("x-amz-version-id", version_id)];
    if written {
        lines.push(("last-modified", MARKER_WRITTEN));
    }
    carrying(code, &lines)
}

fn read(error: &S3Error) -> Result<LegacyRefusal, &'static str> {
    refusal_from_legacy(error).map_err(|error| error.field)
}

fn legacy(code: ErrorCode, message: Option<&str>) -> LegacyRefusal {
    LegacyRefusal {
        code,
        message: message.map(str::to_owned),
        etag: None,
        last_modified: None,
        delete_marker: None,
        complete_length: None,
    }
}

// ── what is read ──────────────────────────────────────────────────────────────────────────────

#[test]
fn the_three_not_modified_answers_legacy_rustfs_writes_are_read_with_exactly_their_validators() {
    let etag = || Some(ETag::new("abc").expect("a tag"));
    let both = LegacyRefusal {
        etag: etag(),
        last_modified: Some(MARKER_WRITTEN_SECONDS),
        ..legacy(ErrorCode::NOT_MODIFIED, Some("Not Modified"))
    };
    assert_eq!(read(&legacy_not_modified(&VALIDATORS)), Ok(both));
    // `If-Modified-Since` on an object without an entity tag: the instant alone.
    let instant = LegacyRefusal {
        last_modified: Some(MARKER_WRITTEN_SECONDS),
        ..legacy(ErrorCode::NOT_MODIFIED, Some("Not Modified"))
    };
    assert_eq!(read(&legacy_not_modified(&[("last-modified", MARKER_WRITTEN)])), Ok(instant));
    // The conditional `HEAD` (`head.rs:423,431`): no header at all, the code's own sentence.
    let head = S3Error::new(S3ErrorCode::NotModified);
    let sentence = head.message().map(str::to_owned);
    assert_eq!(read(&head), Ok(legacy(ErrorCode::NOT_MODIFIED, sentence.as_deref())));
}

#[test]
fn an_invalid_range_is_read_with_its_message_and_a_length_only_when_stated() {
    let message = "The requested range is not satisfiable";
    let error = S3Error::with_message(S3ErrorCode::InvalidRange, message);
    assert_eq!(read(&error), Ok(legacy(ErrorCode::INVALID_RANGE, Some(message))));
    let stated = LegacyRefusal {
        complete_length: Some(10),
        ..legacy(ErrorCode::INVALID_RANGE, S3Error::new(S3ErrorCode::InvalidRange).message())
    };
    assert_eq!(read(&carrying(S3ErrorCode::InvalidRange, &[("content-range", "bytes */10")])), Ok(stated));
}

#[test]
fn a_delete_marker_read_is_read_with_its_instant_only_when_stated() {
    let current = S3Error::new(S3ErrorCode::NoSuchKey);
    let marker = |code, written| LegacyRefusal {
        delete_marker: Some(MARKER_VERSION.to_owned()),
        last_modified: written,
        ..legacy(code, current.message())
    };
    assert_eq!(
        read(&legacy_marker(S3ErrorCode::NoSuchKey, MARKER_VERSION, false)),
        Ok(marker(ErrorCode::NO_SUCH_KEY, None))
    );
    assert_eq!(
        read(&legacy_marker(S3ErrorCode::NoSuchKey, MARKER_VERSION, true)),
        Ok(marker(ErrorCode::NO_SUCH_KEY, Some(MARKER_WRITTEN_SECONDS)))
    );
    let versioned = S3Error::new(S3ErrorCode::MethodNotAllowed);
    assert_eq!(
        read(&legacy_marker(S3ErrorCode::MethodNotAllowed, MARKER_VERSION, true)),
        Ok(LegacyRefusal {
            delete_marker: Some(MARKER_VERSION.to_owned()),
            last_modified: Some(MARKER_WRITTEN_SECONDS),
            ..legacy(ErrorCode::METHOD_NOT_ALLOWED, versioned.message())
        })
    );
    // A marker written while versioning was off has the null version id.
    let null = read(&legacy_marker(S3ErrorCode::NoSuchKey, "null", false)).map(|refusal| refusal.delete_marker);
    assert_eq!(null, Ok(Some("null".to_owned())));
}

/// Nothing is resolved from typed context: a contextual code, an absent message and a long one all
/// cross as the legacy stack writes them.
#[test]
fn contextual_codes_absent_and_long_messages_cross_as_written() {
    let long = format!("Invalid argument: {}", "x".repeat(1500));
    let rows = [
        (
            S3Error::with_message(S3ErrorCode::InvalidArgument, long.clone()),
            legacy(ErrorCode::INVALID_ARGUMENT, Some(&long)),
        ),
        (
            S3Error::with_message(
                S3ErrorCode::BucketAlreadyOwnedByYou,
                "Your previous request to create the named bucket succeeded and you already own it.",
            ),
            legacy(
                ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU,
                Some("Your previous request to create the named bucket succeeded and you already own it."),
            ),
        ),
        (
            S3Error::with_message(S3ErrorCode::MethodNotAllowed, "not allowed here"),
            legacy(ErrorCode::METHOD_NOT_ALLOWED, Some("not allowed here")),
        ),
        (
            S3Error::new(S3ErrorCode::NoSuchBucket),
            legacy(ErrorCode::NO_SUCH_BUCKET, S3Error::new(S3ErrorCode::NoSuchBucket).message()),
        ),
        (
            S3Error::new(S3ErrorCode::NoSuchVersion),
            legacy(ErrorCode::NO_SUCH_VERSION, S3Error::new(S3ErrorCode::NoSuchVersion).message()),
        ),
    ];
    for (error, expected) in rows {
        assert_eq!(read(&error), Ok(expected), "{error:?}");
    }
    let mut conflict = S3Error::with_message(S3ErrorCode::InvalidRequest, "Object is WORM protected");
    conflict.set_status_code(StatusCode::CONFLICT);
    let custom = ErrorCode::custom("InvalidRequest", StatusCode::CONFLICT);
    assert_eq!(read(&conflict), Ok(legacy(custom, Some("Object is WORM protected"))));
}

// ── what is refused ───────────────────────────────────────────────────────────────────────────

#[test]
fn n_a_status_the_legacy_answer_cannot_have_is_refused() {
    let mut ok = S3Error::new(S3ErrorCode::NotModified);
    ok.set_status_code(StatusCode::OK);
    let mut redirect = S3Error::new(S3ErrorCode::AccessDenied);
    redirect.set_status_code(StatusCode::MOVED_PERMANENTLY);
    let mut not_modified_elsewhere = S3Error::new(S3ErrorCode::AccessDenied);
    not_modified_elsewhere.set_status_code(StatusCode::NOT_MODIFIED);
    let mut not_modified_refused = S3Error::new(S3ErrorCode::NotModified);
    not_modified_refused.set_status_code(StatusCode::BAD_REQUEST);
    for error in [ok, redirect, not_modified_elsewhere, not_modified_refused] {
        assert_eq!(read(&error), Err("status_code"), "{error:?}");
    }
}

#[test]
fn n_a_code_message_or_request_id_the_gateway_cannot_write_is_refused() {
    let code = S3ErrorCode::from_bytes(b"Not-An-Identifier").unwrap_or(S3ErrorCode::InternalError);
    assert_eq!(read(&S3Error::with_message(code, "x")), Err("code"));
    let control = S3Error::with_message(S3ErrorCode::InvalidArgument, "bad \u{1} byte");
    assert_eq!(read(&control), Err("message"));
    let mut identified = S3Error::with_message(S3ErrorCode::InvalidArgument, "x");
    identified.set_request_id("request-id");
    assert_eq!(read(&identified), Err("request_id"));
}

/// Each code states only its own facts; the marker facts on a code that is not a marker read, and
/// any header no legacy fact is, are refused rather than dropped.
#[test]
fn n_a_header_its_code_does_not_state_is_refused() {
    let rows = [
        legacy_not_modified(&[("etag", "\"abc\""), ("content-range", "bytes */10")]),
        legacy_not_modified(&[("etag", "\"abc\""), ("x-amz-delete-marker", "true")]),
        carrying(S3ErrorCode::InvalidRange, &[("etag", "\"abc\"")]),
        carrying(S3ErrorCode::InvalidRange, &[("last-modified", MARKER_WRITTEN)]),
        carrying(S3ErrorCode::NoSuchKey, &[("x-amz-version-id", MARKER_VERSION)]),
        carrying(S3ErrorCode::NoSuchKey, &[("last-modified", MARKER_WRITTEN)]),
        carrying(S3ErrorCode::NoSuchBucket, &[("x-amz-delete-marker", "true")]),
        carrying(S3ErrorCode::NoSuchVersion, &[("x-amz-delete-marker", "true"), ("x-amz-version-id", "v")]),
        carrying(S3ErrorCode::AccessDenied, &[("x-custom", "1")]),
        carrying(
            S3ErrorCode::NoSuchKey,
            &[
                ("x-amz-delete-marker", "true"),
                ("x-amz-version-id", MARKER_VERSION),
                ("etag", "\"abc\""),
            ],
        ),
    ];
    for error in &rows {
        assert_eq!(read(error), Err("headers"), "{error:?}");
    }
}

/// A document the legacy stack sends with the error's own header map is typed only by that map:
/// untyped, or typed otherwise, it is not the document the gateway writes.
#[test]
fn n_a_document_without_the_xml_type_in_its_header_map_is_refused() {
    let untyped = bare(S3ErrorCode::NoSuchKey, &[("x-amz-delete-marker", "true"), ("x-amz-version-id", "v")]);
    assert_eq!(read(&untyped), Err("content-type"));
    assert_eq!(read(&bare(S3ErrorCode::AccessDenied, &[])), Err("content-type"));
    let other = bare(S3ErrorCode::AccessDenied, &[("content-type", "text/plain")]);
    assert_eq!(read(&other), Err("content-type"));
    let twice = bare(
        S3ErrorCode::AccessDenied,
        &[("content-type", "application/xml"), ("content-type", "application/xml")],
    );
    assert_eq!(read(&twice), Err("content-type"));
}

#[test]
fn n_a_validator_spelled_otherwise_than_the_gateway_writes_it_is_refused() {
    for tag in ["abc", "\"abc", "W/ \"abc\"", "*", "", "\"a\"b\""] {
        let error = legacy_not_modified(&[("etag", tag)]);
        assert_eq!(read(&error), Err("etag"), "{tag:?}");
    }
    assert_eq!(read(&legacy_not_modified(&[("etag", "\"abc\""), ("etag", "\"abc\"")])), Err("etag"));
    for date in [
        "Fri, 2 Jan 2026 03:04:05 GMT",
        "Friday, 02-Jan-26 03:04:05 GMT",
        "Fri Jan  2 03:04:05 2026",
        "Fri, 02 Jan 2026 03:04:05 UTC",
        "2026-01-02T03:04:05Z",
        "",
    ] {
        let error = legacy_not_modified(&[("etag", "\"abc\""), ("last-modified", date)]);
        assert_eq!(read(&error), Err("last-modified"), "{date:?}");
    }
}

#[test]
fn n_a_content_range_spelled_otherwise_than_the_gateway_writes_it_is_refused() {
    for value in [
        "bytes */010",
        "bytes */",
        "bytes */+10",
        "bytes */1x",
        "bytes 0-1/10",
        "Bytes */10",
        "bytes */18446744073709551616",
    ] {
        let error = carrying(S3ErrorCode::InvalidRange, &[("content-range", value)]);
        assert_eq!(read(&error), Err("content-range"), "{value:?}");
    }
}

#[test]
fn n_a_marker_short_of_its_flag_or_version_is_refused_by_that_header() {
    let rows = [
        (
            carrying(S3ErrorCode::NoSuchKey, &[("x-amz-delete-marker", "false"), ("x-amz-version-id", "v")]),
            "x-amz-delete-marker",
        ),
        (
            carrying(S3ErrorCode::NoSuchKey, &[("x-amz-delete-marker", "TRUE"), ("x-amz-version-id", "v")]),
            "x-amz-delete-marker",
        ),
        (carrying(S3ErrorCode::NoSuchKey, &[("x-amz-delete-marker", "true")]), "x-amz-version-id"),
        (
            carrying(S3ErrorCode::NoSuchKey, &[("x-amz-delete-marker", "true"), ("x-amz-version-id", "")]),
            "x-amz-version-id",
        ),
        (
            carrying(
                S3ErrorCode::MethodNotAllowed,
                &[
                    ("x-amz-delete-marker", "true"),
                    ("x-amz-version-id", "v"),
                    ("last-modified", "yesterday"),
                ],
            ),
            "last-modified",
        ),
    ];
    for (error, field) in rows {
        assert_eq!(read(&error), Err(field), "{error:?}");
    }
}
