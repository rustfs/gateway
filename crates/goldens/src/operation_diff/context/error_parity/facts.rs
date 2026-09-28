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

//! The GetObject/HeadObject handler errors whose facts ride in the s3s error's own headers:
//! `NotModified` with `ETag`, `InvalidRange` with `Content-Range`, and the two delete-marker reads
//! with `x-amz-delete-marker`, `x-amz-version-id` and `Last-Modified` (rustfs/gateway#795).
//!
//! Responsible for: the seam's typed verdict for each, and its refusal, by header name, of every
//! shape short of the facts the gateway renders from — a missing, repeated or malformed header, a
//! header the verdict has no member for, and marker headers on a code that is not a marker read.
//! NOT responsible for: the two-stack answers these verdicts produce (`super::divergences`), or the
//! M1 operations' errors, which carry no header but `Content-Type` (`super::mapping`).
//! Upstream: `compat::error`. Downstream: nothing.
//!
//! The errors here are spelled as the RustFS body must spell them for the gateway to answer as AWS
//! does: `with_delete_marker_read_headers` already attaches the marker headers (and `Last-Modified`
//! on a versioned read only); the entity tag on a `304` and the unsatisfied `Content-Range` on a
//! `416` are the RustFS body's to add.

use super::super::super::seam::error::{Refusal, refusal_from_s3s};
use super::s3s;
use http::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway::ETag;
use s3s::{S3Error, S3ErrorCode};

/// The marker's version id, as RustFS renders a stored UUID.
pub(super) const MARKER_VERSION: &str = "0e4a9c3c-8d1f-4c55-9a8e-1f4f0b6d2c11";
/// When the marker was written, as RustFS renders it, and the same instant in Unix seconds.
pub(super) const MARKER_WRITTEN: &str = "Fri, 02 Jan 2026 03:04:05 GMT";
pub(super) const MARKER_WRITTEN_SECONDS: i64 = 1_767_323_045;

/// `code` carrying `lines` as its response headers, after the `Content-Type` RustFS re-adds.
pub(super) fn carrying(code: S3ErrorCode, lines: &[(&'static str, &'static str)]) -> S3Error {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/xml"));
    for (name, value) in lines {
        headers.append(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    let mut error = S3Error::new(code);
    error.set_headers(headers);
    error
}

pub(super) fn not_modified() -> S3Error {
    carrying(S3ErrorCode::NotModified, &[("etag", "\"abc\"")])
}

pub(super) fn unsatisfiable() -> S3Error {
    carrying(S3ErrorCode::InvalidRange, &[("content-range", "bytes */10")])
}

const MARKER: [(&str, &str); 3] = [
    ("x-amz-delete-marker", "true"),
    ("x-amz-version-id", MARKER_VERSION),
    ("last-modified", MARKER_WRITTEN),
];

pub(super) fn current_marker() -> S3Error {
    carrying(S3ErrorCode::NoSuchKey, &MARKER)
}

pub(super) fn versioned_marker() -> S3Error {
    carrying(S3ErrorCode::MethodNotAllowed, &MARKER)
}

fn refused(error: &S3Error) -> Result<Refusal, &'static str> {
    refusal_from_s3s(error).map_err(|error| error.field)
}

// ── the four verdicts ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_not_modified_carrying_its_entity_tag_is_the_typed_304() {
    let etag = ETag::new("abc").expect("a tag");
    assert_eq!(refused(&not_modified()), Ok(Refusal::NotModified { etag }));
}

#[test]
fn an_invalid_range_carrying_the_unsatisfied_content_range_is_the_typed_416() {
    assert_eq!(refused(&unsatisfiable()), Ok(Refusal::UnsatisfiableRange { complete_length: 10 }));
    let empty = carrying(S3ErrorCode::InvalidRange, &[("content-range", "bytes */0")]);
    assert_eq!(refused(&empty), Ok(Refusal::UnsatisfiableRange { complete_length: 0 }));
}

#[test]
fn the_marker_headers_on_the_two_marker_codes_are_the_two_marker_reads() {
    let facts = || (MARKER_VERSION.to_owned(), MARKER_WRITTEN_SECONDS);
    let (version_id, last_modified) = facts();
    assert_eq!(
        refused(&current_marker()),
        Ok(Refusal::CurrentDeleteMarker {
            version_id,
            last_modified
        })
    );
    let (version_id, last_modified) = facts();
    assert_eq!(
        refused(&versioned_marker()),
        Ok(Refusal::VersionedDeleteMarker {
            version_id,
            last_modified
        })
    );
}

// ── short of the facts ────────────────────────────────────────────────────────────────────────

/// What RustFS answers today: no tag on the `304`, no length on the `416`.
#[test]
fn n_a_not_modified_or_invalid_range_without_its_fact_is_refused_by_the_header_it_lacks() {
    assert_eq!(refused(&S3Error::new(S3ErrorCode::NotModified)), Err("etag"));
    assert_eq!(refused(&carrying(S3ErrorCode::NotModified, &[])), Err("etag"));
    let range_message = S3Error::with_message(S3ErrorCode::InvalidRange, "The requested range is not satisfiable");
    assert_eq!(refused(&range_message), Err("content-range"));
}

#[test]
fn n_a_malformed_or_repeated_entity_tag_is_refused() {
    for tag in ["\"abc", "\"a\"b\"", "", "*"] {
        assert_eq!(refused(&carrying(S3ErrorCode::NotModified, &[("etag", tag)])), Err("etag"), "{tag:?}");
    }
    let twice = carrying(S3ErrorCode::NotModified, &[("etag", "\"abc\""), ("etag", "\"def\"")]);
    assert_eq!(refused(&twice), Err("etag"));
}

/// Only the unsatisfied form, `bytes */<length>`, states a complete length and nothing else.
#[test]
fn n_a_content_range_other_than_the_unsatisfied_form_is_refused() {
    for value in [
        "bytes 0-1/10",
        "bytes */",
        "bytes */-1",
        "bytes */+10",
        "bytes */1x",
        "bytes */ 10",
        "bytes */*",
        "Bytes */10",
        "items */10",
        "bytes */18446744073709551616",
    ] {
        let error = carrying(S3ErrorCode::InvalidRange, &[("content-range", value)]);
        assert_eq!(refused(&error), Err("content-range"), "{value:?}");
    }
    let twice = carrying(
        S3ErrorCode::InvalidRange,
        &[("content-range", "bytes */10"), ("content-range", "bytes */10")],
    );
    assert_eq!(refused(&twice), Err("content-range"));
}

/// Every marker fact is required: the gateway states the instant on both marker reads, so the
/// current-marker `NoSuchKey` RustFS writes today, with no `Last-Modified`, does not cross.
#[test]
fn n_a_marker_read_missing_or_misspelling_a_fact_is_refused_by_that_header() {
    let without = |missing: &str| {
        let lines: Vec<_> = MARKER.into_iter().filter(|(name, _)| *name != missing).collect();
        let leaked: &'static [(&'static str, &'static str)] = Box::leak(lines.into_boxed_slice());
        (carrying(S3ErrorCode::NoSuchKey, leaked), carrying(S3ErrorCode::MethodNotAllowed, leaked))
    };
    for missing in ["x-amz-version-id", "last-modified"] {
        let (current, versioned) = without(missing);
        assert_eq!(refused(&current), Err(missing), "current, no {missing}");
        assert_eq!(refused(&versioned), Err(missing), "versioned, no {missing}");
    }
    let with = |name: &'static str, value: &'static str| {
        let lines: Vec<_> = MARKER
            .into_iter()
            .map(|(line, original)| (line, if line == name { value } else { original }))
            .collect();
        carrying(S3ErrorCode::NoSuchKey, Box::leak(lines.into_boxed_slice()))
    };
    for (name, value) in [
        ("x-amz-delete-marker", "false"),
        ("x-amz-delete-marker", "TRUE"),
        ("x-amz-version-id", ""),
        ("last-modified", "2026-01-02T03:04:05Z"),
        ("last-modified", "Fri, 02 Jan 2026 03:04:05"),
    ] {
        assert_eq!(refused(&with(name, value)), Err(name), "{name}: {value:?}");
    }
}

/// A version id or instant with no marker flag is not a marker read, and a `NoSuchKey` or
/// `MethodNotAllowed` carrying them is refused as carrying headers the verdict has no member for.
#[test]
fn n_marker_facts_without_the_marker_flag_are_refused_as_headers() {
    let facts = [("x-amz-version-id", MARKER_VERSION), ("last-modified", MARKER_WRITTEN)];
    assert_eq!(refused(&carrying(S3ErrorCode::NoSuchKey, &facts)), Err("headers"));
    assert_eq!(refused(&carrying(S3ErrorCode::MethodNotAllowed, &facts)), Err("headers"));
    assert_eq!(refused(&carrying(S3ErrorCode::MethodNotAllowed, &[])), Err("code"));
}

/// Each verdict admits exactly its own headers: a fact belonging to another verdict, or one the
/// gateway has no member for, is refused rather than dropped.
#[test]
fn n_a_header_beyond_the_verdicts_own_is_refused() {
    let rows = [
        carrying(S3ErrorCode::NotModified, &[("etag", "\"abc\""), ("last-modified", MARKER_WRITTEN)]),
        carrying(S3ErrorCode::NotModified, &[("etag", "\"abc\""), ("x-amz-delete-marker", "true")]),
        carrying(S3ErrorCode::InvalidRange, &[("content-range", "bytes */10"), ("etag", "\"abc\"")]),
        carrying(S3ErrorCode::InvalidRange, &[("content-range", "bytes */10"), ("accept-ranges", "bytes")]),
        carrying(
            S3ErrorCode::NoSuchKey,
            &[
                ("x-amz-delete-marker", "true"),
                ("x-amz-version-id", MARKER_VERSION),
                ("last-modified", MARKER_WRITTEN),
                ("etag", "\"abc\""),
            ],
        ),
        carrying(S3ErrorCode::NoSuchBucket, &[("x-amz-delete-marker", "true")]),
        carrying(S3ErrorCode::NoSuchVersion, &MARKER),
        carrying(S3ErrorCode::AccessDenied, &[("etag", "\"abc\"")]),
    ];
    for error in &rows {
        assert_eq!(refused(error), Err("headers"), "{error:?}");
    }
}

/// Repeating a marker header is two answers to one question.
#[test]
fn n_a_repeated_marker_header_is_refused_by_name() {
    for name in ["x-amz-delete-marker", "x-amz-version-id", "last-modified"] {
        let value = MARKER
            .iter()
            .find(|(line, _)| *line == name)
            .map(|(_, value)| *value)
            .expect("a marker line");
        let mut error = current_marker();
        let mut headers = error.headers().cloned().expect("marker headers");
        headers.append(HeaderName::from_static(name), HeaderValue::from_static(value));
        error.set_headers(headers);
        assert_eq!(refused(&error), Err(name), "{name}");
    }
}
