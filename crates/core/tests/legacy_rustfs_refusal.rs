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

//! The RustFS profile's refusal (`LegacyRustfsRefusal`, rustfs/gateway#1148): what it resolves to,
//! what it refuses to state, and that a caller who may not list the bucket still learns nothing
//! from it.
//!
//! Responsible for: the resolution of each legacy shape — the `304`s with and without their
//! validators, the `416` with and without its length, both delete-marker reads with and without
//! their instant, an absent and a long message, a custom status — and every refusal of the
//! constructor; the stored headers and the evaluated version a `304` repeats (rustfs/gateway#1612);
//! masking and the copy-source restriction applied to a legacy refusal as to a typed one.
//! NOT responsible for: reading a legacy error (the migration seam), or the bytes the facade
//! renders (the goldens error-parity diff drives both stacks).
//! Upstream: `rustfs-gateway-core`. Downstream: nothing.

use http::StatusCode;
use rustfs_gateway_core::{
    BodyPolicy, ErrorContext, ErrorHeader, HandlerError, HandlerErrorContext, InvalidErrorContext, LegacyRustfsFacts,
    LegacyRustfsRefusal, ResponseKind, resolve,
};
use rustfs_gateway_types::{ETag, ErrorCode};

const WRITTEN: i64 = 1_767_323_045;
const WRITTEN_TEXT: &str = "Fri, 02 Jan 2026 03:04:05 GMT";
const MARKER: &str = "0e4a9c3c-8d1f-4c55-9a8e-1f4f0b6d2c11";

fn refusal(code: ErrorCode, message: Option<&str>, facts: LegacyRustfsFacts) -> Result<LegacyRustfsRefusal, InvalidErrorContext> {
    LegacyRustfsRefusal::new(code, message.map(str::to_owned), facts)
}

fn resolved(refusal: LegacyRustfsRefusal, response: ResponseKind) -> rustfs_gateway_core::ErrorResolution {
    resolve(ErrorContext::legacy_rustfs(refusal), response)
}

fn names(headers: &[ErrorHeader]) -> Vec<String> {
    headers
        .iter()
        .map(|header| format!("{}: {}", header.name(), header.value()))
        .collect()
}

fn marker(written: Option<i64>) -> LegacyRustfsFacts {
    LegacyRustfsFacts {
        delete_marker: Some(MARKER.to_owned()),
        last_modified: written,
        ..LegacyRustfsFacts::default()
    }
}

// ── what a legacy refusal states ──────────────────────────────────────────────────────────────

#[test]
fn a_legacy_not_modified_states_exactly_the_validators_it_was_given() {
    let rows = [
        (
            Some(ETag::new("abc").expect("a tag")),
            Some(WRITTEN),
            vec![format!("last-modified: {WRITTEN_TEXT}")],
        ),
        (None, Some(WRITTEN), vec![format!("last-modified: {WRITTEN_TEXT}")]),
        (None, None, Vec::new()),
    ];
    for (etag, last_modified, headers) in rows {
        let facts = LegacyRustfsFacts {
            etag: etag.clone(),
            last_modified,
            ..LegacyRustfsFacts::default()
        };
        let resolution = resolved(
            refusal(ErrorCode::NOT_MODIFIED, Some("Not Modified"), facts).expect("a legacy 304"),
            ResponseKind::Other,
        );
        assert_eq!(resolution.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(resolution.etag(), etag.as_ref());
        assert_eq!(names(resolution.headers()), headers);
        // No document, and so no message a `HEAD` could be measured by.
        assert_eq!((resolution.body_policy(), resolution.message()), (BodyPolicy::None, None));
    }
}

#[test]
fn a_legacy_invalid_range_states_its_message_and_a_length_only_when_given_and_no_element() {
    let bare = resolved(
        refusal(
            ErrorCode::INVALID_RANGE,
            Some("The requested range is not satisfiable"),
            LegacyRustfsFacts::default(),
        )
        .expect("a legacy 416"),
        ResponseKind::Other,
    );
    assert_eq!(bare.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(bare.message(), Some("The requested range is not satisfiable"));
    assert!(bare.headers().is_empty() && bare.details().is_empty(), "{bare:?}");
    let facts = LegacyRustfsFacts {
        complete_length: Some(10),
        ..LegacyRustfsFacts::default()
    };
    let stated = resolved(refusal(ErrorCode::INVALID_RANGE, None, facts).expect("a legacy 416"), ResponseKind::Other);
    assert_eq!(names(stated.headers()), ["content-range: bytes */10"]);
    assert!(stated.details().is_empty(), "{stated:?}");
    assert_eq!(stated.message(), None);
}

#[test]
fn a_legacy_delete_marker_read_states_its_instant_only_when_given() {
    let current = resolved(
        refusal(ErrorCode::NO_SUCH_KEY, Some("The specified key does not exist."), marker(None)).expect("a marker read"),
        ResponseKind::Other,
    );
    assert_eq!(current.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        names(current.headers()),
        ["x-amz-delete-marker: true", &format!("x-amz-version-id: {MARKER}")]
    );
    assert!(current.details().is_empty(), "legacy RustFS names no key: {current:?}");
    let versioned = resolved(
        refusal(ErrorCode::METHOD_NOT_ALLOWED, None, marker(Some(WRITTEN))).expect("a marker read"),
        ResponseKind::Other,
    );
    assert_eq!(versioned.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        names(versioned.headers()),
        [
            "x-amz-delete-marker: true".to_owned(),
            format!("x-amz-version-id: {MARKER}"),
            format!("last-modified: {WRITTEN_TEXT}")
        ]
    );
}

/// A contextual code, a custom status, an absent message and one past the typed bound all resolve
/// as given.
#[test]
fn any_code_and_any_message_resolve_as_given() {
    let long = "x".repeat(4096);
    let rows = [
        (ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU, Some("owned"), StatusCode::CONFLICT),
        (ErrorCode::METHOD_NOT_ALLOWED, Some("not here"), StatusCode::METHOD_NOT_ALLOWED),
        (ErrorCode::NO_SUCH_VERSION, None, StatusCode::NOT_FOUND),
        (
            ErrorCode::custom("InvalidRequest", StatusCode::CONFLICT),
            Some("WORM"),
            StatusCode::CONFLICT,
        ),
        (
            ErrorCode::custom("XRustfsQuotaExceeded", StatusCode::FORBIDDEN),
            Some(long.as_str()),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (code, message, status) in rows {
        let resolution = resolved(
            refusal(code.clone(), message, LegacyRustfsFacts::default()).expect("a legacy refusal"),
            ResponseKind::Other,
        );
        assert_eq!((resolution.status(), resolution.code()), (status, Some(&code)));
        assert_eq!((resolution.message(), resolution.body_policy()), (message, BodyPolicy::ErrorDocument));
        assert!(resolution.headers().is_empty() && resolution.details().is_empty());
    }
}

/// A legacy refusal is a context: a handler returns it like any typed one, and it keeps its facts.
#[test]
fn a_legacy_refusal_is_a_handler_error_carrying_its_resolution() {
    let error = HandlerError::from(HandlerErrorContext::legacy_rustfs(
        refusal(ErrorCode::NO_SUCH_KEY, Some("gone"), marker(None)).expect("a marker read"),
    ));
    assert_eq!((error.code(), error.message()), (&ErrorCode::NO_SUCH_KEY, "gone"));
    let context = ErrorContext::ordinary(error).expect("a context crosses admission");
    assert_eq!(resolve(context, ResponseKind::Other).status(), StatusCode::NOT_FOUND);
}

// ── what a legacy refusal refuses to state ────────────────────────────────────────────────────

#[test]
fn n_a_status_that_is_not_a_refusal_or_the_304_of_not_modified_is_refused() {
    for code in [
        ErrorCode::custom("AccessDenied", StatusCode::OK),
        ErrorCode::custom("AccessDenied", StatusCode::MOVED_PERMANENTLY),
        ErrorCode::custom("AccessDenied", StatusCode::NOT_MODIFIED),
        ErrorCode::custom("NotModified", StatusCode::BAD_REQUEST),
        ErrorCode::custom("NotModified", StatusCode::OK),
    ] {
        assert_eq!(
            refusal(code.clone(), None, LegacyRustfsFacts::default()),
            Err(InvalidErrorContext::InvalidCode),
            "{code:?}"
        );
    }
    let unreadable = ErrorCode::custom("Not-An-Identifier", StatusCode::BAD_REQUEST);
    assert_eq!(
        refusal(unreadable, None, LegacyRustfsFacts::default()),
        Err(InvalidErrorContext::InvalidCode)
    );
}

#[test]
fn n_a_message_xml_cannot_carry_is_refused() {
    assert_eq!(
        refusal(ErrorCode::INVALID_ARGUMENT, Some("a \u{1} b"), LegacyRustfsFacts::default()),
        Err(InvalidErrorContext::InvalidMessage)
    );
}

/// Each fact belongs to its code: an entity tag to `NotModified`, a length to `InvalidRange`, a
/// marker to the two marker reads, an instant to `NotModified` or a marker read.
#[test]
fn n_a_fact_its_code_does_not_state_is_refused() {
    let etag = LegacyRustfsFacts {
        etag: Some(ETag::new("abc").expect("a tag")),
        ..LegacyRustfsFacts::default()
    };
    let length = LegacyRustfsFacts {
        complete_length: Some(10),
        ..LegacyRustfsFacts::default()
    };
    let instant = LegacyRustfsFacts {
        last_modified: Some(WRITTEN),
        ..LegacyRustfsFacts::default()
    };
    let rows = [
        (ErrorCode::NO_SUCH_KEY, etag.clone()),
        (ErrorCode::INVALID_RANGE, etag),
        (ErrorCode::NOT_MODIFIED, length.clone()),
        (ErrorCode::ACCESS_DENIED, length),
        (ErrorCode::NO_SUCH_BUCKET, marker(None)),
        (ErrorCode::NO_SUCH_VERSION, marker(Some(WRITTEN))),
        (ErrorCode::custom("NoSuchKey", StatusCode::FORBIDDEN), marker(None)),
        (ErrorCode::NO_SUCH_KEY, instant.clone()),
        (ErrorCode::INVALID_RANGE, instant),
    ];
    for (code, facts) in rows {
        assert_eq!(refusal(code.clone(), None, facts), Err(InvalidErrorContext::InvalidDetail), "{code:?}");
    }
}

#[test]
fn n_a_marker_version_or_instant_the_headers_cannot_carry_is_refused() {
    for version_id in ["", "a b", "\u{e9}"] {
        let facts = LegacyRustfsFacts {
            delete_marker: Some(version_id.to_owned()),
            ..LegacyRustfsFacts::default()
        };
        assert_eq!(refusal(ErrorCode::NO_SUCH_KEY, None, facts), Err(InvalidErrorContext::InvalidVersionId));
    }
    assert_eq!(
        refusal(ErrorCode::NO_SUCH_KEY, None, marker(Some(i64::MAX))),
        Err(InvalidErrorContext::InvalidLastModified)
    );
}

// ── hidden and copied, as the typed refusals are ──────────────────────────────────────────────

/// A caller who may not list the bucket learns from a legacy missing object, or a legacy current
/// marker, exactly what it learns from a typed one: `AccessDenied`, no marker header.
#[test]
fn n_a_hidden_legacy_missing_object_discloses_nothing() {
    let rows = [
        refusal(ErrorCode::NO_SUCH_KEY, Some("gone"), LegacyRustfsFacts::default()),
        refusal(ErrorCode::NO_SUCH_VERSION, None, LegacyRustfsFacts::default()),
        refusal(ErrorCode::NO_SUCH_KEY, Some("gone"), marker(None)),
        refusal(ErrorCode::NO_SUCH_KEY, None, marker(Some(WRITTEN))),
    ];
    for legacy in rows {
        let error =
            HandlerError::from(HandlerErrorContext::legacy_rustfs(legacy.expect("a legacy refusal"))).hide_missing_object();
        assert_eq!(error.code(), &ErrorCode::ACCESS_DENIED, "{error:?}");
        assert!(error.headers().is_empty(), "{error:?}");
        let resolution = resolve(ErrorContext::ordinary(error).expect("a context"), ResponseKind::Other);
        assert_eq!(resolution.status(), StatusCode::FORBIDDEN);
    }
    // What is not a missing object is not hidden.
    let versioned = refusal(ErrorCode::METHOD_NOT_ALLOWED, None, marker(Some(WRITTEN))).expect("a marker read");
    let error = HandlerError::from(HandlerErrorContext::legacy_rustfs(versioned)).hide_missing_object();
    assert_eq!(error.code(), &ErrorCode::METHOD_NOT_ALLOWED);
    let conflict = refusal(ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU, None, LegacyRustfsFacts::default()).expect("a refusal");
    let error = HandlerError::from(HandlerErrorContext::legacy_rustfs(conflict)).hide_missing_object();
    assert_eq!(error.code(), &ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU);
}

/// A copy's refusal for a marker source withholds the marker's version id, as a typed marker
/// refusal does; the flag and the instant stay.
#[test]
fn n_a_legacy_marker_answered_for_a_copy_source_withholds_its_version_id() {
    let legacy = refusal(ErrorCode::METHOD_NOT_ALLOWED, None, marker(Some(WRITTEN))).expect("a marker read");
    let error = HandlerError::from(HandlerErrorContext::legacy_rustfs(legacy)).as_copy_source_refusal();
    assert_eq!(
        names(error.headers()),
        [
            "x-amz-delete-marker: true".to_owned(),
            format!("last-modified: {WRITTEN_TEXT}")
        ]
    );
}

// ── what a `304` repeats of the representation (rustfs/gateway#1612) ───────────────────────────

const CACHE_CONTROL: &str = "max-age=3600, must-revalidate";
const CONTENT_LOCATION: &str = "/bucket/photos/a.jpg";
const EXPIRES: &str = "Thu, 01 Dec 2027 16:00:00 GMT";
const VARY: &str = "Origin, Accept-Encoding";
const EVALUATED: &str = "3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY";

/// Every fact a legacy `304` may state, each its own row: the facts, and the one line it puts on
/// the wire.
fn stored_rows() -> [(LegacyRustfsFacts, String); 5] {
    let facts = LegacyRustfsFacts::default;
    [
        (
            LegacyRustfsFacts {
                cache_control: Some(CACHE_CONTROL.to_owned()),
                ..facts()
            },
            format!("cache-control: {CACHE_CONTROL}"),
        ),
        (
            LegacyRustfsFacts {
                content_location: Some(CONTENT_LOCATION.to_owned()),
                ..facts()
            },
            format!("content-location: {CONTENT_LOCATION}"),
        ),
        (
            LegacyRustfsFacts {
                expires: Some(EXPIRES.to_owned()),
                ..facts()
            },
            format!("expires: {EXPIRES}"),
        ),
        (
            LegacyRustfsFacts {
                vary: Some(VARY.to_owned()),
                ..facts()
            },
            format!("vary: {VARY}"),
        ),
        (
            LegacyRustfsFacts {
                version_id: Some(EVALUATED.to_owned()),
                ..facts()
            },
            format!("x-amz-version-id: {EVALUATED}"),
        ),
    ]
}

fn every_stored_fact() -> LegacyRustfsFacts {
    LegacyRustfsFacts {
        etag: Some(ETag::new("abc").expect("a tag")),
        last_modified: Some(WRITTEN),
        cache_control: Some(CACHE_CONTROL.to_owned()),
        content_location: Some(CONTENT_LOCATION.to_owned()),
        expires: Some(EXPIRES.to_owned()),
        vary: Some(VARY.to_owned()),
        version_id: Some(EVALUATED.to_owned()),
        ..LegacyRustfsFacts::default()
    }
}

/// Each stated fact is the one header it names, with the stated value; all of them together are
/// all of those headers, in one order, beside the entity tag.
#[test]
fn a_legacy_not_modified_states_each_stored_header_and_the_evaluated_version() {
    for (facts, line) in stored_rows() {
        let resolution = resolved(
            refusal(ErrorCode::NOT_MODIFIED, Some("Not Modified"), facts).expect("a legacy 304"),
            ResponseKind::Other,
        );
        assert_eq!(names(resolution.headers()), [line]);
        assert_eq!(resolution.etag(), None);
    }
    let all = resolved(
        refusal(ErrorCode::NOT_MODIFIED, Some("Not Modified"), every_stored_fact()).expect("a legacy 304"),
        ResponseKind::Other,
    );
    assert_eq!(all.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(all.etag(), Some(&ETag::new("abc").expect("a tag")));
    assert_eq!(
        names(all.headers()),
        [
            format!("x-amz-version-id: {EVALUATED}"),
            format!("last-modified: {WRITTEN_TEXT}"),
            format!("cache-control: {CACHE_CONTROL}"),
            format!("content-location: {CONTENT_LOCATION}"),
            format!("expires: {EXPIRES}"),
            format!("vary: {VARY}"),
        ]
    );
    assert_eq!((all.body_policy(), all.message()), (BodyPolicy::None, None));
}

/// Negative — a stored header and an evaluated version belong to `NotModified` alone; every other
/// code, the marker reads and a `304`-named custom code at another status included, refuses them.
#[test]
fn n_a_stored_header_or_evaluated_version_on_another_code_is_refused() {
    let codes = [
        ErrorCode::NO_SUCH_KEY,
        ErrorCode::METHOD_NOT_ALLOWED,
        ErrorCode::INVALID_RANGE,
        ErrorCode::PRECONDITION_FAILED,
        ErrorCode::ACCESS_DENIED,
        ErrorCode::custom("NotModifiedHere", StatusCode::CONFLICT),
    ];
    for (facts, line) in stored_rows() {
        for code in &codes {
            assert_eq!(
                refusal(code.clone(), None, facts.clone()),
                Err(InvalidErrorContext::InvalidDetail),
                "{code:?} {line}"
            );
        }
    }
    // Beside a delete marker the evaluated version is still refused: the marker's id is the only
    // version id a marker read states.
    let both = LegacyRustfsFacts {
        version_id: Some(EVALUATED.to_owned()),
        ..marker(Some(WRITTEN))
    };
    assert_eq!(
        refusal(ErrorCode::METHOD_NOT_ALLOWED, None, both),
        Err(InvalidErrorContext::InvalidDetail)
    );
}

/// Negative — a stored value a header cannot carry is refused at construction, not dropped at
/// encoding: empty, edged by whitespace a recipient would strip, a control byte or line break, a
/// byte past ASCII, or past the bound.
#[test]
fn n_a_stored_header_value_a_header_cannot_carry_is_refused() {
    let long = "a".repeat(8193);
    let values = [
        "",
        " max-age=1",
        "max-age=1 ",
        "a\tb",
        "a\r\nSet-Cookie: x",
        "a\nb",
        "\u{7f}",
        "caf\u{e9}",
        long.as_str(),
    ];
    let setters: [fn(String) -> LegacyRustfsFacts; 4] = [
        |value| LegacyRustfsFacts {
            cache_control: Some(value),
            ..LegacyRustfsFacts::default()
        },
        |value| LegacyRustfsFacts {
            content_location: Some(value),
            ..LegacyRustfsFacts::default()
        },
        |value| LegacyRustfsFacts {
            expires: Some(value),
            ..LegacyRustfsFacts::default()
        },
        |value| LegacyRustfsFacts {
            vary: Some(value),
            ..LegacyRustfsFacts::default()
        },
    ];
    for set in setters {
        for value in values {
            assert_eq!(
                refusal(ErrorCode::NOT_MODIFIED, None, set(value.to_owned())),
                Err(InvalidErrorContext::InvalidDetail),
                "{value:?}"
            );
        }
        // The bound itself is carried.
        assert!(refusal(ErrorCode::NOT_MODIFIED, None, set("a".repeat(8192))).is_ok());
    }
    for version_id in ["", "a b", "\u{e9}", "v\r\n"] {
        let facts = LegacyRustfsFacts {
            version_id: Some(version_id.to_owned()),
            ..LegacyRustfsFacts::default()
        };
        assert_eq!(
            refusal(ErrorCode::NOT_MODIFIED, None, facts),
            Err(InvalidErrorContext::InvalidVersionId),
            "{version_id:?}"
        );
    }
}

/// Negative — a `304` answered for a copy source withholds the evaluated version too: on a copy,
/// `x-amz-version-id` names the version the copy wrote, so the source's id would name the wrong
/// object. The stored headers and the validators stay.
#[test]
fn n_a_legacy_not_modified_answered_for_a_copy_source_withholds_its_evaluated_version() {
    let legacy = refusal(ErrorCode::NOT_MODIFIED, None, every_stored_fact()).expect("a legacy 304");
    let error = HandlerError::from(HandlerErrorContext::legacy_rustfs(legacy)).as_copy_source_refusal();
    let resolution = resolve(ErrorContext::ordinary(error).expect("a context"), ResponseKind::Other);
    assert_eq!(resolution.etag(), Some(&ETag::new("abc").expect("a tag")));
    assert_eq!(
        names(resolution.headers()),
        [
            format!("last-modified: {WRITTEN_TEXT}"),
            format!("cache-control: {CACHE_CONTROL}"),
            format!("content-location: {CONTENT_LOCATION}"),
            format!("expires: {EXPIRES}"),
            format!("vary: {VARY}"),
        ]
    );
    // Not answered for a copy source, the same refusal keeps it.
    let direct = refusal(ErrorCode::NOT_MODIFIED, None, every_stored_fact()).expect("a legacy 304");
    let kept = resolved(direct, ResponseKind::Other);
    assert!(names(kept.headers()).contains(&format!("x-amz-version-id: {EVALUATED}")));
}
