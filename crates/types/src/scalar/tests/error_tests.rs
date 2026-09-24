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

//! Error-code cases: the context-free table and the fallback that is not a 500.
//!
//! Responsible for: the surprising status mappings, the generated table's internal consistency,
//! the counterintuitive rows, and the property that a code the table does not hold keeps the
//! status its author gave it rather than one this crate invented.
//! NOT responsible for: contextual selection, which belongs to `rustfs-gateway-core`.
//! Upstream: [`crate::scalar::error_code`]. Downstream: nothing.

use http::StatusCode;
use proptest::prelude::*;

use crate::scalar::ErrorCode;

#[test]
fn c_err_0001_a_missing_bucket_is_404() {
    assert_eq!(ErrorCode::NO_SUCH_BUCKET.default_status(), StatusCode::NOT_FOUND);
}

#[test]
fn bad_request_is_a_registered_400_code() {
    let code = ErrorCode::known("BadRequest").expect("AWS headerless OPTIONS returns a registered BadRequest");
    assert_eq!(code.as_str(), "BadRequest");
    assert!(code.is_known());
    assert_eq!(code.default_status(), StatusCode::BAD_REQUEST);
}

#[test]
fn bad_request_registration_does_not_accept_other_spellings() {
    for name in ["badrequest", "Badrequest", "BadRequest ", "BadRequestUnknown"] {
        assert_eq!(ErrorCode::known(name), None, "{name}");
    }
}

#[test]
fn bad_request_does_not_replace_distinct_request_errors_or_custom_statuses() {
    let code = ErrorCode::known("BadRequest").expect("registered wire code");
    assert_ne!(code, ErrorCode::INVALID_REQUEST);
    assert_ne!(code, ErrorCode::INVALID_ARGUMENT);
    let custom = ErrorCode::custom("BadRequest", StatusCode::FORBIDDEN);
    assert_ne!(custom, code);
    assert_eq!(custom.default_status(), StatusCode::FORBIDDEN);
}

#[test]
fn the_counterintuitive_mappings_are_pinned() {
    // Each of these reads wrong at first glance and is right on the wire; a table row is the only
    // place they can be stated once.
    let cases = [
        (ErrorCode::MISSING_CONTENT_LENGTH, StatusCode::LENGTH_REQUIRED),
        (ErrorCode::ENTITY_TOO_LARGE, StatusCode::BAD_REQUEST),
        (ErrorCode::ENTITY_TOO_SMALL, StatusCode::BAD_REQUEST),
        (ErrorCode::REQUEST_TIMEOUT, StatusCode::BAD_REQUEST),
        (ErrorCode::INVALID_OBJECT_STATE, StatusCode::FORBIDDEN),
        (ErrorCode::ACCESS_FORBIDDEN, StatusCode::FORBIDDEN),
        (ErrorCode::METHOD_NOT_ALLOWED, StatusCode::METHOD_NOT_ALLOWED),
        (ErrorCode::NOT_IMPLEMENTED, StatusCode::NOT_IMPLEMENTED),
        (ErrorCode::BUCKET_NOT_EMPTY, StatusCode::CONFLICT),
        (ErrorCode::BUCKET_ALREADY_OWNED_BY_YOU, StatusCode::CONFLICT),
        (ErrorCode::SLOW_DOWN, StatusCode::SERVICE_UNAVAILABLE),
        (ErrorCode::INVALID_RANGE, StatusCode::RANGE_NOT_SATISFIABLE),
        (ErrorCode::PERMANENT_REDIRECT, StatusCode::MOVED_PERMANENTLY),
        (ErrorCode::TEMPORARY_REDIRECT, StatusCode::TEMPORARY_REDIRECT),
        (ErrorCode::NOT_MODIFIED, StatusCode::NOT_MODIFIED),
    ];
    for (code, expected) in cases {
        assert_eq!(code.default_status(), expected, "{code}");
    }
}

#[test]
fn an_unknown_code_carries_the_status_its_author_chose() {
    // There is no fallback left to fall back to: `custom` cannot be called without a status, so a
    // code this implementation does not know is answered with the status its author picked and
    // never with a status this crate invented on its behalf.
    let custom = ErrorCode::custom("RustFsTierBackendUnreachable".to_owned(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!custom.is_known());
    assert_eq!(custom.default_status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(custom.as_str(), "RustFsTierBackendUnreachable");
    assert_eq!(custom.to_string(), "RustFsTierBackendUnreachable");
}

#[test]
fn a_custom_code_is_never_silently_remapped_by_the_table() {
    // The failure this pins: a `custom` that consulted the table would answer 403 here, quietly
    // discarding the status the caller asked for and making the argument decorative.
    let impersonator = ErrorCode::custom("AccessDenied", StatusCode::BAD_REQUEST);
    assert_eq!(impersonator.default_status(), StatusCode::BAD_REQUEST);
    assert_ne!(
        impersonator,
        ErrorCode::ACCESS_DENIED,
        "a code that renders a different status is a different value, or it could impersonate one"
    );
    assert_eq!(ErrorCode::custom("AccessDenied", StatusCode::FORBIDDEN), ErrorCode::ACCESS_DENIED);
}

#[test]
fn an_unknown_name_has_no_looked_up_form() {
    // `known` is the whole replacement for `From<&'static str>`: a name with no row has no status,
    // so it has no `ErrorCode` either, rather than one carrying a status nobody chose.
    assert_eq!(ErrorCode::known("Nonsense"), None);
    assert_eq!(ErrorCode::known(""), None);
    assert_eq!(ErrorCode::known("nosuchkey"), None, "the wire spelling is case sensitive");
    assert_eq!(ErrorCode::known("NoSuchKey"), Some(ErrorCode::NO_SUCH_KEY));
    assert_eq!(
        ErrorCode::known("NoSuchKey").map(|code| code.default_status()),
        Some(StatusCode::NOT_FOUND)
    );
}

#[test]
fn the_codes_operations_declare_but_nobody_had_named_are_in_the_table() {
    // Six codes that `generated/error_codes.rs` says an operation can produce had no row before
    // rustfs/backlog#1694, so each one took the 400 fallback while reading like a mapped code.
    let cases = [
        (ErrorCode::NOT_FOUND, StatusCode::NOT_FOUND),
        (ErrorCode::OBJECT_ALREADY_IN_ACTIVE_TIER, StatusCode::FORBIDDEN),
        (ErrorCode::OBJECT_NOT_IN_ACTIVE_TIER, StatusCode::FORBIDDEN),
        (ErrorCode::ENCRYPTION_TYPE_MISMATCH, StatusCode::BAD_REQUEST),
        (ErrorCode::INVALID_WRITE_OFFSET, StatusCode::BAD_REQUEST),
        (ErrorCode::TOO_MANY_PARTS, StatusCode::BAD_REQUEST),
    ];
    for (code, expected) in cases {
        assert_eq!(code.default_status(), expected, "{code}");
        assert!(code.is_known(), "{code}");
    }
}

#[test]
fn only_deliberately_declared_codes_are_5xx() {
    let intentional = [
        ErrorCode::INTERNAL_ERROR,
        ErrorCode::NOT_IMPLEMENTED,
        ErrorCode::SERVICE_UNAVAILABLE,
        ErrorCode::SLOW_DOWN,
    ];
    for (name, status) in crate::scalar::error_code::CODE_TABLE {
        if status.is_server_error() {
            assert!(
                intentional.iter().any(|code| code.as_str() == *name),
                "{name} maps to a 5xx without being on the deliberate list"
            );
        }
    }
}

#[test]
fn the_table_has_no_duplicate_rows() {
    let table = crate::scalar::error_code::CODE_TABLE;
    for (index, (name, _)) in table.iter().enumerate() {
        assert!(
            !table[index + 1..].iter().any(|(other, _)| other == name),
            "{name} appears twice, so one of the two rows is dead"
        );
    }
}

#[test]
fn known_codes_are_recognised_as_known() {
    assert!(ErrorCode::NO_SUCH_BUCKET.is_known());
    assert!(ErrorCode::known("NoSuchKey").is_some_and(|code| code.is_known()));
    assert!(!ErrorCode::custom("Nonsense".to_owned(), StatusCode::BAD_REQUEST).is_known());
}

proptest! {
    /// No name, however arbitrary, moves the status away from the one the caller chose. The old
    /// property asserted the fallback was not a 500; there is no fallback now, so what has to hold
    /// is that the table never reaches a code that is not in it.
    #[test]
    fn an_arbitrary_name_keeps_the_status_it_was_constructed_with(name in "[A-Za-z0-9]{0,40}") {
        let error = ErrorCode::custom(name, StatusCode::IM_A_TEAPOT);
        prop_assert_eq!(error.default_status(), StatusCode::IM_A_TEAPOT);
    }
}
