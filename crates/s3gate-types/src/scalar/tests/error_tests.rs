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

//! Error-code cases: the table, the fallback that is not a 500, and the context-sensitive rules.
//!
//! Responsible for: the surprising status mappings, the table's internal consistency, the
//! existence-hiding rule, and the property that no input produces a 500.
//! NOT responsible for: which code an operation chooses.
//! Upstream: [`crate::scalar::error_code`], [`crate::scalar::error_status`]. Downstream: nothing.

use http::{Method, StatusCode};
use proptest::prelude::*;

use crate::scalar::{ErrorCode, ErrorContext, mask_for_authorization, status_of};

#[test]
fn c_err_0001_a_missing_bucket_is_404() {
    assert_eq!(ErrorCode::NO_SUCH_BUCKET.default_status(), StatusCode::NOT_FOUND);
    assert_eq!(status_of(&ErrorCode::NO_SUCH_BUCKET, &ErrorContext::default()), StatusCode::NOT_FOUND);
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
fn an_unknown_code_falls_back_to_400_and_never_to_500() {
    // A 5xx tells the client to retry something that cannot succeed, and some clients discard the
    // body of a 5xx entirely, so the operator's chosen code never reaches the user.
    let custom = ErrorCode::custom("RustFsTierBackendUnreachable".to_owned());
    assert!(!custom.is_known());
    assert_eq!(custom.default_status(), StatusCode::BAD_REQUEST);
    assert_eq!(status_of(&custom, &ErrorContext::default()), StatusCode::BAD_REQUEST);
    assert_eq!(custom.as_str(), "RustFsTierBackendUnreachable");
    assert_eq!(custom.to_string(), "RustFsTierBackendUnreachable");
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
fn a_missing_key_is_hidden_from_a_caller_who_may_not_list() {
    // Without s3:ListBucket the existence of the key is itself privileged information.
    let blind = ErrorContext::default();
    assert_eq!(mask_for_authorization(ErrorCode::NO_SUCH_KEY, &blind), ErrorCode::ACCESS_DENIED);
    assert_eq!(mask_for_authorization(ErrorCode::NO_SUCH_VERSION, &blind), ErrorCode::ACCESS_DENIED);
    assert_eq!(
        status_of(&mask_for_authorization(ErrorCode::NO_SUCH_KEY, &blind), &blind),
        StatusCode::FORBIDDEN
    );

    let permitted = ErrorContext {
        has_list_bucket_permission: true,
        ..ErrorContext::default()
    };
    assert_eq!(mask_for_authorization(ErrorCode::NO_SUCH_KEY, &permitted), ErrorCode::NO_SUCH_KEY);
    assert_eq!(status_of(&ErrorCode::NO_SUCH_KEY, &permitted), StatusCode::NOT_FOUND);
}

#[test]
fn a_bucket_owned_by_another_account_is_not_reported_as_missing() {
    let ctx = ErrorContext {
        owned_by_other_account: true,
        has_list_bucket_permission: true,
        ..ErrorContext::default()
    };
    assert_eq!(mask_for_authorization(ErrorCode::NO_SUCH_BUCKET, &ctx), ErrorCode::ACCESS_DENIED);
}

#[test]
fn a_bucket_in_another_region_redirects_instead_of_failing() {
    let moved = ErrorContext {
        region_mismatch: true,
        ..ErrorContext::default()
    };
    assert_eq!(status_of(&ErrorCode::NO_SUCH_BUCKET, &moved), StatusCode::MOVED_PERMANENTLY);

    let fresh = ErrorContext {
        dns_not_propagated: true,
        ..ErrorContext::default()
    };
    assert_eq!(status_of(&ErrorCode::NO_SUCH_BUCKET, &fresh), StatusCode::TEMPORARY_REDIRECT);
}

#[test]
fn a_head_response_reports_that_it_may_not_carry_a_body() {
    let head = ErrorContext {
        is_head: true,
        ..ErrorContext::default()
    };
    assert!(!head.body_allowed());
    assert_eq!(
        status_of(&ErrorCode::NO_SUCH_KEY, &head),
        StatusCode::NOT_FOUND,
        "the status is unchanged; only the body is dropped"
    );

    let by_method = ErrorContext {
        method: Some(Method::HEAD),
        ..ErrorContext::default()
    };
    assert!(!by_method.body_allowed());
    assert!(ErrorContext::default().body_allowed());
}

#[test]
fn known_codes_are_recognised_as_known() {
    assert!(ErrorCode::NO_SUCH_BUCKET.is_known());
    assert!(ErrorCode::from("NoSuchKey").is_known());
    assert!(!ErrorCode::custom("Nonsense".to_owned()).is_known());
}

proptest! {
    /// No string, however arbitrary, produces a server error from the mapping.
    #[test]
    fn no_arbitrary_code_maps_to_a_server_error(code in "[A-Za-z0-9]{0,40}") {
        let error = ErrorCode::custom(code);
        let ctx = ErrorContext::default();
        prop_assume!(!error.is_known());
        prop_assert!(!status_of(&error, &ctx).is_server_error());
    }
}
