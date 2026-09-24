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

//! Responsible for: static pre-authentication constructors and their closed status set.
//! NOT responsible for: routing or the generated error-to-status authority.
//! Upstream: core pre-authentication errors. Downstream: core integration regression coverage.

use http::StatusCode;
use rustfs_gateway_core::error::{PRE_AUTH_STATUSES, PreAuthError};

#[test]
fn bad_request_constructor_is_static_and_uses_the_registered_wire_code() {
    const ERROR: PreAuthError = PreAuthError::bad_request("An Origin header is required for this OPTIONS request");
    assert_eq!(ERROR.code().as_str(), "BadRequest");
    assert!(ERROR.code().is_known());
    assert_eq!(ERROR.status(), StatusCode::BAD_REQUEST);
    assert_eq!(ERROR.message(), "An Origin header is required for this OPTIONS request");
    assert_eq!(ERROR.operation(), None);
}

#[test]
fn bad_request_constructor_does_not_substitute_other_pre_auth_errors() {
    let error = PreAuthError::bad_request("static");
    for other in [
        PreAuthError::invalid_request("static"),
        PreAuthError::invalid_argument("static"),
        PreAuthError::access_forbidden("static"),
        PreAuthError::not_implemented("static"),
    ] {
        assert_ne!(error.code(), other.code());
    }
}

#[test]
fn bad_request_constructor_does_not_discard_the_static_message() {
    let first = PreAuthError::bad_request("first static explanation");
    let second = PreAuthError::bad_request("second static explanation");
    assert_ne!(first.message(), second.message());
    assert_eq!(second.message(), "second static explanation");
}

/// Every constructor lands inside the closed set.
#[test]
fn every_pre_auth_error_carries_an_allowed_status() {
    let errors = [
        PreAuthError::bad_request("headerless OPTIONS"),
        PreAuthError::invalid_argument("a"),
        PreAuthError::invalid_request("b"),
        PreAuthError::access_denied("c"),
        PreAuthError::not_implemented("d"),
    ];
    for error in errors {
        assert!(
            PRE_AUTH_STATUSES.contains(&error.status()),
            "{} maps to {}, outside the pre-authentication set",
            error.code(),
            error.status()
        );
        // 501 is in the set on purpose; 500 and 503 are what must be unreachable, because a
        // client that receives one retries a request that cannot succeed.
        assert_ne!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
