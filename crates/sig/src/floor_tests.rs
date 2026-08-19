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

//! The security floor's own unit suite.
//!
//! Responsible for: the floor rules that are decidable from a `WireView` alone — duplicate
//! detection through a malformed escape, the session-token-without-a-signature rejection, and the
//! header-free `Debug`.
//! NOT responsible for: admission outcomes, which are `crates/sig/tests/security_floor*.rs` and
//! `crates/sig/tests/sig_v2_admission.rs`.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::*;
use crate::query::RawQuery;

fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = http::header::HeaderName::from_bytes(name.as_bytes()).expect("valid name");
        map.append(name, http::HeaderValue::from_str(value).expect("valid value"));
    }
    map
}

/// Negative — a duplicate spelled with a broken escape is still a duplicate.
#[test]
fn a_malformed_escape_cannot_hide_a_second_occurrence() {
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("X-Amz-Signature=a%zz&X-Amz-Signature=b"));
    assert_eq!(view.count_query_param(X_AMZ_SIGNATURE), 2);
    assert_eq!(
        enforce_no_duplicate_sig_params(&view).err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
}

/// Negative — a session token with no signature is neither verifiable nor anonymous.
#[test]
fn a_security_token_alone_is_a_rejection() {
    let headers = headers_with(&[(X_AMZ_SECURITY_TOKEN_HEADER, "FQoDYXdzE")]);
    let view = WireView::new(&headers, RawQuery::new(""));
    let presence = detect_credentials(&view);
    assert!(presence.any());
    assert!(presence.into_evidence().is_err());
}

/// Negative — the wire view prints no header value.
#[test]
fn the_wire_view_debug_prints_no_header_value() {
    let headers = headers_with(&[("authorization", "AWS4-HMAC-SHA256 Credential=leaked")]);
    let view = WireView::new(&headers, RawQuery::new(""));
    let rendered = format!("{view:?}");
    assert!(!rendered.contains("leaked"));
}
