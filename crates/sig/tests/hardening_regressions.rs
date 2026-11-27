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

//! Security-hardening regressions for rustfs/gateway#1628 across `rustfs-gateway-sig`.
//!
//! Responsible for: negative and positive controls for POST-policy auth-field bindings,
//! same-surface SigV4/SigV2 ambiguity, duplicate `Date` headers, custom-scheme prefix overlap and
//! multi-scheme ambiguity, leap-second rejection in `AmzDate`, T10 strict lowercase hex in POST
//! policy signatures, and T4 disposition hygiene in `SIDE_CHANNELS`.
//! NOT responsible for: gateway-level HTTP pipeline wiring, authorization, or failure-floor async
//! awaiting (owned by `rustfs-gateway` tests).
//! Upstream: `rustfs-gateway-sig` public API. Downstream: Cargo's integration test harness.

use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_sig::codec::{encode_base64_exact, encode_hex_lower};
use rustfs_gateway_sig::timing::{Disposition, SIDE_CHANNELS};
use rustfs_gateway_sig::{
    Admission, AmzDate, AuthError, CustomAuthScheme, CustomSchemeRegistry, HeaderTokenClaim, OperationFloor, PostPolicy,
    PostPolicyError, PostPolicyLimits, RawQuery, RequestNow, SchemeRegistrationError, SecurityFloor, SigService, SigV2Policy,
    WireView, detect_credentials, enforce_no_duplicate_sig_params,
};

use crate::security_floor_fixtures::{CRED, SIG_HEX, SIGNED_AT, header_map, now, presigned_query, s3_object_op, signed_headers};

fn encode_policy_json(json: &str) -> String {
    let mut out = String::new();
    for chunk in json.as_bytes().chunks(3) {
        match chunk {
            [a, b, c] => out.push_str(&encode_base64_exact(&[*a, *b, *c])),
            [a, b] => out.push_str(&encode_base64_exact(&[*a, *b])),
            [a] => out.push_str(&encode_base64_exact(&[*a])),
            _ => unreachable!("chunks of three are non-empty"),
        }
    }
    out
}

fn post_fields<'a>(policy: &'a str, signature: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut fields = vec![
        ("key", "uploads/${filename}"),
        ("bucket", "example-bucket"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", CRED),
        ("x-amz-date", SIGNED_AT),
        ("x-amz-signature", signature),
        ("policy", policy),
    ];
    fields.extend_from_slice(extra);
    fields
}

// ── Item 2: SigV4 PostPolicy auth-field condition enforcement ────────────────────────────────────

/// Negative — omitting `x-amz-date` from POST policy `conditions` must be refused so an attacker
/// cannot rewrite the timestamp within the UTC day to bypass H1's 15-minute skew window.
#[test]
fn n_sigv4_post_policy_without_x_amz_date_condition_is_rejected() {
    let json = format!(
        r#"{{"expiration":"2015-08-30T13:36:00Z","conditions":[{{"bucket":"example-bucket"}},["starts-with","$key","uploads/"],{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{CRED}"}}]}}"#
    );
    let encoded = encode_policy_json(&json);
    let fields = post_fields(&encoded, SIG_HEX, &[]);
    let result = PostPolicy::parse(&fields, "report.txt", PostPolicyLimits::default(), now());
    assert_eq!(result.err(), Some(PostPolicyError::ConditionFailed));
}

/// Negative — a `starts-with` prefix condition on `x-amz-date`, `x-amz-credential`, or
/// `x-amz-algorithm` does not bind the exact signed value and must be refused (prevents same-day
/// `HHMMSS` rewriting under `["starts-with","$x-amz-date","20150830T"]`), and a non-matching
/// `starts-with` condition on `x-amz-security-token` must be refused.
#[test]
fn n_sigv4_post_policy_with_starts_with_auth_field_is_rejected() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"},["starts-with","$x-amz-date","20150830T"]]"#,
            &[],
        ),
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-algorithm":"AWS4-HMAC-SHA256"},["starts-with","$x-amz-credential","AKIDEXAMPLE/"],{"x-amz-date":"20150830T123600Z"}]"#,
            &[],
        ),
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],["starts-with","$x-amz-algorithm","AWS4-"],{"x-amz-credential":"AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"},{"x-amz-date":"20150830T123600Z"}]"#,
            &[],
        ),
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"},{"x-amz-date":"20150830T123600Z"},["starts-with","$x-amz-security-token","other-"]]"#,
            &[("x-amz-security-token", "token-secret-value")],
        ),
    ];
    for (conditions, extra) in cases {
        let json = format!(r#"{{"expiration":"2015-08-30T13:36:00Z","conditions":{conditions}}}"#);
        let encoded = encode_policy_json(&json);
        let fields = post_fields(&encoded, SIG_HEX, extra);
        let result = PostPolicy::parse(&fields, "report.txt", PostPolicyLimits::default(), now());
        assert_eq!(result.err(), Some(PostPolicyError::ConditionFailed), "conditions={conditions}");
    }
}

/// Negative — omitting `x-amz-credential`, `x-amz-algorithm`, or a presented
/// `x-amz-security-token` from POST policy `conditions` must be refused.
#[test]
fn n_sigv4_post_policy_without_auth_conditions_is_rejected() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-date":"20150830T123600Z"}]"#,
            &[],
        ),
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-credential":"AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"},{"x-amz-date":"20150830T123600Z"}]"#,
            &[],
        ),
        (
            r#"[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"},{"x-amz-date":"20150830T123600Z"}]"#,
            &[("x-amz-security-token", "token-secret-value")],
        ),
    ];
    for (conditions, extra) in cases {
        let json = format!(r#"{{"expiration":"2015-08-30T13:36:00Z","conditions":{conditions}}}"#);
        let encoded = encode_policy_json(&json);
        let fields = post_fields(&encoded, SIG_HEX, extra);
        let result = PostPolicy::parse(&fields, "report.txt", PostPolicyLimits::default(), now());
        assert_eq!(result.err(), Some(PostPolicyError::ConditionFailed), "conditions={conditions}");
    }
}

/// Positive — exact conditions on `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`, and a
/// presented `x-amz-security-token` are accepted.
#[test]
fn p_sigv4_post_policy_with_exact_auth_and_session_conditions_succeeds() {
    let json = format!(
        r#"{{"expiration":"2015-08-30T13:36:00Z","conditions":[{{"bucket":"example-bucket"}},["starts-with","$key","uploads/"],{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{CRED}"}},{{"x-amz-date":"{SIGNED_AT}"}},{{"x-amz-security-token":"token-secret-value"}}]}}"#
    );
    let encoded = encode_policy_json(&json);
    let fields = post_fields(&encoded, SIG_HEX, &[("x-amz-security-token", "token-secret-value")]);
    let policy = PostPolicy::parse(&fields, "report.txt", PostPolicyLimits::default(), now()).expect("bound policy");
    assert_eq!(policy.final_key(), "uploads/report.txt");
    assert!(policy.session_token().is_some());
}

/// Negative — T10: SigV4 POST policy signatures must use canonical lowercase hex.
#[test]
fn n_sigv4_post_policy_rejects_uppercase_hex_signature() {
    let json = format!(
        r#"{{"expiration":"2015-08-30T13:36:00Z","conditions":[{{"bucket":"example-bucket"}},["starts-with","$key","uploads/"],{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{CRED}"}},{{"x-amz-date":"{SIGNED_AT}"}}]}}"#
    );
    let encoded = encode_policy_json(&json);
    let uppercase = encode_hex_lower(&[0xab; 32]).to_ascii_uppercase();
    let fields = post_fields(&encoded, &uppercase, &[]);
    let result = PostPolicy::parse(&fields, "report.txt", PostPolicyLimits::default(), now());
    assert_eq!(result.err(), Some(PostPolicyError::Malformed));
}

// ── Item 5: H4 same-surface SigV4 + SigV2 credential ambiguity ─────────────────────────────────

/// Negative — H4 must reject simultaneous SigV4 and SigV2 credential parameters on the query
/// surface under both AWS default recognition and RustFS legacy recognition.
#[test]
fn n_h4_rejects_same_surface_sigv4_and_sigv2_query_credentials() {
    let headers = HeaderMap::new();
    let op = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    let floors = [
        SecurityFloor::default().with_sigv2_policy(SigV2Policy::HeaderAndPresigned),
        SecurityFloor::default()
            .with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
            .recognize_signatures_as_legacy_rustfs(),
    ];
    let sigv2_sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D";
    let queries = [
        format!(
            "{}&AWSAccessKeyId=AKIDEXAMPLE&Expires=2000000000&Signature={sigv2_sig}",
            presigned_query(SIGNED_AT, "3600")
        ),
        format!("X-Amz-Signature={SIG_HEX}&Signature={sigv2_sig}"),
        format!("X-Amz-Credential={CRED}&Signature={sigv2_sig}"),
        format!("X-Amz-Signature={SIG_HEX}&AWSAccessKeyId=AKIDEXAMPLE"),
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&AWSAccessKeyId=AKIDEXAMPLE".to_owned(),
    ];
    for query in &queries {
        let view = WireView::new(&headers, RawQuery::new(query));
        assert!(detect_credentials(&view).is_ambiguous(), "query must be ambiguous: {query}");
        assert!(detect_credentials(&view).any(), "ambiguous query must never be anonymous: {query}");
        for floor in &floors {
            assert_eq!(
                floor.admit(view, &op, now()).err(),
                Some(AuthError::AuthorizationHeaderMalformed),
                "floor must refuse ambiguous query: {query}"
            );
        }
    }
}

/// Negative — H4 must reject simultaneous SigV4 and SigV2 credential fields on the POST form
/// surface under both AWS default recognition and RustFS legacy recognition.
#[test]
fn n_h4_rejects_same_surface_sigv4_and_sigv2_form_credentials() {
    let headers = HeaderMap::new();
    let op = s3_object_op()
        .allow_post_policy()
        .allow_anonymous_after_listing_in_the_posture_report();
    let floors = [
        SecurityFloor::default().with_sigv2_policy(SigV2Policy::HeaderAndPresigned),
        SecurityFloor::default()
            .with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
            .recognize_signatures_as_legacy_rustfs(),
    ];
    let forms: &[&[(&str, &str)]] = &[
        &[("x-amz-signature", SIG_HEX), ("signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")],
        &[("x-amz-credential", CRED), ("signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=")],
        &[("x-amz-signature", SIG_HEX), ("AWSAccessKeyId", "AKIDEXAMPLE")],
        &[("x-amz-algorithm", "AWS4-HMAC-SHA256"), ("AWSAccessKeyId", "AKIDEXAMPLE")],
    ];
    for fields in forms {
        let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(fields);
        assert!(detect_credentials(&view).is_ambiguous(), "form must be ambiguous: {fields:?}");
        assert!(detect_credentials(&view).any(), "ambiguous form must never be anonymous: {fields:?}");
        for floor in &floors {
            assert_eq!(
                floor.admit(view, &op, now()).err(),
                Some(AuthError::AuthorizationHeaderMalformed),
                "floor must refuse ambiguous form: {fields:?}"
            );
        }
    }
}

// ── Item 6: H6 duplicate `Date` header enforcement ─────────────────────────────────────────────

/// Negative — H6 must refuse duplicate `Date` headers on both SigV4 and SigV2 header-signed
/// requests, including when a single valid `x-amz-date` is also present.
#[test]
fn n_h6_rejects_duplicate_date_header() {
    let mut headers = signed_headers(SIGNED_AT);
    headers.append(http::header::DATE, HeaderValue::from_static("Sun, 30 Aug 2015 12:36:00 GMT"));
    headers.append(http::header::DATE, HeaderValue::from_static("Sun, 30 Aug 2015 12:36:01 GMT"));
    let view = WireView::new(&headers, RawQuery::new(""));
    assert_eq!(
        enforce_no_duplicate_sig_params(&view).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let mut date_only = HeaderMap::new();
    date_only.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_static("AWS AKIDEXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    );
    date_only.append(http::header::DATE, HeaderValue::from_static("Sun, 30 Aug 2015 12:36:00 GMT"));
    date_only.append(http::header::DATE, HeaderValue::from_static("Sun, 30 Aug 2015 12:36:01 GMT"));
    let sigv2_view = WireView::new(&date_only, RawQuery::new(""));
    assert_eq!(
        SecurityFloor::default()
            .with_sigv2_policy(SigV2Policy::HeaderOnly)
            .admit(sigv2_view, &s3_object_op(), now())
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

// ── Item 9: CustomAuthScheme prefix reservation & multi-scheme ambiguity ───────────────────────

/// Negative — `CustomAuthScheme::new("x-")` (and uppercase `"X-"`) overlaps the reserved `x-amz-`
/// namespace and must be refused with `ReservedPrefix`.
#[test]
fn n_custom_scheme_rejects_super_prefix_of_x_amz() {
    for reserved in ["x-", "X-", "x-amz-", "X-Amz-"] {
        assert_eq!(
            CustomAuthScheme::new(reserved).err(),
            Some(SchemeRegistrationError::ReservedPrefix),
            "must refuse {reserved}"
        );
    }
    // Positive control: a sibling `x-` prefix that does not overlap `x-amz-` remains valid.
    assert!(CustomAuthScheme::new("x-corp-").is_ok());
}

/// Negative — a request carrying headers for two distinct registered custom schemes is ambiguous:
/// `matching` must not pick the first one, the floor must refuse with `AuthorizationHeaderMalformed`,
/// and header-token exclusivity must still reject a request carrying both custom schemes beside the
/// header token.
#[test]
fn n_custom_scheme_registry_rejects_multiple_matching_schemes() {
    let mut registry = CustomSchemeRegistry::new();
    let corp = CustomAuthScheme::new("x-corp-").expect("legal prefix");
    let partner = CustomAuthScheme::new("x-partner-").expect("legal prefix");
    registry.register(corp).expect("first");
    registry.register(partner).expect("second");

    // Positive control: one matching scheme is returned unambiguously.
    let single_headers = header_map(&[("x-corp-token", "a")]);
    let single_view = WireView::new(&single_headers, RawQuery::new(""));
    assert_eq!(registry.matching(&single_view), Some(corp));

    // Ambiguous: both custom schemes present on the same request.
    let both_headers = header_map(&[("x-corp-token", "a"), ("x-partner-token", "b")]);
    let both_view = WireView::new(&both_headers, RawQuery::new(""));
    assert_eq!(registry.matching(&both_view), None, "matching must not silently pick the first scheme");
    assert!(
        registry.any_matches(&both_view),
        "any_matches must still report presented custom credentials"
    );

    let floor = SecurityFloor::default().with_custom_schemes(registry.clone());
    assert_eq!(
        floor.admit(both_view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
    // Must also never fall through to anonymous on an anonymous-allowing operation.
    let anon_op = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    assert_eq!(
        floor.admit(both_view, &anon_op, now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    // Header-token exclusivity must still see the two custom schemes as another credential.
    let claim = HeaderTokenClaim::new("x-host-token").expect("valid claim");
    let floor_with_token = SecurityFloor::default()
        .with_custom_schemes(registry)
        .with_header_token_claim(claim);
    let token_and_two_custom = header_map(&[
        ("x-host-token", "host-secret"),
        ("x-corp-token", "a"),
        ("x-partner-token", "b"),
    ]);
    let token_view = WireView::new(&token_and_two_custom, RawQuery::new(""));
    assert_eq!(
        floor_with_token.admit(token_view, &s3_object_op(), now()).err(),
        Some(AuthError::AccessDenied)
    );
    // Sanity control: header token alone succeeds.
    let token_only = header_map(&[("x-host-token", "host-secret")]);
    assert!(matches!(
        floor_with_token.admit(WireView::new(&token_only, RawQuery::new("")), &s3_object_op(), now()),
        Ok(Admission::HeaderToken(_))
    ));
}

// ── Item 10: AmzDate rejects leap second 60 ────────────────────────────────────────────────────

/// Negative — `AmzDate::parse` must reject second `60` on every date and minute so H1 epoch day
/// cannot split from H3 scope day at `235960Z`.
#[test]
fn n_amz_date_rejects_leap_second_60() {
    for bad in [
        "20260101T235960Z",
        "20260630T235960Z",
        "20261231T235960Z",
        "20260101T123460Z",
        "20161231T235960Z",
    ] {
        assert_eq!(
            AmzDate::parse(bad).err(),
            Some(AuthError::AuthorizationHeaderMalformed),
            "must reject leap second {bad}"
        );
    }
    assert_eq!(
        rustfs_gateway_sig::sig_v2::parse_sigv2_date("Thu, 01 Jan 2026 23:59:60 GMT").err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
    // Positive control: 59 remains accepted.
    let valid = AmzDate::parse("20260101T235959Z").expect("59 is valid");
    assert_eq!(valid.as_str(), "20260101T235959Z");
}

// ── Item 12: timing.rs T4 disposition hygiene ──────────────────────────────────────────────────

/// Positive and negative — T4 is closed rather than carrying a stale `DeferredTo("P2-04 ...")`.
#[test]
fn t4_is_closed_and_no_stale_deferrals_remain_in_side_channels() {
    let t4 = SIDE_CHANNELS.iter().find(|entry| entry.id == "T4").expect("T4 exists");
    assert_eq!(t4.disposition, Disposition::ClosedHere);
    assert!(
        !SIDE_CHANNELS
            .iter()
            .any(|entry| matches!(entry.disposition, Disposition::DeferredTo(_))),
        "no side channel should remain deferred once P2-04 has landed"
    );
    let _ = RequestNow::from_unix_seconds(0);
    let _ = OperationFloor::builtin("GetObject", SigService::S3);
}
