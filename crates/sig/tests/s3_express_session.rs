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

//! S3 Express `x-amz-s3session-token` admission, `CreateSession` floor rules, and signer support.
//!
//! Responsible for: proving every fail-closed security-floor rule for S3 Express session tokens
//! (standalone non-anonymity, mixed/duplicate/multi-surface/empty/malformed refusals, SigV2 and
//! POST-policy refusals, `CreateSession`'s `DisableS3ExpressSessionAuth` and ADR-0054 refusals,
//! non-S3 service refusal, signed-header coverage, and `SigService::S3Express` scope sealing)
//! plus client-side `SigV4Signer` round-trips for header and presigned S3 Express tokens.
//! NOT responsible for: end-to-end credential lookup or HTTP response rendering (`crates/gateway`).
//! Upstream: `rustfs-gateway-sig` public API. Downstream: Cargo's test harness.

use http::Method;
use http::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_sig::{
    Admission, AmzDate, AuthError, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, HeaderTokenClaim, OperationFloor,
    PayloadMode, RawHost, RawQuery, SecurityFloor, SessionToken, SigService, SigV2Policy, SigV4Signer, SignedHeaderSet,
    SignerError, SigningCredentials, SigningRequest, SigningScope, WireView, X_AMZ_S3SESSION_TOKEN, X_AMZ_S3SESSION_TOKEN_HEADER,
    X_AMZ_SECURITY_TOKEN, X_AMZ_SECURITY_TOKEN_HEADER, detect_credentials, enforce_no_duplicate_sig_params,
};

use crate::security_floor_fixtures::{
    SIGNED_AT, form_view, header_map, now, post_form, presigned_query, s3_object_op, signed_headers,
};

fn create_session_floor() -> OperationFloor {
    OperationFloor::builtin("CreateSession", SigService::S3Express)
        .mark_privileged()
        .require_sigv4_under_every_policy()
        .refuse_s3_express_session_auth()
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — a lone `x-amz-s3session-token` header is credential presence and never anonymous.
#[test]
fn n_standalone_s3session_token_header_is_never_anonymous() {
    let headers = header_map(&[(X_AMZ_S3SESSION_TOKEN_HEADER, "express-session-tok")]);
    let view = WireView::new(&headers, RawQuery::new(""));
    let presence = detect_credentials(&view);
    assert!(presence.any());
    assert!(presence.has_s3_express_session_token());
    assert!(presence.into_evidence().is_err());

    let floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    let op = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    assert_eq!(floor.admit(view, &op, now()).err(), Some(AuthError::AuthorizationHeaderMalformed));
}

/// Negative — a lone `X-Amz-S3session-Token` query parameter is never anonymous.
#[test]
fn n_standalone_s3session_token_query_is_never_anonymous() {
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("X-Amz-S3session-Token=express-session-tok"));
    let presence = detect_credentials(&view);
    assert!(presence.any());
    assert!(presence.has_s3_express_session_token());
    assert!(presence.into_evidence().is_err());

    let floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    assert_eq!(
        floor.admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — a lone `x-amz-s3session-token` form field is never anonymous.
#[test]
fn n_standalone_s3session_token_form_is_never_anonymous() {
    let headers = HeaderMap::new();
    let fields = [(X_AMZ_S3SESSION_TOKEN_HEADER, "express-session-tok")];
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let presence = detect_credentials(&view);
    assert!(presence.any());
    assert!(presence.has_s3_express_session_token());
    assert!(presence.into_evidence().is_err());

    let floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    assert_eq!(
        floor.admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — mixing STS `x-amz-security-token` and S3 Express `x-amz-s3session-token` is
/// ambiguous on every surface combination and refused `AuthorizationHeaderMalformed`.
#[test]
fn n_mixed_security_token_and_s3session_token_is_malformed() {
    let floor = SecurityFloor::new();
    let op = s3_object_op();

    let mut both_headers = signed_headers(SIGNED_AT);
    both_headers.insert(X_AMZ_SECURITY_TOKEN_HEADER, HeaderValue::from_static("sts-tok"));
    both_headers.insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("express-tok"));
    let view = WireView::new(&both_headers, RawQuery::new(""));
    assert!(detect_credentials(&view).is_ambiguous());
    assert_eq!(floor.admit(view, &op, now()).err(), Some(AuthError::AuthorizationHeaderMalformed));

    let empty = HeaderMap::new();
    let both_query = format!(
        "{}&{X_AMZ_SECURITY_TOKEN}=sts-tok&{X_AMZ_S3SESSION_TOKEN}=express-tok",
        presigned_query(SIGNED_AT, "60")
    );
    let view = WireView::new(&empty, RawQuery::new(&both_query));
    assert!(detect_credentials(&view).is_ambiguous());
    assert_eq!(floor.admit(view, &op, now()).err(), Some(AuthError::AuthorizationHeaderMalformed));

    let mut header_sts = HeaderMap::new();
    header_sts.insert(X_AMZ_SECURITY_TOKEN_HEADER, HeaderValue::from_static("sts-tok"));
    let query_express = format!("{}&{X_AMZ_S3SESSION_TOKEN}=express-tok", presigned_query(SIGNED_AT, "60"));
    assert_eq!(
        floor
            .admit(WireView::new(&header_sts, RawQuery::new(&query_express)), &op, now())
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — duplicate `x-amz-s3session-token` headers, query parameters, or form fields are
/// refused by H6 before any rule reads one of the occurrences.
#[test]
fn n_duplicate_s3session_token_is_refused_on_every_surface() {
    let mut dup_headers = signed_headers(SIGNED_AT);
    dup_headers.append(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("tok-a"));
    dup_headers.append(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("tok-b"));
    assert_eq!(
        enforce_no_duplicate_sig_params(&WireView::new(&dup_headers, RawQuery::new(""))).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let empty = HeaderMap::new();
    let dup_query = format!("{}&{X_AMZ_S3SESSION_TOKEN}=a&{X_AMZ_S3SESSION_TOKEN}=b", presigned_query(SIGNED_AT, "60"));
    assert_eq!(
        enforce_no_duplicate_sig_params(&WireView::new(&empty, RawQuery::new(&dup_query))).err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );

    let dup_form = [(X_AMZ_S3SESSION_TOKEN_HEADER, "a"), (X_AMZ_S3SESSION_TOKEN_HEADER, "b")];
    assert_eq!(
        enforce_no_duplicate_sig_params(&WireView::new(&empty, RawQuery::new("")).with_form_fields(&dup_form)).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — carrying `x-amz-s3session-token` in both a header and the query is malformed.
#[test]
fn n_s3session_token_on_two_surfaces_is_malformed() {
    let mut headers = HeaderMap::new();
    headers.insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("tok-header"));
    let query = format!("{}&{X_AMZ_S3SESSION_TOKEN}=tok-query", presigned_query(SIGNED_AT, "60"));
    let floor = SecurityFloor::new();
    assert_eq!(
        floor
            .admit(WireView::new(&headers, RawQuery::new(&query)), &s3_object_op(), now())
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — empty, non-UTF-8, or percent-malformed `x-amz-s3session-token` values are refused.
#[test]
fn n_empty_or_malformed_s3session_token_is_refused() {
    let floor = SecurityFloor::new();
    let op = s3_object_op();

    let mut empty_header = signed_headers(SIGNED_AT);
    empty_header.insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static(""));
    assert_eq!(
        floor.admit(WireView::new(&empty_header, RawQuery::new("")), &op, now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let mut non_utf8_header = signed_headers(SIGNED_AT);
    non_utf8_header.insert(
        X_AMZ_S3SESSION_TOKEN_HEADER,
        HeaderValue::from_bytes(&[0xff, 0xfe]).expect("valid opaque header bytes"),
    );
    assert_eq!(
        floor
            .admit(WireView::new(&non_utf8_header, RawQuery::new("")), &op, now())
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    let empty = HeaderMap::new();
    for bad_query in [
        format!("{}&{X_AMZ_S3SESSION_TOKEN}=", presigned_query(SIGNED_AT, "60")),
        format!("{}&{X_AMZ_S3SESSION_TOKEN}=bad%zz", presigned_query(SIGNED_AT, "60")),
    ] {
        assert_eq!(
            floor
                .admit(WireView::new(&empty, RawQuery::new(&bad_query)), &op, now())
                .err(),
            Some(AuthError::AuthorizationQueryParametersError),
            "{bad_query}"
        );
    }
}

/// Negative — a query `X-Amz-S3session-Token` beside a header signature is malformed.
#[test]
fn n_query_s3session_token_with_header_signature_is_malformed() {
    let headers = signed_headers(SIGNED_AT);
    let query = format!("{X_AMZ_S3SESSION_TOKEN}=express-tok");
    let floor = SecurityFloor::new();
    assert_eq!(
        floor
            .admit(WireView::new(&headers, RawQuery::new(&query)), &s3_object_op(), now())
            .err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — SigV2 (header and presigned) cannot use S3 Express session tokens even when SigV2
/// compatibility is enabled.
#[test]
fn n_sigv2_refuses_s3session_token() {
    let floor = SecurityFloor::new().with_sigv2_policy(SigV2Policy::HeaderAndPresigned);
    let op = s3_object_op();

    let sigv2_headers = header_map(&[
        ("authorization", "AWS AKIDEXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        ("x-amz-date", "Sun, 30 Aug 2015 12:36:00 GMT"),
        (X_AMZ_S3SESSION_TOKEN_HEADER, "express-tok"),
    ]);
    assert_eq!(
        floor
            .admit(WireView::new(&sigv2_headers, RawQuery::new("")), &op, now())
            .err(),
        Some(AuthError::AccessDenied)
    );

    let empty = HeaderMap::new();
    let sigv2_query = format!(
        "AWSAccessKeyId=AKIDEXAMPLE&Expires=1440938220&Signature=AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&{X_AMZ_S3SESSION_TOKEN}=express-tok"
    );
    assert_eq!(
        floor
            .admit(WireView::new(&empty, RawQuery::new(&sigv2_query)), &op, now())
            .err(),
        Some(AuthError::AccessDenied)
    );
}

/// Negative — browser POST-policy uploads refuse `x-amz-s3session-token` on form or header.
#[test]
fn n_post_policy_refuses_s3session_token() {
    let floor = SecurityFloor::new();
    let op = OperationFloor::builtin("PostObject", SigService::S3).allow_post_policy();
    let empty = HeaderMap::new();

    let mut form = post_form(SIGNED_AT);
    form.push((X_AMZ_S3SESSION_TOKEN_HEADER, "express-tok".to_owned()));
    let fields = form_view(&form);
    assert_eq!(
        floor
            .admit(WireView::new(&empty, RawQuery::new("")).with_form_fields(&fields), &op, now())
            .err(),
        Some(AuthError::AccessDenied)
    );

    let form_only = post_form(SIGNED_AT);
    let fields_only = form_view(&form_only);
    let hdr = header_map(&[(X_AMZ_S3SESSION_TOKEN_HEADER, "express-tok")]);
    assert_eq!(
        floor
            .admit(WireView::new(&hdr, RawQuery::new("")).with_form_fields(&fields_only), &op, now())
            .err(),
        Some(AuthError::AccessDenied)
    );
}

/// Negative — `CreateSession` refuses `x-amz-s3session-token` (`DisableS3ExpressSessionAuth`),
/// presigned URLs, anonymous delegation, SigV2, host header tokens (ADR-0054), and custom schemes.
#[test]
fn n_create_session_floor_enforces_privileged_sigv4_and_refuses_session_and_header_tokens() {
    let op = create_session_floor();
    assert!(op.privileged());
    assert!(op.requires_sigv4_under_every_policy());
    assert!(op.refuses_s3_express_session_auth());
    assert_eq!(op.service(), SigService::S3Express);

    let mut custom = CustomSchemeRegistry::new();
    custom
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("valid prefix"))
        .expect("registrable custom scheme");
    let claim = HeaderTokenClaim::new("x-auth-token").expect("valid claim");
    let floor = SecurityFloor::new()
        .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
        .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
        .with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
        .with_custom_schemes(custom)
        .with_header_token_claim(claim);

    // ADR-0054: CreateSession never admits host header-token auth.
    assert!(!floor.admits_header_token(&op));
    let host_token = header_map(&[("x-auth-token", "keystone-token")]);
    assert_eq!(
        floor.admit(WireView::new(&host_token, RawQuery::new("")), &op, now()).err(),
        Some(AuthError::AccessDenied)
    );

    // DisableS3ExpressSessionAuth: CreateSession refuses x-amz-s3session-token.
    let mut with_express = signed_headers(SIGNED_AT);
    with_express.insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("express-tok"));
    assert_eq!(
        floor.admit(WireView::new(&with_express, RawQuery::new("")), &op, now()).err(),
        Some(AuthError::AccessDenied)
    );

    // Presigned, anonymous, SigV2, and custom schemes are all refused.
    let empty = HeaderMap::new();
    let presigned = presigned_query(SIGNED_AT, "60");
    assert_eq!(
        floor
            .admit(WireView::new(&empty, RawQuery::new(&presigned)), &op, now())
            .err(),
        Some(AuthError::AccessDenied)
    );
    assert_eq!(
        floor.admit(WireView::new(&empty, RawQuery::new("")), &op, now()).err(),
        Some(AuthError::AccessDenied)
    );
    let sigv2 = header_map(&[
        ("authorization", "AWS AKIDEXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        ("x-amz-date", "Sun, 30 Aug 2015 12:36:00 GMT"),
    ]);
    assert_eq!(
        floor.admit(WireView::new(&sigv2, RawQuery::new("")), &op, now()).err(),
        Some(AuthError::AccessDenied)
    );
    let custom_hdr = header_map(&[("x-vendor-auth-token", "opaque")]);
    let custom_result: Result<Admission<'_>, AuthError> = floor.admit(WireView::new(&custom_hdr, RawQuery::new("")), &op, now());
    assert!(
        !matches!(custom_result, Ok(Admission::Custom(_))),
        "CreateSession must never admit a custom scheme: {custom_result:?}"
    );
    assert_eq!(custom_result.err(), Some(AuthError::AccessDenied));
    let _phantom: Option<CustomAuthRequest<'_>> = None;
}

/// Negative — non-S3 services (STS, S3Vectors) refuse `x-amz-s3session-token`.
#[test]
fn n_non_s3_services_refuse_s3session_token() {
    let floor = SecurityFloor::new();
    let mut headers = signed_headers(SIGNED_AT);
    headers.insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("express-tok"));
    for service in [SigService::Sts, SigService::S3Vectors] {
        let op = OperationFloor::builtin("NonS3Op", service);
        assert_eq!(
            floor.admit(WireView::new(&headers, RawQuery::new("")), &op, now()).err(),
            Some(AuthError::AccessDenied),
            "{service:?}"
        );
    }
}

/// Negative — a host header token beside `x-amz-s3session-token` (header or case-varied query) is
/// refused `AccessDenied` under ADR-0054 exclusivity.
#[test]
fn n_host_header_token_refuses_s3session_token_header_and_case_varied_query() {
    let claim = HeaderTokenClaim::new("x-auth-token").expect("valid claim");
    let floor = SecurityFloor::new().with_header_token_claim(claim);
    let op = s3_object_op();

    let both = header_map(&[
        ("x-auth-token", "keystone-tok"),
        (X_AMZ_S3SESSION_TOKEN_HEADER, "express-tok"),
    ]);
    assert_eq!(
        floor.admit(WireView::new(&both, RawQuery::new("")), &op, now()).err(),
        Some(AuthError::AccessDenied)
    );

    let only_host = header_map(&[("x-auth-token", "keystone-tok")]);
    for query in [
        "X-Amz-S3session-Token=tok",
        "x-amz-s3session-token=tok",
        "X-AMZ-S3SESSION-TOKEN=tok",
    ] {
        assert_eq!(
            floor.admit(WireView::new(&only_host, RawQuery::new(query)), &op, now()).err(),
            Some(AuthError::AccessDenied),
            "{query}"
        );
    }
}

/// Negative — an unsigned `x-amz-s3session-token` header is rejected by `SignedHeaderSet`.
#[test]
fn n_unsigned_s3session_token_header_is_rejected() {
    let headers = header_map(&[
        ("host", "s3.example.com"),
        ("x-amz-date", SIGNED_AT),
        (X_AMZ_S3SESSION_TOKEN_HEADER, "express-tok"),
    ]);
    assert_eq!(
        SignedHeaderSet::parse_and_enforce("host;x-amz-date", &headers, None).err(),
        Some(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — `SigV4Signer::presign` refuses a caller query that already names `X-Amz-S3session-Token`.
#[test]
fn n_presign_refuses_preexisting_s3session_token_query_param() {
    let stamp = AmzDate::parse(SIGNED_AT).expect("valid stamp");
    let creds = SigningCredentials::new("AKIDEXAMPLE", b"secret")
        .expect("valid creds")
        .with_s3_express_session_token(SessionToken::new("express-tok").expect("valid token"));
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3Express).expect("valid scope");
    let mut signer = SigV4Signer::new(creds, scope);
    let headers = HeaderMap::new();
    let host = RawHost::from_authority("bucket--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com").expect("valid host");
    let request = SigningRequest::new(
        &Method::GET,
        "/key",
        "X-Amz-S3session-Token=caller-supplied",
        &headers,
        &host,
        PayloadMode::Unsigned,
        stamp,
    );
    assert_eq!(signer.presign(&request, 60).err(), Some(SignerError::SigningParameterAlreadyPresent));
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — header `x-amz-s3session-token` on an S3 operation seals `SigService::S3Express`.
#[test]
fn s3session_token_header_seals_s3express_service() {
    let mut headers = signed_headers(SIGNED_AT);
    headers.insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("express-tok"));
    let floor = SecurityFloor::new();
    let Admission::Sealed(sealed) = floor
        .admit(WireView::new(&headers, RawQuery::new("")), &s3_object_op(), now())
        .expect("admitted")
    else {
        panic!("expected SealedAws");
    };
    assert_eq!(sealed.expected_service(), SigService::S3Express);
    assert!(sealed.presence().has_s3_express_session_token());
    assert!(!sealed.presence().has_security_token());
}

/// Positive — presigned `X-Amz-S3session-Token` on a presigned S3 op seals `SigService::S3Express`.
#[test]
fn s3session_token_presigned_query_seals_s3express_service() {
    let empty = HeaderMap::new();
    let query = format!("{}&{X_AMZ_S3SESSION_TOKEN}=express%2Btok", presigned_query(SIGNED_AT, "60"));
    let floor = SecurityFloor::new();
    let Admission::Sealed(sealed) = floor
        .admit(WireView::new(&empty, RawQuery::new(&query)), &s3_object_op(), now())
        .expect("admitted")
    else {
        panic!("expected SealedAws");
    };
    assert_eq!(sealed.expected_service(), SigService::S3Express);
    assert!(sealed.presence().has_s3_express_session_token());
}

/// Positive — `CreateSession` admits both long-term IAM and STS `x-amz-security-token` SigV4
/// header requests and seals `SigService::S3Express`.
#[test]
fn create_session_admits_long_term_and_sts_sigv4_header() {
    let floor = SecurityFloor::new();
    let op = create_session_floor();

    let long_term = signed_headers(SIGNED_AT);
    let Admission::Sealed(sealed) = floor
        .admit(WireView::new(&long_term, RawQuery::new("")), &op, now())
        .expect("admitted")
    else {
        panic!("expected SealedAws");
    };
    assert_eq!(sealed.expected_service(), SigService::S3Express);

    let mut sts = signed_headers(SIGNED_AT);
    sts.insert(X_AMZ_SECURITY_TOKEN_HEADER, HeaderValue::from_static("sts-session-tok"));
    let Admission::Sealed(sealed_sts) = floor
        .admit(WireView::new(&sts, RawQuery::new("")), &op, now())
        .expect("admitted")
    else {
        panic!("expected SealedAws");
    };
    assert_eq!(sealed_sts.expected_service(), SigService::S3Express);
    assert!(sealed_sts.presence().has_security_token());
    assert!(!sealed_sts.presence().has_s3_express_session_token());
}

/// Positive — `SigV4Signer` mints `x-amz-s3session-token` (header) and `X-Amz-S3session-Token`
/// (presigned query), signs the header in `SignedHeaders`, and round-trips through the floor.
#[test]
fn signer_mints_and_signs_s3session_token_header_and_presigned_query() {
    let stamp = AmzDate::parse(SIGNED_AT).expect("valid stamp");
    let creds = SigningCredentials::new("AKIDEXAMPLE", b"secret")
        .expect("valid creds")
        .with_s3_express_session_token(SessionToken::new("express-tok+1").expect("valid token"));
    assert!(creds.is_s3_express_session_token());
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3Express).expect("valid scope");
    let mut signer = SigV4Signer::new(creds, scope);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("s3.example.com"));
    let host = RawHost::from_authority("s3.example.com").expect("valid host");
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &headers, &host, PayloadMode::Unsigned, stamp);

    let signed_hdr = signer.sign_headers(&request).expect("header signs");
    assert_eq!(
        signed_hdr
            .headers()
            .get(HeaderName::from_static(X_AMZ_S3SESSION_TOKEN_HEADER)),
        Some(&HeaderValue::from_static("express-tok+1"))
    );
    assert!(!signed_hdr.headers().contains_key(X_AMZ_SECURITY_TOKEN_HEADER));
    assert!(
        signed_hdr.authorization().expect("auth").contains("x-amz-s3session-token"),
        "SignedHeaders must include x-amz-s3session-token"
    );

    let floor = SecurityFloor::new();
    let Admission::Sealed(sealed_hdr) = floor
        .admit(
            WireView::new(signed_hdr.headers(), RawQuery::new(signed_hdr.query())),
            &s3_object_op(),
            now(),
        )
        .expect("floor admits signed header")
    else {
        panic!("expected SealedAws");
    };
    assert_eq!(sealed_hdr.expected_service(), SigService::S3Express);

    let signed_query = signer.presign(&request, 60).expect("presign succeeds");
    assert!(
        signed_query.query().contains("X-Amz-S3session-Token=express-tok%2B1"),
        "{}",
        signed_query.query()
    );
    assert!(!signed_query.query().contains(X_AMZ_SECURITY_TOKEN), "{}", signed_query.query());
    let Admission::Sealed(sealed_q) = floor
        .admit(
            WireView::new(signed_query.headers(), RawQuery::new(signed_query.query())),
            &s3_object_op(),
            now(),
        )
        .expect("floor admits presigned query")
    else {
        panic!("expected SealedAws");
    };
    assert_eq!(sealed_q.expected_service(), SigService::S3Express);
}
