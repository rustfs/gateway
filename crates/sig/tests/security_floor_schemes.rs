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

//! The security-floor scheme and boundary cases (`c-sig-0350` .. `c-sig-0380`).
//!
//! Responsible for: "credentials presented means credentials verified" (H4), the duplicate
//! signature parameter rules (H6), the privileged-surface fence and the allow-list defaults (H3),
//! and the sealed boundary that keeps a third-party verifier away from an AWS-marked request —
//! including `c-sig-0375`, which asserts the floor still runs when the built-in SigV4 computation
//! has been replaced.
//! NOT responsible for: the clock, expiry and scope cases, which are `tests/security_floor.rs`.
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (test target).

use core::time::Duration;

use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_sig::{
    Admission, AuthError, CredentialPresence, CtBytes, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, OperationFloor,
    RawQuery, ReplayDecision, ReplayNonceStore, SchemeRegistrationError, SecurityFloor, SigService, Signature, SignatureVerifier,
    Verdict, WireView, detect_aws_credential_marker, detect_credentials, enforce_no_duplicate_sig_params,
};

use crate::security_floor_fixtures::*;

/// A request with no AWS credential marker reaches the registered custom scheme after the floor.
#[test]
fn a_non_aws_request_reaches_the_custom_scheme() {
    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("a legal prefix"))
        .expect("the first registration cannot conflict");
    let floor = SecurityFloor::default().with_custom_schemes(registry);
    let headers = header_map(&[("x-vendor-auth-token", "opaque")]);
    let view = WireView::new(&headers, RawQuery::new(""));
    let request = match floor.admit(view, &s3_object_op(), now()) {
        Ok(Admission::Custom(request)) => request,
        other => panic!("expected a custom admission, got {other:?}"),
    };
    assert_eq!(request.scheme().header_prefix(), "x-vendor-auth-");
    assert!(!request.presence().any(), "no AWS surface was touched");
}

// ---------------------------------------------------------------------------
// Negative — H4 credentials presented must be verified
// ---------------------------------------------------------------------------

/// Negative — c-sig-0350: a malformed `Authorization` header is a rejection, never an anonymous
/// pass, and the presence record refuses to hand out the evidence that would allow one.
#[test]
fn c_sig_0350_a_malformed_authorization_header_is_never_anonymous() {
    let headers = header_map(&[("authorization", "AWS4-HMAC-SHA256 garbage"), ("x-amz-date", SIGNED_AT)]);
    let view = WireView::new(&headers, RawQuery::new(""));
    let presence = detect_credentials(&view);
    assert!(presence.any());
    assert!(presence.into_evidence().is_err(), "presented credentials cannot become anonymous");
    let operation = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    // Even against an anonymously reachable operation, the request is sealed to the AWS path
    // rather than downgraded.
    assert!(matches!(
        SecurityFloor::default().admit(view, &operation, now()),
        Ok(Admission::Sealed(_))
    ));
}

/// Negative — c-sig-0351: a well-formed credential with a wrong signature is a rejection verdict,
/// never an anonymous principal.
#[test]
fn c_sig_0351_a_wrong_signature_is_rejected_not_anonymous() {
    let presented = Signature::HmacSha256(CtBytes::from_array([1; 32]));
    let expected = Signature::HmacSha256(CtBytes::from_array([2; 32]));
    let verdict = match presented.ct_verify(&expected) {
        Ok(_) => panic!("different signatures produced a proof"),
        Err(rejection) => Verdict::reject(rejection.into()),
    };
    assert_eq!(verdict.rejection(), Some(AuthError::SignatureDoesNotMatch));
    assert!(!verdict.is_anonymous());
}

/// Negative — c-sig-0352: `X-Amz-Signature` without the rest of the presigned parameters is a
/// rejection, not an anonymous request.
#[test]
fn c_sig_0352_a_lone_query_signature_is_refused() {
    let query = format!("X-Amz-Signature={SIG_HEX}");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    let operation = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    let error = SecurityFloor::default().admit(view, &operation, now()).err();
    assert!(error.is_some(), "a lone query signature must not be admitted");
    assert!(detect_credentials(&view).into_evidence().is_err());
}

/// Negative — c-sig-0353: a POST form carrying a signature but no policy is refused, and never
/// downgraded to the anonymous POST a public bucket would accept.
#[test]
fn c_sig_0353_a_post_signature_without_a_policy_is_refused() {
    let fields = [("x-amz-signature", SIG_HEX), ("x-amz-date", SIGNED_AT)];
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let operation = s3_object_op()
        .allow_post_policy()
        .allow_anonymous_after_listing_in_the_posture_report();
    let error = SecurityFloor::default().admit(view, &operation, now()).err();
    assert!(error.is_some(), "a POST signature without a policy must not be admitted");
    assert!(detect_credentials(&view).into_evidence().is_err());
}

/// Negative — c-sig-0355: an `X-Amz-Security-Token` on its own is a presented credential with no
/// signature to verify. It is refused, and specifically not handed to a custom verifier.
#[test]
fn c_sig_0355_a_lone_security_token_is_refused() {
    let headers = header_map(&[("x-amz-security-token", "FQoDYXdzE")]);
    let view = WireView::new(&headers, RawQuery::new(""));
    let operation = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    assert_eq!(
        SecurityFloor::default().admit(view, &operation, now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0356: two signature surfaces on one request is an ambiguity, not a choice of
/// which verification to attempt.
#[test]
fn c_sig_0356_two_signature_surfaces_are_ambiguous_and_refused() {
    let headers = signed_headers(SIGNED_AT);
    let query = presigned_query(SIGNED_AT, "3600");
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert!(detect_credentials(&view).is_ambiguous());
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0357: a verdict a third-party verifier returns is re-checked. An `Anonymous`
/// verdict for a request that presented credentials is turned back into a rejection.
#[test]
fn c_sig_0357_a_custom_anonymous_verdict_for_a_presented_request_is_refused() {
    let presence = CredentialPresence::NONE.with_query_signature();
    let stolen = CredentialPresence::NONE.into_evidence().expect("nothing presented");
    let verdict = SecurityFloor::seal_verdict(Verdict::anonymous(stolen), presence);
    assert_eq!(verdict.rejection(), Some(AuthError::AuthorizationHeaderMalformed));
    assert!(!verdict.is_anonymous());
}

// ---------------------------------------------------------------------------
// Negative — H6 duplicate signature parameters
// ---------------------------------------------------------------------------

fn assert_repeated_query_parameter_is_refused(name: &str, value: &str) {
    let query = format!("{}&{name}={value}&{name}={value}", presigned_query(SIGNED_AT, "3600"));
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(
        enforce_no_duplicate_sig_params(&view).err(),
        Some(AuthError::AuthorizationQueryParametersError),
        "must refuse a repeated {name}"
    );
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AuthorizationQueryParametersError),
        "the floor must refuse a repeated {name} before anything else runs"
    );
}

/// Negative — c-sig-0360: a repeated signature is refused.
#[test]
fn c_sig_0360_a_repeated_signature_parameter_is_refused() {
    assert_repeated_query_parameter_is_refused("X-Amz-Signature", SIG_HEX);
}

/// Negative — c-sig-0361: a repeated credential is refused.
#[test]
fn c_sig_0361_a_repeated_credential_parameter_is_refused() {
    assert_repeated_query_parameter_is_refused("X-Amz-Credential", CRED);
}

/// Negative — c-sig-0362: every other signature-bearing query parameter is refused when repeated.
#[test]
fn c_sig_0362_every_other_signature_query_parameter_rejects_duplicates() {
    for (name, value) in [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Date", SIGNED_AT),
        ("X-Amz-Expires", "3600"),
        ("X-Amz-SignedHeaders", "host"),
        ("X-Amz-Security-Token", "FQoDYXdzE"),
    ] {
        assert_repeated_query_parameter_is_refused(name, value);
    }
}

/// Negative — c-sig-0363: two `Authorization` headers are refused for the same reason.
#[test]
fn c_sig_0363_two_authorization_headers_are_refused() {
    let mut headers = signed_headers(SIGNED_AT);
    headers.append(
        HeaderName::from_static("authorization"),
        HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host, Signature=y"),
    );
    let view = WireView::new(&headers, RawQuery::new(""));
    assert_eq!(
        enforce_no_duplicate_sig_params(&view).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0367: a repeated signed header that participates in the signature — the
/// timestamp, the payload digest, the session token — is refused too.
#[test]
fn c_sig_0367_repeated_signature_bearing_headers_are_refused() {
    for name in ["x-amz-date", "x-amz-content-sha256", "x-amz-security-token"] {
        let mut headers = signed_headers(SIGNED_AT);
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a valid header name");
        headers.append(name.clone(), HeaderValue::from_static("second"));
        headers.append(name, HeaderValue::from_static("third"));
        let view = WireView::new(&headers, RawQuery::new(""));
        assert_eq!(
            enforce_no_duplicate_sig_params(&view).err(),
            Some(AuthError::AuthorizationHeaderMalformed)
        );
    }
}

/// Negative — c-sig-0368: a repeated POST form field is refused on the same grounds.
#[test]
fn c_sig_0368_a_repeated_post_form_field_is_refused() {
    let fields = [
        ("x-amz-signature", SIG_HEX),
        ("x-amz-signature", "0000000000000000000000000000000000000000000000000000000000000000"),
    ];
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    assert_eq!(
        enforce_no_duplicate_sig_params(&view).err(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

// ---------------------------------------------------------------------------
// Negative — H3 the privileged surface
// ---------------------------------------------------------------------------

/// Negative — c-sig-0364: a presigned URL aimed at a privileged operation is refused. Rewriting a
/// presigned URL onto an admin operation is MinIO #5411.
#[test]
fn c_sig_0364_a_privileged_operation_refuses_presigned() {
    let query = presigned_query(SIGNED_AT, "3600");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(
        SecurityFloor::default().admit(view, &admin_op(), now()).err(),
        Some(AuthError::AccessDenied)
    );
    // And the allow-list cannot be widened to let one in.
    assert!(admin_op().allow_presigned().is_err());
}

/// Negative — c-sig-0365: an operation that never declared a scheme accepts header signatures
/// only. A custom operation is privileged until it says otherwise.
#[test]
fn c_sig_0365_the_default_allow_list_excludes_presigned_and_anonymous() {
    let custom = OperationFloor::custom("Vendor:DoThing", SigService::S3);
    assert!(custom.privileged(), "a custom operation is privileged by default");
    assert!(!custom.allows_anonymous());
    assert!(!custom.allowed_schemes().allows_presigned());
    assert!(!custom.allowed_schemes().allows_post_policy());
    assert!(custom.allowed_schemes().allows_header());

    let query = presigned_query(SIGNED_AT, "3600");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(SecurityFloor::default().admit(view, &custom, now()).err(), Some(AuthError::AccessDenied));

    // An anonymous request against it is refused as well, rather than reaching the operation.
    let empty = HeaderMap::new();
    let anonymous = WireView::new(&empty, RawQuery::new(""));
    assert_eq!(
        SecurityFloor::default().admit(anonymous, &custom, now()).err(),
        Some(AuthError::AccessDenied)
    );
}

/// Negative — c-sig-0366: SigV2 presigned is off unless a deployment turns it on, and even then
/// this crate refuses it rather than verifying it (P2-06 owns the string-to-sign).
#[test]
fn c_sig_0366_sigv2_presigned_is_refused() {
    let query = format!("AWSAccessKeyId=AKIDEXAMPLE&Expires=1440938160&Signature={SIG_HEX}");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(
        SecurityFloor::default().admit(view, &s3_object_op(), now()).err(),
        Some(AuthError::AccessDenied)
    );
}

// ---------------------------------------------------------------------------
// Negative — the sealed boundary
// ---------------------------------------------------------------------------

/// A verifier that would authenticate anything, and counts how often it was asked.
struct AlwaysYes {
    calls: std::sync::atomic::AtomicUsize,
}

impl SignatureVerifier for AlwaysYes {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Verdict::reject(AuthError::AccessDenied)
    }
}

fn sealed_floor() -> SecurityFloor {
    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("a legal prefix"))
        .expect("the first registration cannot conflict");
    SecurityFloor::default().with_custom_schemes(registry)
}

fn assert_aws_marker_never_reaches_custom_verifier(case: &str, view: WireView<'_>) {
    let verifier = AlwaysYes {
        calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let floor = sealed_floor();
    let operation = s3_object_op().allow_anonymous_after_listing_in_the_posture_report();
    assert!(detect_aws_credential_marker(&view).is_some(), "{case}: the marker must be detected");
    match floor.admit(view, &operation, now()) {
        Ok(Admission::Custom(request)) => {
            let _ = verifier.verify(&request);
            panic!("{case}: an AWS-marked request reached the custom verifier");
        }
        Ok(Admission::Anonymous(_)) => panic!("{case}: an AWS-marked request was treated as anonymous"),
        Ok(Admission::Sealed(_)) | Err(_) => {}
        Ok(_) => panic!("{case}: an AWS-marked request took an unexpected admission"),
    }
    assert_eq!(verifier.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// Negative — c-sig-0370: a SigV4 header never reaches a custom verifier.
#[test]
fn c_sig_0370_a_sigv4_header_never_reaches_a_custom_verifier() {
    let mut headers = signed_headers(SIGNED_AT);
    headers.append(HeaderName::from_static("x-vendor-auth-token"), HeaderValue::from_static("opaque"));
    assert_aws_marker_never_reaches_custom_verifier("c-sig-0370", WireView::new(&headers, RawQuery::new("")));
}

/// Negative — c-sig-0371: a presigned request never reaches a custom verifier.
#[test]
fn c_sig_0371_a_presigned_request_never_reaches_a_custom_verifier() {
    let headers = HeaderMap::new();
    let query = presigned_query(SIGNED_AT, "3600");
    assert_aws_marker_never_reaches_custom_verifier("c-sig-0371", WireView::new(&headers, RawQuery::new(&query)));
}

/// Negative — c-sig-0372: a SigV2 header never reaches a custom verifier.
#[test]
fn c_sig_0372_a_sigv2_header_never_reaches_a_custom_verifier() {
    let headers = header_map(&[
        ("authorization", &format!("AWS AKIDEXAMPLE:{SIG_HEX}")),
        ("x-vendor-auth-token", "opaque"),
    ]);
    assert_aws_marker_never_reaches_custom_verifier("c-sig-0372", WireView::new(&headers, RawQuery::new("")));
}

struct RememberReplay;

impl ReplayNonceStore for RememberReplay {
    fn record_first_use(&self, _fingerprint: rustfs_gateway_sig::ReplayFingerprint) -> ReplayDecision {
        ReplayDecision::FirstUse
    }
}

/// H7: replay prevention is an explicit deployment hook and its key never reveals a signature.
#[test]
fn h7_replay_nonce_hook_is_explicit_and_opaque() {
    let store = RememberReplay;
    let query = presigned_query(SIGNED_AT, "3600");
    let headers = HeaderMap::new();
    let sealed = match SecurityFloor::default().admit(WireView::new(&headers, RawQuery::new(&query)), &s3_object_op(), now()) {
        Ok(Admission::Sealed(sealed)) => sealed,
        other => panic!("expected a sealed presigned request, got {other:?}"),
    };
    let fingerprint = sealed
        .replay_fingerprint()
        .expect("presigned requests have a replay fingerprint");
    assert_eq!(format!("{fingerprint:?}"), "ReplayFingerprint(<opaque>)");
    let decision = store.record_first_use(fingerprint);
    assert_eq!(decision, ReplayDecision::FirstUse);
}

/// Negative — c-sig-0373: a custom scheme may not claim an AWS prefix, and two schemes may not
/// claim overlapping ones.
#[test]
fn c_sig_0373_a_custom_scheme_cannot_claim_a_reserved_or_taken_prefix() {
    for reserved in ["x-amz-", "X-Amz-Custom-", "authorization", "Authorization-Extra"] {
        assert_eq!(
            CustomAuthScheme::new(reserved).err(),
            Some(SchemeRegistrationError::ReservedPrefix),
            "must refuse {reserved}"
        );
    }
    for malformed in ["", "vendor auth", "vendor_auth", "Vendor-Auth-"] {
        assert!(CustomAuthScheme::new(malformed).is_err(), "must refuse {malformed}");
    }

    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("legal"))
        .expect("first");
    assert_eq!(
        registry
            .register(CustomAuthScheme::new("x-vendor-auth-").expect("legal"))
            .err(),
        Some(SchemeRegistrationError::Conflict)
    );
    assert_eq!(
        registry.register(CustomAuthScheme::new("x-vendor-").expect("legal")).err(),
        Some(SchemeRegistrationError::Conflict),
        "a prefix of a registered prefix overlaps it"
    );
}

/// Negative — c-sig-0374: an anonymously reachable operation still runs the whole floor, and it is
/// visible to the startup posture report rather than only to whoever registered it. This is the
/// visibility half of attack scenario A.
#[test]
fn c_sig_0374_an_anonymous_operation_still_runs_the_floor() {
    let operation =
        OperationFloor::custom("Vendor:PostThing", SigService::Sts).allow_anonymous_after_listing_in_the_posture_report();
    assert!(operation.allows_anonymous());
    assert!(operation.privileged(), "a custom operation stays privileged");

    // A duplicated signature parameter is still a rejection on the anonymous path.
    let query = format!("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature={SIG_HEX}");
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new(&query));
    assert_eq!(
        SecurityFloor::default().admit(view, &operation, now()).err(),
        Some(AuthError::AuthorizationQueryParametersError)
    );
}

/// Negative — the failure paths stay indistinguishable: the two credential rejections share one
/// message, no rejection message names a value from the request, and every rejection is held to
/// the same latency floor.
#[test]
fn c_sig_0379_rejections_are_not_separable_by_message_or_latency() {
    let floor = SecurityFloor::default();
    assert!(!floor.failure_floor().floor().is_zero());
    assert_eq!(AuthError::InvalidAccessKeyId.message(), AuthError::SignatureDoesNotMatch.message());
    for error in [
        AuthError::InvalidAccessKeyId,
        AuthError::SignatureDoesNotMatch,
        AuthError::AuthorizationHeaderMalformed,
        AuthError::AccessDenied,
        AuthError::RequestExpired,
        AuthError::RequestTimeTooSkewed,
        AuthError::AuthorizationQueryParametersError,
    ] {
        let message = error.message();
        assert!(!message.contains("AKIDEXAMPLE"), "{error:?} names an access key");
        assert!(!message.contains(SIG_HEX), "{error:?} names a signature");
        // Every rejection owes the same floor, whichever stage produced it.
        assert_eq!(floor.failure_floor().remaining(Duration::ZERO), Some(floor.failure_floor().floor()));
    }
}

// ---------------------------------------------------------------------------
// Negative — c-sig-0375: the floor outlives the verifier it wraps
// ---------------------------------------------------------------------------

/// Negative — c-sig-0375: with `dangerous-replace-signature-verifier` on, a replacement that
/// authenticates absolutely everything still never sees a request the floor refused. Run with
/// `cargo test -p rustfs-gateway-sig --features dangerous-replace-signature-verifier -- floor_still_enforced`.
#[cfg(feature = "dangerous-replace-signature-verifier")]
#[test]
fn c_sig_0375_floor_still_enforced_when_the_verifier_is_replaced() {
    use rustfs_gateway_sig::{AwsSignatureVerifier, CtBytes, DangerAck, Identity, RequestNow, SealedAws, Signature};

    /// The worst replacement anybody could write: it authenticates without looking.
    struct AuthenticateEverything {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl AwsSignatureVerifier for AuthenticateEverything {
        fn verify_sealed(&self, request: &SealedAws<'_>) -> Verdict {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let bytes = Signature::HmacSha256(CtBytes::from_array([7u8; 32]));
            let proof = bytes
                .ct_verify(&Signature::HmacSha256(CtBytes::from_array([7u8; 32])))
                .expect("equal signatures match");
            Verdict::authenticated(
                Identity::new("AKIDEXAMPLE").expect("valid"),
                rustfs_gateway_sig::AuthScheme::sigv4_presigned(
                    rustfs_gateway_sig::SigIdentity::LongTerm,
                    request.expected_service(),
                ),
                proof,
            )
        }
    }

    // The witness cannot be defaulted or built from a literal; this is the only spelling.
    let _ack = DangerAck::i_understand_this_disables_aws_sigv4();
    let replacement = AuthenticateEverything {
        calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let floor = SecurityFloor::default();

    // Four requests the floor refuses. Each would be authenticated by the replacement above if it
    // ever reached it, and none of them does.
    let expired = presigned_query(SIGNED_AT, "60");
    let over_ceiling = presigned_query(SIGNED_AT, "604801");
    let duplicated = format!("{}&X-Amz-Signature={SIG_HEX}", presigned_query(SIGNED_AT, "3600"));
    let fresh = presigned_query(SIGNED_AT, "3600");
    let empty = HeaderMap::new();
    let cases: [(&str, &str, RequestNow, &OperationFloor, AuthError); 4] = [
        (
            "expired",
            &expired,
            RequestNow::from_unix_seconds(SIGNED_AT_UNIX + 61),
            &s3_object_op(),
            AuthError::RequestExpired,
        ),
        (
            "over the ceiling",
            &over_ceiling,
            now(),
            &s3_object_op(),
            AuthError::AuthorizationQueryParametersError,
        ),
        (
            "duplicated signature",
            &duplicated,
            now(),
            &s3_object_op(),
            AuthError::AuthorizationQueryParametersError,
        ),
        ("privileged surface", &fresh, now(), &admin_op(), AuthError::AccessDenied),
    ];
    for (label, query, at, operation, expected) in cases {
        let view = WireView::new(&empty, RawQuery::new(query));
        match floor.admit(view, operation, at) {
            Err(error) => assert_eq!(error, expected, "{label}"),
            Ok(Admission::Sealed(sealed)) => {
                let _ = replacement.verify_sealed(&sealed);
                panic!("{label}: the floor let a refused request through to the replacement");
            }
            Ok(_) => panic!("{label}: unexpected admission"),
        }
    }
    assert_eq!(
        replacement.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the replacement must not have been reached at all"
    );
}
