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

//! The `SigV4Authenticator` unit suite.
//!
//! Responsible for: the built-in authenticator's own contracts — `dyn` compatibility, the region
//! set's refusal of an empty configuration, the outage-versus-rejection boundary, and the two
//! shapes an `AuthenticationOutcome` can carry.
//! NOT responsible for: what an assembled service does with a request, which is
//! `crates/gateway/tests/`.
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;

use crate::ext::credentials::{Credentials, StaticCredentials};
use rustfs_gateway_sig::{
    Admission, AmzDate, CredentialScope, OperationFloor, RawQuery, RequestNow, SecurityFloor, SigService, SigV2Policy,
    SigV2Signer, SkewWindow, WireView, enforce_clock_skew,
};

fn authenticator() -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"))),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
}

/// Negative — the verifier is usable behind `Arc<dyn _>`. An RPITIT method here would not
/// compile at all, which is the measured `E0038` ADR-0002 records.
#[test]
fn the_trait_is_dyn_compatible() {
    let _: Arc<dyn Authenticator> = Arc::new(authenticator());
}

/// Negative — a deployment cannot be built with an empty region set: an empty set matches no
/// presented region and would reject every request with a scope error rather than saying the
/// configuration is wrong.
#[test]
fn an_empty_region_set_is_refused_where_it_is_written() {
    assert!(RegionSet::new(Vec::<String>::new()).is_err());
}

/// Negative — a store outage is not an `AuthError`, so it cannot be rendered as a statement
/// about the caller's credentials.
#[test]
fn a_store_outage_is_not_a_credential_rejection() {
    assert_eq!(Unavailable.to_string(), "the credential store could not answer");
}

#[test]
fn an_ordinary_outcome_borrows_the_exact_verdict() {
    let outcome = AuthenticationOutcome::ordinary(Verdict::reject(AuthError::AuthorizationHeaderMalformed));
    assert_eq!(outcome.verdict().rejection(), Some(AuthError::AuthorizationHeaderMalformed));
    assert!(outcome.scope_rejection.is_none());
}

#[test]
fn a_scope_outcome_fixes_the_public_verdict() {
    let signed_at = AmzDate::parse("20150830T123600Z").expect("valid timestamp");
    let clock = enforce_clock_skew(&signed_at, RequestNow::from_unix_seconds(1_440_938_160), SkewWindow::DEFAULT)
        .expect("inside the window");
    let regions = RegionSet::new(["us-east-1"]).expect("valid region");
    let expected = ExpectedScope::new(SigService::S3, &regions);
    let presented = CredentialScope::parse("AKID/20150830/eu-west-1/s3/aws4_request").expect("valid scope");
    let rejection = enforce_scope(&presented, clock, &expected).expect_err("region is not configured");
    let outcome = AuthenticationOutcome::scope_rejected(rejection);

    assert_eq!(outcome.verdict().rejection(), Some(AuthError::AuthorizationHeaderMalformed));
    assert_eq!(
        outcome
            .scope_rejection
            .as_ref()
            .and_then(ScopeRejection::expected_region)
            .map(rustfs_gateway_sig::ScopeRegion::as_str),
        Some("us-east-1")
    );
}

#[tokio::test]
async fn c_sig_0428_form_field_material_uses_the_post_policy_authority() {
    const POLICY: &str = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2Fkcy9yZXBvcnQudHh0In0seyJ4LWFtei1hbGdvcml0aG0iOiJBV1M0LUhNQUMtU0hBMjU2In0seyJ4LWFtei1jcmVkZW50aWFsIjoiQUtJREVYQU1QTEUvMjAxNTA4MzAvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LHsieC1hbXotZGF0ZSI6IjIwMTUwODMwVDEyMzYwMFoifV19";
    let headers = http::HeaderMap::new();
    let fields = [
        ("key", "uploads/report.txt"),
        ("bucket", "example-bucket"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-amz-signature", "77e76bae68e9999f40becaeae16e5e41ae02b70e6e816c41d7fcf1a3a7e0b5f9"),
        ("policy", POLICY),
    ];
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let operation = OperationFloor::builtin("PutObject", SigService::S3).allow_post_policy();
    let admitted = SecurityFloor::new()
        .admit(view, &operation, RequestNow::from_unix_seconds(1_440_938_160))
        .expect("valid form reaches the sealed path");
    let Admission::Sealed(sealed) = admitted else { panic!("AWS form must be sealed") };
    let method = Method::POST;
    let host = RawHost::from_host_header(b"example-bucket.s3.example.test").expect("valid host");
    let payload = PayloadMode::Empty;
    let request = Authentication::new(&sealed, &method, "/", &host, &payload, Some(0));
    let Ok((verdict, _secret)) = authenticator().try_verify(&request).await else {
        panic!("authenticated verdict required")
    };
    assert!(verdict.is_authenticated());
    let scope = verdict.verified_scope().expect("a SigV4 form names its scope");
    assert_eq!((scope.date().as_str(), scope.region(), scope.service()), ("20150830", "us-east-1", "s3"));
}

// ── the verified scope on the verdict ─────────────────────────────────────────────────────────

const SCOPE_STAMP: &str = "20150830T123600Z";
const SCOPE_NOW: i64 = 1_440_938_160;
const SCOPE_HOST: &[u8] = b"s3.example.test";

/// Two served regions, so a verdict reporting the first configured one is not a pass.
fn two_region_authenticator() -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"))),
        RegionSet::new(["us-east-1", "eu-west-1"]).expect("non-empty"),
    )
}

fn signer_for(region: &str) -> rustfs_gateway_sig::SigV4Signer {
    let stamp = AmzDate::parse(SCOPE_STAMP).expect("valid stamp");
    let scope = rustfs_gateway_sig::SigningScope::new(stamp.day(), region, SigService::S3).expect("valid scope");
    let credentials = rustfs_gateway_sig::SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    rustfs_gateway_sig::SigV4Signer::new(credentials, scope)
}

/// A bodiless `GET /bucket`, header-signed for `region`.
fn header_signed(region: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.test"));
    let host = RawHost::from_host_header(SCOPE_HOST).expect("valid host");
    let stamp = AmzDate::parse(SCOPE_STAMP).expect("valid stamp");
    let signing =
        rustfs_gateway_sig::SigningRequest::new(&Method::GET, "/bucket", "", &headers, &host, PayloadMode::Unsigned, stamp);
    signer_for(region).sign_headers(&signing).expect("signable").headers().clone()
}

/// Floor, then the built-in verifier, exactly as the service runs them.
async fn verify(headers: &http::HeaderMap, query: &str, operation: &OperationFloor) -> Verdict {
    verify_with(&two_region_authenticator(), headers, query, operation).await
}

async fn verify_with(
    authenticator: &SigV4Authenticator,
    headers: &http::HeaderMap,
    query: &str,
    operation: &OperationFloor,
) -> Verdict {
    let view = WireView::new(headers, RawQuery::new(query));
    let admitted = SecurityFloor::new()
        .admit(view, operation, RequestNow::from_unix_seconds(SCOPE_NOW))
        .expect("the floor admits the request");
    let Admission::Sealed(sealed) = admitted else { panic!("a SigV4 request must be sealed") };
    let token = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");
    let payload = PayloadMode::parse(token, rustfs_gateway_sig::TrailerSet::None).expect("payload mode");
    let host = RawHost::from_host_header(SCOPE_HOST).expect("valid host");
    let request = Authentication::new(&sealed, &Method::GET, "/bucket", &host, &payload, None);
    let outcome = authenticator
        .authenticate(&request)
        .await
        .expect("credential store is available");
    let (verdict, _, _) = outcome.into_parts();
    verdict
}

/// Positive — the verdict names the region the signature was verified under. `RegionSet` sorts,
/// so the first served region here is `eu-west-1`; signing for `us-east-1` means a verdict that
/// reported the first configured region instead would fail.
#[tokio::test]
async fn a_header_signed_verdict_carries_the_verified_scope() {
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&header_signed("us-east-1"), "", &operation).await;
    let scope = verdict
        .verified_scope()
        .expect("an authenticated SigV4 verdict names its scope");
    assert_eq!((scope.date().as_str(), scope.region(), scope.service()), ("20150830", "us-east-1", "s3"));
}

/// Positive — a presigned URL's scope is carried from the query it was verified from.
#[tokio::test]
async fn a_presigned_verdict_carries_the_verified_scope() {
    let headers = {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.test"));
        headers
    };
    let host = RawHost::from_host_header(SCOPE_HOST).expect("valid host");
    let stamp = AmzDate::parse(SCOPE_STAMP).expect("valid stamp");
    let signing =
        rustfs_gateway_sig::SigningRequest::new(&Method::GET, "/bucket", "", &headers, &host, PayloadMode::Unsigned, stamp);
    let presigned = signer_for("eu-west-1").presign(&signing, 900).expect("presignable");
    let operation = OperationFloor::builtin_presigned("GetBucketLocation", SigService::S3);
    let verdict = verify(presigned.headers(), presigned.query(), &operation).await;
    let scope = verdict.verified_scope().expect("a presigned SigV4 verdict names its scope");
    assert_eq!(scope.region(), "eu-west-1");
}

/// Negative — a client cannot choose the region the verdict reports. Re-scoping a valid
/// signature to the other served region keeps the old signature, which no longer verifies, so
/// the request is rejected and no scope is reported at all.
#[tokio::test]
async fn a_rescoped_credential_is_rejected_and_reports_no_scope() {
    let mut headers = header_signed("us-east-1");
    let authorization = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .expect("a signed request has an Authorization header")
        .replace("/us-east-1/", "/eu-west-1/");
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&authorization).expect("valid header"),
    );
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&headers, "", &operation).await;
    assert_eq!(verdict.rejection(), Some(AuthError::SignatureDoesNotMatch));
    assert!(verdict.verified_scope().is_none());
}

/// Negative — a scope naming a region this deployment does not serve never becomes a verdict
/// scope, even with a signature that is valid for that region.
#[tokio::test]
async fn an_unserved_region_is_rejected_and_reports_no_scope() {
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&header_signed("ap-south-1"), "", &operation).await;
    assert_eq!(verdict.rejection(), Some(AuthError::AuthorizationHeaderMalformed));
    assert!(verdict.verified_scope().is_none());
}

/// A bodiless `GET /bucket`, header-signed for `us-east-1` and dated by the HTTP `Date` header,
/// with no `x-amz-date` (rustfs/gateway#809), plus any `extra` headers the caller wants sent.
fn date_signed(extra: &[(&'static str, &str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.test"));
    for (name, value) in extra {
        headers.insert(http::HeaderName::from_static(name), http::HeaderValue::from_str(value).expect("ASCII"));
    }
    let host = RawHost::from_host_header(SCOPE_HOST).expect("valid host");
    let stamp = AmzDate::parse(SCOPE_STAMP).expect("valid stamp");
    let signing =
        rustfs_gateway_sig::SigningRequest::new(&Method::GET, "/bucket", "", &headers, &host, PayloadMode::Unsigned, stamp)
            .dated_by_http_date();
    signer_for("us-east-1")
        .sign_headers(&signing)
        .expect("signable")
        .headers()
        .clone()
}

/// The floor's answer alone, for a request the floor is expected to refuse.
fn floor_refusal(headers: &http::HeaderMap, now: i64) -> Option<AuthError> {
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let view = WireView::new(headers, RawQuery::new(""));
    SecurityFloor::new()
        .admit(view, &operation, RequestNow::from_unix_seconds(now))
        .err()
}

/// Positive — a request dated only by the HTTP `Date` header verifies: the floor reads `Date` for
/// the skew check, the string-to-sign is dated with the same instant, and the verdict names the
/// scope (rustfs/gateway#809, s3-tests `test_object_create_date_and_amz_date`).
#[tokio::test]
async fn a_request_dated_by_the_date_header_verifies() {
    let headers = date_signed(&[]);
    assert!(headers.get("x-amz-date").is_none());
    assert_eq!(
        headers.get("date").and_then(|value| value.to_str().ok()),
        Some("Sun, 30 Aug 2015 12:36:00 GMT")
    );
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&headers, "", &operation).await;
    assert_eq!(verdict.rejection(), None, "{verdict:?}");
    assert_eq!(verdict.verified_scope().map(|scope| scope.region()), Some("us-east-1"));
}

/// Positive — with both headers present, `x-amz-date` is the timestamp: a request signed under
/// `x-amz-date` verifies whatever an unsigned `Date` beside it says, because the signature covers
/// `x-amz-date` and the skew check judged the same field.
#[tokio::test]
async fn x_amz_date_wins_over_a_disagreeing_date_header() {
    let mut headers = header_signed("us-east-1");
    headers.insert(http::header::DATE, http::HeaderValue::from_static("Thu, 01 Jan 2015 00:00:00 GMT"));
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&headers, "", &operation).await;
    assert_eq!(verdict.rejection(), None, "{verdict:?}");
}

/// Negative — the `Date` header that dates a request is covered by the signature: rewriting it
/// to another instant inside the skew window changes the string-to-sign, so the signature no
/// longer matches, and a replay under a fresh `Date` cannot succeed.
#[tokio::test]
async fn n_a_rewritten_date_header_no_longer_matches_its_signature() {
    let mut headers = date_signed(&[]);
    headers.insert(http::header::DATE, http::HeaderValue::from_static("Sun, 30 Aug 2015 12:37:00 GMT"));
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&headers, "", &operation).await;
    assert_eq!(verdict.rejection(), Some(AuthError::SignatureDoesNotMatch));
}

/// Negative — a `Date` that supplies the timestamp but is left out of `SignedHeaders` is refused:
/// the list is rewritten to `host` alone, and the verifier answers `SignatureDoesNotMatch` before
/// any signature is compared.
#[tokio::test]
async fn n_an_unsigned_date_header_cannot_date_a_request() {
    let mut headers = date_signed(&[]);
    let authorization = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .expect("a signed request has an Authorization header")
        .to_owned();
    assert!(authorization.contains("SignedHeaders=date;host;"), "{authorization}");
    let authorization = authorization.replace("SignedHeaders=date;host;", "SignedHeaders=host;");
    headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(&authorization).expect("valid"));
    let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
    let verdict = verify(&headers, "", &operation).await;
    assert_eq!(verdict.rejection(), Some(AuthError::SignatureDoesNotMatch));
}

/// Negative — the `Date` path has the same skew window as `x-amz-date`: the same request judged
/// twenty minutes later is `RequestTimeTooSkewed`; and a `Date` the grammar refuses — a real
/// offset, a two-digit year, an empty value — is `AuthorizationHeaderMalformed`, while a request
/// with neither header is refused as before.
#[tokio::test]
async fn n_a_stale_or_malformed_date_header_is_refused_at_the_floor() {
    let headers = date_signed(&[]);
    assert_eq!(floor_refusal(&headers, SCOPE_NOW), None);
    assert_eq!(floor_refusal(&headers, SCOPE_NOW + 20 * 60), Some(AuthError::RequestTimeTooSkewed));
    for malformed in ["Sun, 30 Aug 2015 12:36:00 +0200", "Sun, 30 Aug 15 12:36:00 GMT", ""] {
        let mut headers = date_signed(&[]);
        headers.insert(http::header::DATE, http::HeaderValue::from_str(malformed).expect("ASCII"));
        assert_eq!(
            floor_refusal(&headers, SCOPE_NOW),
            Some(AuthError::AuthorizationHeaderMalformed),
            "{malformed:?}"
        );
    }
    let mut neither = date_signed(&[]);
    neither.remove(http::header::DATE);
    assert_eq!(floor_refusal(&neither, SCOPE_NOW), Some(AuthError::AuthorizationHeaderMalformed));
}

/// Positive — c-sig-0586: the built-in verifier authenticates the floor-sealed SigV2 POST proof.
#[tokio::test]
async fn c_sig_0586_sigv2_post_policy_reaches_the_builtin_authenticator() {
    const POLICY: &str = "eyJleHBpcmF0aW9uIjoiMjAzMC0wMS0wMVQwMDowMDowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2Fkcy9yZXBvcnQudHh0In1dfQ==";
    let signer = SigV2Signer::new("AKIDEXAMPLE", b"secret").expect("valid signer");
    let signature = signer.post_policy_signature(POLICY);
    let headers = http::HeaderMap::new();
    let fields = [
        ("key", "uploads/report.txt"),
        ("bucket", "example-bucket"),
        ("AWSAccessKeyId", "AKIDEXAMPLE"),
        ("signature", signature.as_str()),
        ("policy", POLICY),
    ];
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let operation = OperationFloor::builtin("PutObject", SigService::S3).allow_post_policy();
    let admitted = SecurityFloor::new()
        .with_sigv2_policy(SigV2Policy::HeaderAndPresigned)
        .admit(view, &operation, RequestNow::from_unix_seconds(1_440_938_160))
        .expect("valid SigV2 form reaches the sealed path");
    let Admission::SealedSigV2(sealed) = admitted else { panic!("SigV2 form must be sealed") };
    let method = Method::POST;
    let request = SigV2Authentication::new(&sealed, &method, "/", None);
    let outcome = authenticator()
        .verify_sigv2(&request)
        .await
        .expect("credential store is available");
    let verdict = outcome.verdict();
    assert!(verdict.is_authenticated());
    let Verdict::Authenticated { scheme, .. } = verdict else {
        panic!("authenticated scheme required")
    };
    assert_eq!(scheme.family, SigFamily::V2);
    assert_eq!(scheme.location, SigLocation::FormField);
    // SigV2 has no credential scope, so none is reported rather than one being invented.
    assert!(verdict.verified_scope().is_none());
}

// ── an expired session: `ExpiredToken` only to a caller that proved possession ───────────────────
//
// rustfs/gateway#1575. SDKs refresh temporary credentials on `ExpiredToken`; every other session
// failure stays the uniform `InvalidAccessKeyId`. Each negative differs from the positive in one
// fact the caller would have to hold: the secret, the token, or a usable key.

const SESSION_TOKEN: &str = "FQoGZXIvYXdzEExampleSessionTokenValue";
const OTHER_TOKEN: &str = "FQoGZXIvYXdzEAnotherSessionTokenValue";
const SESSION_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const WRONG_SECRET: &[u8] = b"this-is-not-the-secret-the-target-knows-";

fn session(access_key: &str, expires_at: i64) -> Credentials {
    let binding = crate::ext::credentials::SessionBinding::new("sts.example.test", expires_at).expect("a valid binding");
    Credentials::new(access_key, SESSION_SECRET)
        .expect("a valid access key")
        .with_session(SESSION_TOKEN, binding)
        .expect("a valid token")
}

fn session_authenticator() -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(
            StaticCredentials::new()
                .with(session("AKIDEXPIRED", SCOPE_NOW - 1))
                .with(session("AKIDLIVE", SCOPE_NOW + 3_600))
                .with(session("AKIDDISABLED", SCOPE_NOW - 1).disable()),
        ),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
}

fn session_signer(access_key: &str, secret: &[u8], token: Option<&str>) -> rustfs_gateway_sig::SigV4Signer {
    let stamp = AmzDate::parse(SCOPE_STAMP).expect("valid stamp");
    let scope = rustfs_gateway_sig::SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("valid scope");
    let mut credentials = rustfs_gateway_sig::SigningCredentials::new(access_key, secret).expect("valid credentials");
    if let Some(token) = token {
        credentials = credentials.with_session_token(rustfs_gateway_sig::SessionToken::new(token).expect("non-empty"));
    }
    rustfs_gateway_sig::SigV4Signer::new(credentials, scope)
}

/// The header-signed or presigned `GET /bucket` the session cases send, and what it is answered.
async fn session_verdict(access_key: &str, secret: &[u8], token: Option<&str>, presigned: bool) -> Verdict {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.test"));
    let host = RawHost::from_host_header(SCOPE_HOST).expect("valid host");
    let stamp = AmzDate::parse(SCOPE_STAMP).expect("valid stamp");
    let signing =
        rustfs_gateway_sig::SigningRequest::new(&Method::GET, "/bucket", "", &headers, &host, PayloadMode::Unsigned, stamp);
    let mut signer = session_signer(access_key, secret, token);
    let authenticator = session_authenticator();
    if presigned {
        let signed = signer.presign(&signing, 900).expect("presignable");
        let operation = OperationFloor::builtin_presigned("GetBucketLocation", SigService::S3);
        verify_with(&authenticator, signed.headers(), signed.query(), &operation).await
    } else {
        let signed = signer.sign_headers(&signing).expect("signable");
        let operation = OperationFloor::builtin("GetBucketLocation", SigService::S3);
        verify_with(&authenticator, signed.headers(), "", &operation).await
    }
}

/// Positive — an expired session whose signature verified under its own secret, presenting the
/// token issued with it, is answered `ExpiredToken`: the answer an SDK refreshes on. Header and
/// presigned spellings alike.
#[tokio::test]
async fn an_expired_session_that_proved_possession_is_told_it_expired() {
    for presigned in [false, true] {
        let verdict = session_verdict("AKIDEXPIRED", SESSION_SECRET, Some(SESSION_TOKEN), presigned).await;
        assert_eq!(verdict.rejection(), Some(AuthError::ExpiredToken), "presigned = {presigned}");
    }
}

/// Positive — the same session an hour before its end is authenticated, so the refusal above is
/// the lifetime and nothing else about the fixture.
#[tokio::test]
async fn a_live_session_presenting_its_token_is_authenticated() {
    for presigned in [false, true] {
        let verdict = session_verdict("AKIDLIVE", SESSION_SECRET, Some(SESSION_TOKEN), presigned).await;
        assert!(verdict.is_authenticated(), "presigned = {presigned}: {verdict:?}");
    }
}

/// Negative — the oracle direction: an expired session signed with a secret the caller does not
/// hold is the uniform refusal. Answering the expiry here would confirm a real issuance to anyone
/// who guessed its access key.
#[tokio::test]
async fn an_expired_session_with_a_wrong_signature_is_not_told_it_expired() {
    for presigned in [false, true] {
        let verdict = session_verdict("AKIDEXPIRED", WRONG_SECRET, Some(SESSION_TOKEN), presigned).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "presigned = {presigned}");
    }
}

/// Negative — an expired session presenting another, correctly signed token is a binding
/// violation and is answered as one, not as an expiry.
#[tokio::test]
async fn an_expired_session_with_another_token_is_not_told_it_expired() {
    for presigned in [false, true] {
        let verdict = session_verdict("AKIDEXPIRED", SESSION_SECRET, Some(OTHER_TOKEN), presigned).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "presigned = {presigned}");
    }
}

/// Negative — an expired session presented without any token is the uniform refusal.
#[tokio::test]
async fn an_expired_session_without_its_token_is_not_told_it_expired() {
    for presigned in [false, true] {
        let verdict = session_verdict("AKIDEXPIRED", SESSION_SECRET, None, presigned).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "presigned = {presigned}");
    }
}

/// Negative — a disabled session is refused uniformly even when it has also expired and the
/// caller proved possession: switched off outranks the lifetime, header and presigned alike.
#[tokio::test]
async fn a_disabled_expired_session_is_not_told_it_expired() {
    for presigned in [false, true] {
        let verdict = session_verdict("AKIDDISABLED", SESSION_SECRET, Some(SESSION_TOKEN), presigned).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "presigned = {presigned}");
    }
}

/// Negative — an access key the provider does not know, signed with a token, is the uniform
/// refusal.
#[tokio::test]
async fn an_unknown_session_key_is_the_uniform_refusal() {
    let verdict = session_verdict("AKIDUNKNOWN", SESSION_SECRET, Some(SESSION_TOKEN), false).await;
    assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId));
}

/// Negative — the rendered expiry is the `400` the error authority gives `ExpiredToken`, and the
/// uniform refusal is still `403`. What the body carries is asserted on the wire, in
/// `tests/credential_runtime.rs`.
#[test]
fn the_expired_token_answer_is_a_400_and_the_uniform_refusal_a_403() {
    use rustfs_gateway_core::ResponseKind;
    use rustfs_gateway_types::ErrorCode;
    let expired = crate::render::from_auth(AuthError::ExpiredToken, ResponseKind::Other, false);
    assert_eq!(expired.code(), Some(&ErrorCode::EXPIRED_TOKEN));
    assert_eq!(expired.status(), http::StatusCode::BAD_REQUEST);
    let uniform = crate::render::from_auth(AuthError::InvalidAccessKeyId, ResponseKind::Other, false);
    assert_eq!(uniform.status(), http::StatusCode::FORBIDDEN);
}

// ── the POST-policy spelling of the same rule ─────────────────────────────────────────────────

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut block = [0_u8; 64];
    for (slot, byte) in block.iter_mut().zip(key) {
        *slot = *byte;
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Standard padded base64; the codec's own encoder takes fixed-size arrays only.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, byte)| n | u32::from(*byte) << (16 - 8 * i));
        for index in 0..4 {
            let sextet = ((n >> (18 - 6 * index)) & 63) as usize;
            let symbol = ALPHABET.get(sextet).copied().map_or('=', char::from);
            out.push(if index <= chunk.len() { symbol } else { '=' });
        }
    }
    out
}

/// A SigV4 browser form for `access_key`, carrying the issued session token, signed with `secret`.
async fn session_form_verdict(access_key: &str, secret: &[u8]) -> Verdict {
    let credential = format!("{access_key}/20150830/us-east-1/s3/aws4_request");
    // Concatenated rather than formatted: the token is a fixture, and no formatting macro names it.
    let document = [
        r#"{"expiration":"2015-08-30T13:36:00Z","conditions":[{"bucket":"example-bucket"},{"key":"uploads/report.txt"},"#,
        r#"{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":""#,
        credential.as_str(),
        r#""},{"x-amz-date":"20150830T123600Z"},{"x-amz-security-token":""#,
        SESSION_TOKEN,
        r#""}]}"#,
    ]
    .concat();
    let policy = base64(document.as_bytes());
    let mut key = hmac_sha256(&[b"AWS4".as_slice(), secret].concat(), b"20150830");
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = rustfs_gateway_sig::codec::encode_hex_lower(&hmac_sha256(&key, policy.as_bytes()));
    let headers = http::HeaderMap::new();
    let fields = [
        ("key", "uploads/report.txt"),
        ("bucket", "example-bucket"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", credential.as_str()),
        ("x-amz-date", "20150830T123600Z"),
        ("x-amz-security-token", SESSION_TOKEN),
        ("x-amz-signature", signature.as_str()),
        ("policy", policy.as_str()),
    ];
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let operation = OperationFloor::builtin("PutObject", SigService::S3).allow_post_policy();
    let admitted = SecurityFloor::new()
        .admit(view, &operation, RequestNow::from_unix_seconds(SCOPE_NOW))
        .expect("the form reaches the sealed path");
    let Admission::Sealed(sealed) = admitted else { panic!("a SigV4 form must be sealed") };
    let host = RawHost::from_host_header(b"example-bucket.s3.example.test").expect("valid host");
    let (method, payload) = (Method::POST, PayloadMode::Empty);
    let request = Authentication::new(&sealed, &method, "/", &host, &payload, Some(0));
    let authenticator = session_authenticator();
    let outcome = authenticator.authenticate(&request).await.expect("the store answers");
    outcome.into_parts().0
}

/// Positive — a browser form for an expired session, signed with its secret and carrying its
/// token, is told `ExpiredToken`; the same form for the live session is authenticated, so the
/// fixture is a valid form and only the lifetime differs.
#[tokio::test]
async fn an_expired_session_form_that_proved_possession_is_told_it_expired() {
    let expired = session_form_verdict("AKIDEXPIRED", SESSION_SECRET).await;
    assert_eq!(expired.rejection(), Some(AuthError::ExpiredToken));
    let live = session_form_verdict("AKIDLIVE", SESSION_SECRET).await;
    assert!(live.is_authenticated(), "{live:?}");
}

/// Negative — the same form signed with a secret the caller does not hold, and the same form for
/// a disabled expired session, are the uniform refusal.
#[tokio::test]
async fn an_expired_session_form_without_the_secret_is_not_told_it_expired() {
    for (access_key, secret) in [("AKIDEXPIRED", WRONG_SECRET), ("AKIDDISABLED", SESSION_SECRET)] {
        let verdict = session_form_verdict(access_key, secret).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{access_key}");
    }
}
