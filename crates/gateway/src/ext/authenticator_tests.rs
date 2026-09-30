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
    let Ok(Some((verdict, _secret))) = authenticator().try_verify(&request).await else {
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
    let outcome = two_region_authenticator()
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
