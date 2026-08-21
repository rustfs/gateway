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
    Admission, OperationFloor, RawQuery, RequestNow, SecurityFloor, SigService, SigV2Policy, SigV2Signer, SkewWindow, WireView,
    enforce_clock_skew,
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
    let Ok(Some(verdict)) = authenticator().try_verify(&request).await else {
        panic!("authenticated verdict required")
    };
    assert!(verdict.is_authenticated());
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
}
