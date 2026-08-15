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

//! Runtime coverage for the custom-signature extension point.
//!
//! Responsible for: proving that a registered non-AWS scheme reaches its installed verifier and
//! then the ordinary authorization pipeline, while AWS-marked requests remain sealed away from it.
//! NOT responsible for: the signature floor's parsing rules or built-in SigV4 verification.
//! Upstream: `rustfs_gateway::ServiceBuilder`. Downstream: the assembled service pipeline.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::dto::ListBuckets;
use rustfs_gateway::sig::{
    AuthError, AuthScheme, CredentialPresence, CtBytes, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, Identity,
    SigFamily, SigIdentity, SigLocation, SigService, Signature, SignatureVerifier, Verdict,
};
use rustfs_gateway_core::route::{generated_entries, render_selector};

#[cfg(feature = "dangerous-replace-signature-verifier")]
use rustfs_gateway::sig::{AwsSignatureVerifier, DangerAck, SealedAws};

use crate::support::{self, Backend, CountingBackend, Ping, exchange, ping_route};

struct AcceptingVerifier {
    calls: Arc<AtomicUsize>,
}

struct AnonymousVerifier;

impl SignatureVerifier for AnonymousVerifier {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
        Verdict::anonymous(
            CredentialPresence::NONE
                .into_evidence()
                .expect("no AWS credential surface was recorded"),
        )
    }
}

struct RejectingVerifier {
    calls: Arc<AtomicUsize>,
}

impl SignatureVerifier for AcceptingVerifier {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let actual = Signature::HmacSha256(CtBytes::from_array([7; 32]));
        let expected = Signature::HmacSha256(CtBytes::from_array([7; 32]));
        let proof = actual.ct_verify(&expected).expect("equal signatures produce a proof");
        Verdict::authenticated(
            Identity::new("VENDORACCESSKEY").expect("a valid identity"),
            AuthScheme::new(SigFamily::V4, SigLocation::Header, SigIdentity::LongTerm, SigService::S3),
            proof,
        )
    }
}

impl SignatureVerifier for RejectingVerifier {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Verdict::reject(AuthError::AccessDenied)
    }
}

fn custom_floor() -> rustfs_gateway::SecurityFloor {
    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("a legal custom prefix"))
        .expect("the first scheme is unique");
    rustfs_gateway::SecurityFloor::new().with_custom_schemes(registry)
}

#[tokio::test]
async fn c_sig_0308_a_non_aws_request_reaches_the_installed_custom_verifier() {
    let calls = Arc::new(AtomicUsize::new(0));
    let reached = Arc::new(AtomicUsize::new(0));
    let service = support::wired()
        .security_floor(custom_floor())
        .custom_signature_verifier(AcceptingVerifier {
            calls: Arc::clone(&calls),
        })
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let request = support::plain(http::Method::POST, "/");
    let (mut parts, body) = request.into_parts();
    parts
        .headers
        .insert("x-vendor-auth-token", http::HeaderValue::from_static("opaque"));

    let (status, _) = exchange(&service, http::Request::from_parts(parts, body)).await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    assert!(service.security_posture().custom_signature_verifier());
    assert!(
        service
            .security_posture()
            .to_string()
            .contains("custom signature verifier: installed")
    );
}

#[tokio::test]
async fn a_custom_verifier_rejection_never_reaches_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let reached = Arc::new(AtomicUsize::new(0));
    let service = support::wired()
        .security_floor(custom_floor())
        .custom_signature_verifier(RejectingVerifier {
            calls: Arc::clone(&calls),
        })
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let request = support::plain(http::Method::POST, "/");
    let (mut parts, body) = request.into_parts();
    parts
        .headers
        .insert("x-vendor-auth-token", http::HeaderValue::from_static("opaque"));

    let (status, _) = exchange(&service, http::Request::from_parts(parts, body)).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_custom_credential_cannot_be_downgraded_to_anonymous() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = support::wired()
        .security_floor(custom_floor())
        .custom_signature_verifier(AnonymousVerifier)
        .register::<Ping, _>(Arc::new(CountingBackend::new(&reached)))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let request = support::plain(http::Method::POST, "/");
    let (mut parts, body) = request.into_parts();
    parts
        .headers
        .insert("x-vendor-auth-token", http::HeaderValue::from_static("opaque"));

    let (status, _) = exchange(&service, http::Request::from_parts(parts, body)).await;

    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_aws_marked_request_never_reaches_the_custom_verifier() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .security_floor(custom_floor())
        .custom_signature_verifier(AcceptingVerifier {
            calls: Arc::clone(&calls),
        })
        .register::<ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");
    let request = support::signed_with(http::Method::GET, "/", &[("x-vendor-auth-token", "opaque")]);

    let (status, _) = exchange(&service, request).await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0378: security posture is startup-only and has no unauthenticated HTTP route.
#[tokio::test]
async fn c_sig_0378_no_unauthenticated_security_posture_endpoint_exists() {
    for entry in generated_entries().expect("the generated route table is valid") {
        let selector = render_selector(&entry.selector);
        for forbidden in ["/debug", "/status", "/security-posture"] {
            assert!(!selector.contains(forbidden), "{} exposes {forbidden}: {selector}", entry.op_name);
        }
    }

    let service = support::wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    assert!(!service.security_posture().custom_signature_verifier());
    assert!(
        service
            .security_posture()
            .to_string()
            .contains("custom signature verifier: none")
    );

    for path in ["/debug", "/status", "/security-posture"] {
        let (status, body) = exchange(&service, support::plain(http::Method::GET, path)).await;
        assert_ne!(status, http::StatusCode::OK, "{path} exposed an unauthenticated endpoint");
        assert!(!body.contains("custom_verifier"));
    }
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
struct AuthenticateEverything {
    calls: Arc<AtomicUsize>,
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
impl AwsSignatureVerifier for AuthenticateEverything {
    fn verify_sealed(&self, request: &SealedAws<'_>) -> Verdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let actual = Signature::HmacSha256(CtBytes::from_array([9; 32]));
        let expected = Signature::HmacSha256(CtBytes::from_array([9; 32]));
        let proof = actual.ct_verify(&expected).expect("equal signatures produce a proof");
        Verdict::authenticated(
            Identity::new("DANGEROUSACCESSKEY").expect("a valid identity"),
            AuthScheme::new(SigFamily::V4, SigLocation::Header, SigIdentity::LongTerm, request.expected_service()),
            proof,
        )
    }
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
#[tokio::test]
async fn a_valid_aws_request_reaches_the_explicit_replacement() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .with_dangerously_replaced_signature_verifier(
            AuthenticateEverything {
                calls: Arc::clone(&calls),
            },
            DangerAck::i_understand_this_disables_aws_sigv4(),
        )
        .register::<ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");

    let (status, _) = exchange(&service, support::signed(http::Method::GET, "/")).await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
#[tokio::test]
async fn c_sig_0375_the_floor_rejects_before_the_replacement_runs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .with_dangerously_replaced_signature_verifier(
            AuthenticateEverything {
                calls: Arc::clone(&calls),
            },
            DangerAck::i_understand_this_disables_aws_sigv4(),
        )
        .register::<ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");
    let request = support::signed(http::Method::GET, "/");
    let (mut parts, body) = request.into_parts();
    let authorization = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .expect("the signed fixture has an authorization header")
        .to_str()
        .expect("the fixture authorization is ASCII")
        .replace("20260102", "20200101");
    parts.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&authorization).expect("the adjusted authorization remains a header value"),
    );
    parts
        .headers
        .insert("x-amz-date", http::HeaderValue::from_static("20200101T000000Z"));

    let (status, response) = exchange(&service, http::Request::from_parts(parts, body)).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(response.contains("RequestTimeTooSkewed"), "{response}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
#[test]
fn the_security_posture_names_both_verifier_states() {
    let built_in = support::wired()
        .register::<ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");
    assert!(!built_in.security_posture().dangerously_replaced_aws_signature_verifier());
    assert!(
        built_in
            .security_posture()
            .to_string()
            .contains("AWS signature verifier: built in")
    );

    let replaced = support::wired()
        .with_dangerously_replaced_signature_verifier(
            AuthenticateEverything {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            DangerAck::i_understand_this_disables_aws_sigv4(),
        )
        .register::<ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");
    assert!(replaced.security_posture().dangerously_replaced_aws_signature_verifier());
    assert!(
        replaced
            .security_posture()
            .to_string()
            .contains("AWS signature verifier: dangerously replaced")
    );
}
