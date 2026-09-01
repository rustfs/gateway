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

//! What an assembled service does with a SigV2 request, end to end.
//!
//! Responsible for: P2-06's wiring evidence — that a correctly signed SigV2 request authenticates
//! through the real pipeline, that every way of getting it wrong is a refusal rather than a
//! downgrade, and that the [`SigV2Policy`] switch moves in both directions.
//! NOT responsible for: the string-to-sign itself, which is `crates/sig/tests/sig_v2.rs`. A case
//! here is about a request that travelled the whole service.
//! Upstream: `rustfs-gateway`, `rustfs-gateway-sig`. Downstream: nothing.
//!
//! # The one assertion this file exists for
//!
//! `example:Ping` is **anonymously reachable**. That is deliberate: it means every negative case
//! below distinguishes "refused" from "degraded to anonymous", because a request that silently
//! lost its credential would be answered `200` by this very operation. A presented credential that
//! cannot be verified must never become an unauthenticated one, and on an operation that refuses
//! anonymous access the two outcomes are indistinguishable from the status code.
//!
//! Negative cases outnumber positive ones.

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::{
    Authentication, AuthenticationOutcome, Authenticator, BoxFuture, ClockSkewAck, S3Service, SecurityFloor, Unavailable, Verdict,
};
use rustfs_gateway_sig::sig_v2::{SigV2Mode, SigV2Policy, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway_sig::{RawQuery, percent_encode};
use support::{Ping, exchange, wired};

/// [`support::SIGNED_AT_UNIX_SECONDS`] in the spelling SigV2's `Date` header uses.
const SIGNED_AT_RFC1123: &str = "Fri, 02 Jan 2026 03:04:05 GMT";
/// The same instant with the numeric zero offset AWS's own SigV2 example carries.
const SIGNED_AT_NUMERIC: &str = "Fri, 02 Jan 2026 03:04:05 +0000";
/// The fixture credential, which is the one `support::wired` installs.
const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
/// Its secret.
const SECRET_ACCESS_KEY: &[u8] = b"secret";

// ── fixtures ───────────────────────────────────────────────────────────────────────────────────

fn service_with(floor: SecurityFloor, reached: &Arc<AtomicUsize>) -> S3Service {
    wired()
        .security_floor(floor)
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(reached)))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly")
}

fn header_map(extra: &[(&str, &str)]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        let name: http::HeaderName = name.parse().expect("a header name");
        map.append(name, http::HeaderValue::from_str(value).expect("a header value"));
    }
    map
}

/// One correctly SigV2-signed `POST /`, with whatever extra headers the case wants signed.
fn signed_v2(extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let map = header_map(extra);
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &query, &map, None);
    let signer = SigV2Signer::new(ACCESS_KEY_ID, SECRET_ACCESS_KEY).expect("a valid access key id");
    let authorization = signer.authorization(&spec).expect("a signable request");

    let mut builder = http::Request::builder().method(http::Method::POST).uri("/");
    for (name, value) in &map {
        builder = builder.header(name, value);
    }
    builder
        .header("authorization", authorization)
        .body(Bytes::new())
        .expect("a valid request")
}

/// The same, with the `Date` header a plain SigV2 client sends.
fn dated_v2() -> http::Request<Bytes> {
    signed_v2(&[("date", SIGNED_AT_RFC1123)])
}

/// One correctly SigV2-presigned `POST /`.
fn presigned_v2(expires_at: u64) -> http::Request<Bytes> {
    let map = header_map(&[]);
    let raw = format!("AWSAccessKeyId={ACCESS_KEY_ID}&Expires={expires_at}");
    let query = RawQuery::new(&raw);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::POST, "/", &query, &map, None);
    let signer = SigV2Signer::new(ACCESS_KEY_ID, SECRET_ACCESS_KEY).expect("a valid access key id");
    let rendered = signer.presigned_signature(&spec).expect("a signable request");
    let escaped = percent_encode(rendered.as_bytes());

    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/?{raw}&Signature={escaped}"))
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

/// Replaces the `Authorization` value of an already-signed request.
fn with_authorization(request: http::Request<Bytes>, value: &str) -> http::Request<Bytes> {
    let (mut parts, body) = request.into_parts();
    parts
        .headers
        .insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(value).expect("a header value"));
    http::Request::from_parts(parts, body)
}

/// An authenticator written before SigV2 existed: it implements the one required method and does
/// **not** override the SigV2 entry point.
///
/// This is the shape the refusing default exists for. A default that authenticated, or that
/// produced an anonymous verdict, would silently turn every such deployment into one that accepts
/// unverified SigV2 requests.
struct SigV4Only;

impl Authenticator for SigV4Only {
    fn authenticate<'a>(&'a self, _request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        Box::pin(async {
            Ok(AuthenticationOutcome::ordinary(Verdict::reject(
                rustfs_gateway_sig::AuthError::SignatureDoesNotMatch,
            )))
        })
    }
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — c-sig-0557: a correctly signed SigV2 header request reaches the handler.
#[tokio::test]
async fn c_sig_0557_a_correctly_signed_sigv2_request_reaches_the_handler() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let (status, body) = exchange(&service, dated_v2()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Positive — c-sig-0558: the numeric zero offset AWS's own example carries also authenticates.
#[tokio::test]
async fn c_sig_0558_the_numeric_zero_offset_date_also_authenticates() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let request = signed_v2(&[("date", SIGNED_AT_NUMERIC)]);
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Positive — c-sig-0559: a client sending `x-amz-date` and no `Date` authenticates, which is the
/// empty-`{Date}`-line rule proven over a served request rather than over a string.
#[tokio::test]
async fn c_sig_0559_an_x_amz_date_client_authenticates_with_an_empty_date_line() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let request = signed_v2(&[("x-amz-date", support::SIGNED_AT_STAMP)]);
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Positive — c-sig-0560: presigned SigV2 authenticates once a deployment opts in, so the policy
/// switch is not a control stuck on "refuse".
#[tokio::test]
async fn c_sig_0560_presigned_sigv2_authenticates_when_the_deployment_opts_in() {
    let reached = Arc::new(AtomicUsize::new(0));
    let floor = SecurityFloor::new().enable_sigv2_presigned_compatibility();
    let service = service_with(floor, &reached);
    let expires_at = u64::try_from(support::SIGNED_AT_UNIX_SECONDS).expect("a post-epoch fixture") + 900;
    let (status, body) = exchange(&service, presigned_v2(expires_at)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — c-sig-0570: **the assertion this file exists for.** A SigV2 signature that does not
/// match is `SignatureDoesNotMatch`, and the handler is not reached — on an operation that would
/// have answered `200` to the same request with no credential at all.
#[tokio::test]
async fn c_sig_0570_a_wrong_sigv2_signature_never_degrades_to_anonymous() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let forged = SigV2Signer::new(ACCESS_KEY_ID, b"not-the-secret").expect("a valid access key id");
    let map = header_map(&[("date", SIGNED_AT_RFC1123)]);
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &query, &map, None);
    let authorization = forged.authorization(&spec).expect("a signable request");

    let (status, body) = exchange(&service, with_authorization(dated_v2(), &authorization)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    // `InvalidAccessKeyId` and not `SignatureDoesNotMatch`: a wrong signature and an unknown key
    // get the same bytes, so the pair cannot be used to confirm that a key exists. That is
    // `render::from_auth`'s rule and it now covers SigV2 as well — see c-sig-0579, which asserts
    // the unknown key produces this identical document.
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a forged SigV2 signature reached the handler");
}

/// Negative — c-sig-0571: an `Authorization` header this crate cannot parse is refused, not
/// treated as if nothing had been presented.
#[tokio::test]
async fn c_sig_0571_an_unparsable_sigv2_authorization_is_refused_not_anonymous() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let request = with_authorization(dated_v2(), "AWS  AKIDEXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a malformed credential reached the handler");
}

/// Negative — c-sig-0572: an `x-amz-*` header is inside the SigV2 string-to-sign, so changing one
/// after signing is refused.
#[tokio::test]
async fn c_sig_0572_a_tampered_amz_header_is_refused() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let signed = signed_v2(&[("date", SIGNED_AT_RFC1123), ("x-amz-meta-note", "signed")]);
    let (mut parts, body) = signed.into_parts();
    parts.headers.insert(
        http::HeaderName::from_static("x-amz-meta-note"),
        http::HeaderValue::from_static("tampered"),
    );
    let (status, rendered) = exchange(&service, http::Request::from_parts(parts, body)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{rendered}");
    assert!(rendered.contains("<Code>InvalidAccessKeyId</Code>"), "{rendered}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0573: H1 is wired for SigV2, so a `Date` outside the window is refused before
/// the signature is ever compared.
#[tokio::test]
async fn c_sig_0573_a_skewed_sigv2_date_is_refused() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let request = signed_v2(&[("date", "Fri, 02 Jan 2026 02:44:05 GMT")]);
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>RequestTimeTooSkewed</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0574: a SigV2 request carrying no timestamp at all is refused rather than
/// judged against the server's own clock.
#[tokio::test]
async fn c_sig_0574_a_sigv2_request_without_a_timestamp_is_refused() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let (status, body) = exchange(&service, signed_v2(&[])).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0575: the default policy refuses a correctly signed SigV2 presigned URL. The
/// signature is valid; the location is not permitted.
#[tokio::test]
async fn c_sig_0575_the_default_policy_refuses_a_valid_sigv2_presigned_url() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let expires_at = u64::try_from(support::SIGNED_AT_UNIX_SECONDS).expect("a post-epoch fixture") + 900;
    let (status, body) = exchange(&service, presigned_v2(expires_at)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a presigned SigV2 URL reached the handler");
}

/// Negative — c-sig-0576: `SigV2Policy::Disabled` refuses header authentication too, and the same
/// request authenticates under the default — so the switch is proven in both directions.
#[tokio::test]
async fn c_sig_0576_the_disabled_policy_refuses_header_authentication() {
    let reached = Arc::new(AtomicUsize::new(0));
    let disabled = SecurityFloor::new().with_sigv2_policy(SigV2Policy::Disabled);
    let service = service_with(disabled, &reached);
    let (status, body) = exchange(&service, dated_v2()).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);

    let permitted = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &permitted);
    let (status, body) = exchange(&service, dated_v2()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(permitted.load(Ordering::SeqCst), 1);
}

/// Negative — c-sig-0577: an expired SigV2 presigned URL is refused even with the compatibility
/// switch on. `Expires` is an absolute instant, so "in the past" is the whole rule.
#[tokio::test]
async fn c_sig_0577_an_elapsed_sigv2_presigned_url_is_refused() {
    let reached = Arc::new(AtomicUsize::new(0));
    let floor = SecurityFloor::new().enable_sigv2_presigned_compatibility();
    let service = service_with(floor, &reached);
    let expires_at = u64::try_from(support::SIGNED_AT_UNIX_SECONDS).expect("a post-epoch fixture") - 1;
    let (status, body) = exchange(&service, presigned_v2(expires_at)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    // `RequestExpired` renders as `AccessDenied`, which is what S3 answers: confirming that a URL
    // *used to* work is a fact worth withholding from whoever is holding it.
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0578: SigV2 has no streaming form, so a SigV2 request declaring a framed
/// payload is refused rather than having its chunk framing passed through to the handler.
#[tokio::test]
async fn c_sig_0578_a_sigv2_request_declaring_a_framed_payload_is_refused() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let request = signed_v2(&[
        ("date", SIGNED_AT_RFC1123),
        ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
    ]);
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED, "{body}");
    // The message matters as much as the status: before P2-06's wiring every SigV2 request
    // answered `501` with "the signing algorithm is recognised but not implemented", so a case
    // asserting the status alone would have passed against a service that had not implemented
    // SigV2 at all.
    assert!(body.contains("SigV2 has no streaming payload form"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0579: an unknown access key presented over SigV2 is refused with the same
/// credential rejection an unknown SigV4 key gets, and never reaches the handler.
#[tokio::test]
async fn c_sig_0579_an_unknown_sigv2_access_key_is_refused() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = service_with(SecurityFloor::new(), &reached);
    let map = header_map(&[("date", SIGNED_AT_RFC1123)]);
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &query, &map, None);
    let stranger = SigV2Signer::new("AKIASTRANGER00000000", SECRET_ACCESS_KEY).expect("a valid access key id");
    let authorization = stranger.authorization(&spec).expect("a signable request");

    let (status, body) = exchange(&service, with_authorization(dated_v2(), &authorization)).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Negative — c-sig-0581: an authenticator that does not override the SigV2 entry point refuses
/// the request rather than letting it through.
///
/// The trait's default is the whole safety argument for adding a method to a trait deployments
/// already implement: an implementation written before SigV2 existed keeps compiling and answers
/// `501`. This case is what stops that default from being quietly widened — a default that
/// authenticated would make every such deployment accept unverified SigV2.
#[tokio::test]
async fn c_sig_0581_an_authenticator_without_a_sigv2_override_refuses() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = rustfs_gateway::ServiceBuilder::new()
        .authenticator(SigV4Only)
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&reached)))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, dated_v2()).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED, "{body}");
    assert!(body.contains("SigV2 is recognised and not implemented"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}
