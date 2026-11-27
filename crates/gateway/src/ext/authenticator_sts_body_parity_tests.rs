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

//! Unusable-key refusal and body-read parity on STS and S3 Vectors body-digest paths (#1581).
//!
//! Responsible for: proving disabled, token-missing, token-mismatched, and spurious-token
//! credentials skip pre-auth body reads and answer `InvalidAccessKeyId`, that unknown/disabled
//! keys still reach signed-header verification parity without polling the body, that expired
//! sessions with oversized bodies stay `InvalidAccessKeyId`, and that proven expired sessions
//! over bounded bodies still answer `ExpiredToken`.
//! NOT responsible for: S3 Vectors query-parameter or body-ceiling regressions (`tests`).
//! Upstream: `super` and `super::super::SigV4Authenticator`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    Admission, AuthError, OperationFloor, PayloadMode, RawQuery, RequestNow, SecurityFloor, SigService, WireView,
};
use sha2::{Digest as _, Sha256};

use super::super::{Authentication, Authenticator, RegionSet, SigV4Authenticator};
use crate::ext::credentials::{Credentials, SessionBinding, StaticCredentials};
use crate::gate::{BodyCeilings, BodyTimeouts, StsBodyReader};
use crate::render::S3Error;

const NOW: i64 = 1_440_938_160;
const STAMP: &str = "20150830T123600Z";
const STS_TOKEN: &str = "FQoGZXIvYXdzEStsBodySessionTokenValue";
const STS_OTHER_TOKEN: &str = "FQoGZXIvYXdzEStsBodyOtherTokenValue";

struct CountingBody(Mutex<usize>);

impl StsBodyReader for CountingBody {
    fn digest(&self, _timeouts: BodyTimeouts, _ceilings: Option<BodyCeilings>) -> BoxFuture<'_, Result<[u8; 32], S3Error>> {
        *self.0.lock().expect("uncontended") += 1;
        Box::pin(async { Ok(Sha256::digest(b"Action=AssumeRole").into()) })
    }
}

struct FailingBody(Mutex<usize>);

impl StsBodyReader for FailingBody {
    fn digest(&self, _timeouts: BodyTimeouts, _ceilings: Option<BodyCeilings>) -> BoxFuture<'_, Result<[u8; 32], S3Error>> {
        *self.0.lock().expect("uncontended") += 1;
        Box::pin(async {
            Err(crate::render::from_handler(
                rustfs_gateway_core::HandlerError::new(
                    rustfs_gateway_types::ErrorCode::INVALID_REQUEST,
                    "failed to read STS request body: length limit exceeded",
                ),
                rustfs_gateway_core::ResponseKind::Other,
                crate::close::ConnectionIntent::Close,
            ))
        })
    }
}

fn vectors_service() -> SigService {
    SigService::parse("s3vectors").expect("S3 Vectors has a typed signing service")
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    block
        .get_mut(..key.len())
        .expect("fixture key fits HMAC block")
        .copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(value);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sts_parity_authenticator() -> SigV4Authenticator {
    let live_binding = SessionBinding::new("sts.example.test", NOW + 3_600).expect("binding");
    let expired_binding = SessionBinding::new("sts.example.test", NOW - 1).expect("binding");
    let store = StaticCredentials::new()
        .with(Credentials::new("AKIDLONGTERM", b"secret").expect("valid"))
        .with(Credentials::new("AKIDDISABLED", b"secret").expect("valid").disable())
        .with(
            Credentials::new("AKIDLIVE", b"secret")
                .expect("valid")
                .with_session(STS_TOKEN, live_binding)
                .expect("valid"),
        )
        .with(
            Credentials::new("AKIDEXPIRED", b"secret")
                .expect("valid")
                .with_session(STS_TOKEN, expired_binding.clone())
                .expect("valid"),
        )
        .with(
            Credentials::new("AKIDDISABLEDSESSION", b"secret")
                .expect("valid")
                .with_session(STS_TOKEN, expired_binding)
                .expect("valid")
                .disable(),
        );
    SigV4Authenticator::new(Arc::new(store), RegionSet::new(["us-east-1"]).expect("non-empty"))
        .accept_legacy_rustfs_signing_services()
}

fn body_digest_head(
    service: &str,
    access_key: &str,
    key_bytes: &[u8],
    signed_body: &[u8],
    token: Option<&str>,
    extra_unsigned_header: Option<(&str, &str)>,
) -> HeaderMap {
    let scope = format!("20150830/us-east-1/{service}/aws4_request");
    let digest = hex(&Sha256::digest(signed_body));
    let signed_headers = if token.is_some() {
        "host;x-amz-date;x-amz-security-token"
    } else {
        "host;x-amz-date"
    };
    let token_line = token
        .map(|value| format!("x-amz-security-token:{value}\n"))
        .unwrap_or_default();
    let canonical = format!("POST\n/Action\n\nhost:s3.example.com\nx-amz-date:{STAMP}\n{token_line}\n{signed_headers}\n{digest}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{STAMP}\n{scope}\n{}", hex(&Sha256::digest(canonical)));
    let mut key = hmac_sha256(&[b"AWS4".as_slice(), key_bytes].concat(), b"20150830");
    for value in ["us-east-1", service, "aws4_request"] {
        key = hmac_sha256(&key, value.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("s3.example.com"));
    headers.insert("x-amz-date", HeaderValue::from_static(STAMP));
    if let Some(value) = token {
        headers.insert("x-amz-security-token", HeaderValue::from_str(value).expect("valid token header"));
    }
    if let Some((name, value)) = extra_unsigned_header {
        headers.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ))
        .expect("a header signature"),
    );
    headers
}

#[allow(clippy::too_many_arguments)]
async fn run_probe(
    expected_service: SigService,
    presented_service: &str,
    access_key: &str,
    key_bytes: &[u8],
    signed_body: &[u8],
    token: Option<&str>,
    reader: &dyn StsBodyReader,
    extra_unsigned_header: Option<(&str, &str)>,
) -> (rustfs_gateway_sig::Verdict, bool, bool) {
    let headers = body_digest_head(presented_service, access_key, key_bytes, signed_body, token, extra_unsigned_header);
    let floor = OperationFloor::builtin("example:BodyOp", expected_service);
    let admitted = SecurityFloor::new()
        .admit(WireView::new(&headers, RawQuery::new("")), &floor, RequestNow::from_unix_seconds(NOW))
        .expect("admitted");
    let Admission::Sealed(sealed) = admitted else { panic!("expected sealed") };
    let host = RawHost::from_host_header(b"s3.example.com").expect("valid host");
    let payload = PayloadMode::Empty;
    let request = Authentication::new(&sealed, &Method::POST, "/Action", &host, &payload, Some(17)).with_sts_body_reader(
        Some(reader),
        "example:BodyOp",
        &crate::ServiceConfig::new(8192),
    );
    let outcome = sts_parity_authenticator()
        .authenticate(&request)
        .await
        .expect("store answers");
    let signed_body_flag = request.signs_its_body();
    let (_, _, body_refusal) = request.into_published();
    (outcome.into_parts().0, signed_body_flag, body_refusal.is_some())
}

fn body_digest_modes() -> [(SigService, &'static str); 2] {
    [(SigService::S3, "sts"), (vectors_service(), "s3vectors")]
}

/// Positive — a live session with its issued token and a valid body signature authenticates and
/// marks the body signed on both legacy `sts` and `s3vectors` body-digest paths.
#[tokio::test]
async fn sts_and_s3vectors_live_session_with_issued_token_authenticates_and_signs_body() {
    for (expected, presented) in body_digest_modes() {
        let body = CountingBody(Mutex::new(0));
        let (verdict, signed, body_refusal) = run_probe(
            expected,
            presented,
            "AKIDLIVE",
            b"secret",
            b"Action=AssumeRole",
            Some(STS_TOKEN),
            &body,
            None,
        )
        .await;
        assert!(verdict.is_authenticated(), "{presented}: {verdict:?}");
        assert!(signed, "{presented}: body should be marked signed");
        assert!(!body_refusal, "{presented}");
        assert_eq!(*body.0.lock().expect("uncontended"), 1, "{presented}");
    }
}

/// Positive — an expired session presenting its issued token and a valid body signature answers
/// `ExpiredToken` on both legacy `sts` and `s3vectors` body-digest paths so SDKs refresh.
#[tokio::test]
async fn sts_and_s3vectors_expired_session_with_issued_token_and_valid_signature_answers_expired_token() {
    for (expected, presented) in body_digest_modes() {
        let body = CountingBody(Mutex::new(0));
        let (verdict, signed, body_refusal) = run_probe(
            expected,
            presented,
            "AKIDEXPIRED",
            b"secret",
            b"Action=AssumeRole",
            Some(STS_TOKEN),
            &body,
            None,
        )
        .await;
        assert_eq!(verdict.rejection(), Some(AuthError::ExpiredToken), "{presented}");
        assert!(!signed, "{presented}");
        assert!(!body_refusal, "{presented}");
        assert_eq!(*body.0.lock().expect("uncontended"), 1, "{presented}");
    }
}

/// Negative — rustfs/gateway#1581: a disabled key (long-term or expired session) never reads the
/// body and answers `InvalidAccessKeyId`, even with a valid signature or an oversized body.
#[tokio::test]
async fn n_sts_and_s3vectors_disabled_key_skips_body_read_and_answers_invalid_access_key_id() {
    for (expected, presented) in body_digest_modes() {
        for (key_id, token) in [("AKIDDISABLED", None), ("AKIDDISABLEDSESSION", Some(STS_TOKEN))] {
            for key_bytes in [b"wrong".as_slice(), b"secret".as_slice()] {
                let body = FailingBody(Mutex::new(0));
                let (verdict, signed, body_refusal) =
                    run_probe(expected, presented, key_id, key_bytes, b"Action=AssumeRole", token, &body, None).await;
                assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{presented} {key_id}");
                assert!(!signed, "{presented} {key_id}");
                assert!(!body_refusal, "{presented} {key_id}: must not leak body refusal");
                assert_eq!(*body.0.lock().expect("uncontended"), 0, "{presented} {key_id}: must not poll body");
            }
        }
    }
}

/// Negative — rustfs/gateway#1581: a session key presented without its token or with another token
/// never reads the body and answers `InvalidAccessKeyId`.
#[tokio::test]
async fn n_sts_and_s3vectors_session_without_or_wrong_token_skips_body_read_and_answers_invalid_access_key_id() {
    for (expected, presented) in body_digest_modes() {
        for key_id in ["AKIDLIVE", "AKIDEXPIRED"] {
            for token in [None, Some(STS_OTHER_TOKEN)] {
                for key_bytes in [b"wrong".as_slice(), b"secret".as_slice()] {
                    let body = FailingBody(Mutex::new(0));
                    let (verdict, signed, body_refusal) =
                        run_probe(expected, presented, key_id, key_bytes, b"Action=AssumeRole", token, &body, None).await;
                    assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{presented} {key_id} {token:?}");
                    assert!(!signed);
                    assert!(!body_refusal);
                    assert_eq!(*body.0.lock().expect("uncontended"), 0, "{presented} {key_id} {token:?}");
                }
            }
        }
    }
}

/// Negative — rustfs/gateway#1581: a long-term key presented with a spurious session token never
/// reads the body and answers `InvalidAccessKeyId`.
#[tokio::test]
async fn n_sts_and_s3vectors_long_term_key_with_spurious_token_skips_body_read_and_answers_invalid_access_key_id() {
    for (expected, presented) in body_digest_modes() {
        for key_bytes in [b"wrong".as_slice(), b"secret".as_slice()] {
            let body = FailingBody(Mutex::new(0));
            let (verdict, signed, body_refusal) = run_probe(
                expected,
                presented,
                "AKIDLONGTERM",
                key_bytes,
                b"Action=AssumeRole",
                Some(STS_TOKEN),
                &body,
                None,
            )
            .await;
            assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{presented}");
            assert!(!signed);
            assert!(!body_refusal);
            assert_eq!(*body.0.lock().expect("uncontended"), 0, "{presented}");
        }
    }
}

/// Negative — rustfs/gateway#1581: an expired session with its issued token and a wrong signature
/// answers `InvalidAccessKeyId` rather than `ExpiredToken` or `SignatureDoesNotMatch`.
#[tokio::test]
async fn n_sts_and_s3vectors_expired_session_with_issued_token_and_wrong_signature_answers_invalid_access_key_id() {
    for (expected, presented) in body_digest_modes() {
        let body = CountingBody(Mutex::new(0));
        let (verdict, signed, body_refusal) = run_probe(
            expected,
            presented,
            "AKIDEXPIRED",
            b"wrong",
            b"Action=AssumeRole",
            Some(STS_TOKEN),
            &body,
            None,
        )
        .await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{presented}");
        assert!(!signed);
        assert!(!body_refusal);
    }
}

/// Negative — rustfs/gateway#1581: an expired session with its issued token whose body cannot be
/// read (e.g. past the body ceiling) answers `InvalidAccessKeyId` — never a body-length refusal
/// and never `ExpiredToken` even when the signature covers the empty payload.
#[tokio::test]
async fn n_sts_and_s3vectors_expired_session_with_oversized_body_answers_invalid_access_key_id() {
    for (expected, presented) in body_digest_modes() {
        for (key_bytes, signed_body) in [
            (b"wrong".as_slice(), b"Action=AssumeRole".as_slice()),
            (b"secret".as_slice(), b"".as_slice()),
        ] {
            let body = FailingBody(Mutex::new(0));
            let (verdict, signed, body_refusal) =
                run_probe(expected, presented, "AKIDEXPIRED", key_bytes, signed_body, Some(STS_TOKEN), &body, None).await;
            assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{presented}");
            assert!(!signed);
            assert!(!body_refusal, "{presented}: body refusal must not replace uniform refusal");
        }
    }
}

/// Negative — behavioural parity-order proof (no wall clock): on both legacy `sts` and `s3vectors`
/// body-digest paths, unknown keys and disabled keys skip reading the body yet still enter the
/// signed-header / HMAC verification stage instead of returning early right after lookup.
#[tokio::test]
async fn n_sts_and_s3vectors_unknown_and_disabled_keys_reach_signed_header_parity_without_reading_body() {
    for (expected, presented) in body_digest_modes() {
        for key_id in ["AKIDUNKNOWN", "AKIDDISABLED"] {
            let body = FailingBody(Mutex::new(0));
            let (verdict, signed, body_refusal) = run_probe(
                expected,
                presented,
                key_id,
                b"secret",
                b"Action=AssumeRole",
                None,
                &body,
                Some(("x-amz-meta-unsigned", "extra")),
            )
            .await;
            assert_eq!(
                verdict.rejection(),
                Some(AuthError::SignatureDoesNotMatch),
                "{presented} {key_id}: must reach signed-header verification rather than short-circuiting in sts_payload"
            );
            assert!(!signed);
            assert!(!body_refusal);
            assert_eq!(*body.0.lock().expect("uncontended"), 0, "{presented} {key_id}: must not read body");
        }
    }
}
