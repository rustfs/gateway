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

//! Session and disabled-credential refusal parity on unrouted POST forms (rustfs/gateway#1581).
//!
//! Responsible for: proving that `Presented::UnroutedForm` runs session and disabled admission
//! before answering, so unusable credentials match unknown keys (`InvalidAccessKeyId`) instead of
//! answering `SignatureDoesNotMatch` or authenticating, while live credentials with valid
//! signatures still authenticate for the legacy method refusal and proven expired sessions answer
//! `ExpiredToken`.
//! NOT responsible for: multipart framing or HTTP `405 MethodNotAllowed` rendering, which
//! `crates/gateway/tests/rustfs_selection.rs` and `store_fault_answer.rs` pin end to end.
//! Upstream: `super` and `super::super::SigV4Authenticator`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use http::Method;
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    Admission, AuthError, OperationFloor, PayloadMode, PostPolicyLimits, RawQuery, RegionSet, RequestNow, SecurityFloor,
    SigService, UnroutedPostPolicy, Verdict, WireView,
};
use sha2::{Digest as _, Sha256};

use super::super::{Authentication, Authenticator, SigV4Authenticator};
use crate::ext::credentials::{Credentials, SessionBinding, StaticCredentials};

const NOW: i64 = 1_440_938_160;
const STAMP: &str = "20150830T123600Z";
const KEY_BYTES: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const WRONG_BYTES: &[u8] = b"this-is-not-the-key-bytes-in-the-store--";
const ISSUED_TOKEN: &str = "FQoGZXIvYXdzEExampleSessionTokenValue";
const OTHER_TOKEN: &str = "FQoGZXIvYXdzEAnotherSessionTokenValue";

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
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

fn session(access_key: &str, expires_at: i64) -> Credentials {
    let binding = SessionBinding::new("sts.example.test", expires_at).expect("valid binding");
    Credentials::new(access_key, KEY_BYTES)
        .expect("valid access key")
        .with_session(ISSUED_TOKEN, binding)
        .expect("valid token")
}

fn authenticator() -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(
            StaticCredentials::new()
                .with(Credentials::new("AKIDLONGTERM", KEY_BYTES).expect("valid long-term"))
                .with(Credentials::new("AKIDDISABLED", KEY_BYTES).expect("valid disabled").disable())
                .with(session("AKIDLIVE", NOW + 3_600))
                .with(session("AKIDEXPIRED", NOW - 1))
                .with(session("AKIDDISABLEDSESSION", NOW - 1).disable()),
        ),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
}

async fn unrouted_verdict(access_key: &str, signing_bytes: &[u8], token_field: Option<(&str, &str)>) -> Verdict {
    let credential = format!("{access_key}/20150830/us-east-1/s3/aws4_request");
    let document = [
        r#"{"expiration":"2015-08-30T13:36:00Z","conditions":[{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":""#,
        credential.as_str(),
        r#""},{"x-amz-date":""#,
        STAMP,
        r#""}]}"#,
    ]
    .concat();
    let policy_b64 = base64(document.as_bytes());
    let mut key = hmac_sha256(&[b"AWS4".as_slice(), signing_bytes].concat(), b"20150830");
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = rustfs_gateway_sig::codec::encode_hex_lower(&hmac_sha256(&key, policy_b64.as_bytes()));
    let mut fields = vec![
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", credential.as_str()),
        ("x-amz-date", STAMP),
        ("x-amz-signature", signature.as_str()),
        ("policy", policy_b64.as_str()),
    ];
    if let Some((name, value)) = token_field {
        fields.push((name, value));
    }
    let unrouted = UnroutedPostPolicy::read(&fields, PostPolicyLimits::default())
        .expect("valid unrouted metadata")
        .expect("signed unrouted form");
    let headers = http::HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let operation = OperationFloor::builtin("PostObject", SigService::S3).allow_post_policy();
    let admitted = SecurityFloor::new()
        .admit(view, &operation, RequestNow::from_unix_seconds(NOW))
        .expect("form admitted by floor");
    let Admission::Sealed(sealed) = admitted else {
        panic!("expected sealed SigV4 form");
    };
    let host = RawHost::from_host_header(b"s3.example.test").expect("valid host");
    let payload = PayloadMode::Unsigned;
    let request =
        Authentication::new(&sealed, &Method::POST, "/bucket/obj", &host, &payload, Some(0)).with_unrouted_post_policy(&unrouted);
    let outcome = authenticator().authenticate(&request).await.expect("store answers");
    outcome.into_parts().0
}

/// Positive — a live long-term key with a valid signature still authenticates on an unrouted form
/// so `refused_post` preserves its legacy `405 MethodNotAllowed` refusal.
#[tokio::test]
async fn unrouted_form_live_long_term_key_authenticates() {
    let verdict = unrouted_verdict("AKIDLONGTERM", KEY_BYTES, None).await;
    assert!(verdict.is_authenticated(), "{verdict:?}");
}

/// Positive — a live temporary session carrying its issued `x-amz-security-token` form field
/// (in any ASCII case) with a valid signature authenticates on an unrouted form.
#[tokio::test]
async fn unrouted_form_live_session_key_with_issued_token_authenticates() {
    for field_name in ["x-amz-security-token", "X-Amz-Security-Token"] {
        let verdict = unrouted_verdict("AKIDLIVE", KEY_BYTES, Some((field_name, ISSUED_TOKEN))).await;
        assert!(verdict.is_authenticated(), "{field_name}: {verdict:?}");
    }
}

/// Positive — an expired session that proves possession with its valid signature and issued form
/// token answers `ExpiredToken`, matching routed POST forms and header/presigned paths.
#[tokio::test]
async fn unrouted_form_expired_session_with_issued_token_and_valid_signature_answers_expired_token() {
    let verdict = unrouted_verdict("AKIDEXPIRED", KEY_BYTES, Some(("x-amz-security-token", ISSUED_TOKEN))).await;
    assert_eq!(verdict.rejection(), Some(AuthError::ExpiredToken));
}

/// Negative — baseline control: an unknown key on an unrouted form answers `InvalidAccessKeyId`.
#[tokio::test]
async fn n_unrouted_form_unknown_key_answers_invalid_access_key_id() {
    for token in [None, Some(("x-amz-security-token", ISSUED_TOKEN))] {
        let verdict = unrouted_verdict("AKIDUNKNOWN", KEY_BYTES, token).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId));
    }
}

/// Negative — rustfs/gateway#1581: an expired session with a wrong signature answers
/// `InvalidAccessKeyId` (not `SignatureDoesNotMatch` and not `ExpiredToken`), whether the form
/// carries the issued token, another token, or no token.
#[tokio::test]
async fn n_unrouted_form_expired_session_with_wrong_signature_answers_invalid_access_key_id() {
    for token in [
        None,
        Some(("x-amz-security-token", ISSUED_TOKEN)),
        Some(("x-amz-security-token", OTHER_TOKEN)),
    ] {
        let verdict = unrouted_verdict("AKIDEXPIRED", WRONG_BYTES, token).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{token:?}");
    }
}

/// Negative — rustfs/gateway#1581: a disabled key answers `InvalidAccessKeyId` for both wrong and
/// valid signatures, with or without a token.
#[tokio::test]
async fn n_unrouted_form_disabled_key_with_wrong_or_valid_signature_answers_invalid_access_key_id() {
    for signing_bytes in [WRONG_BYTES, KEY_BYTES] {
        for token in [None, Some(("x-amz-security-token", ISSUED_TOKEN))] {
            let verdict = unrouted_verdict("AKIDDISABLED", signing_bytes, token).await;
            assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId));
        }
    }
}

/// Negative — a disabled expired session stays `InvalidAccessKeyId` even with a valid signature
/// and the issued token: disabled outranks expiry on unrouted forms too.
#[tokio::test]
async fn n_unrouted_form_disabled_expired_session_with_valid_signature_answers_invalid_access_key_id() {
    for signing_bytes in [WRONG_BYTES, KEY_BYTES] {
        let verdict = unrouted_verdict("AKIDDISABLEDSESSION", signing_bytes, Some(("x-amz-security-token", ISSUED_TOKEN))).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId));
    }
}

/// Negative — a live session credential presented without its form token answers
/// `InvalidAccessKeyId` whether its signature is wrong or valid.
#[tokio::test]
async fn n_unrouted_form_session_without_token_answers_invalid_access_key_id() {
    for signing_bytes in [WRONG_BYTES, KEY_BYTES] {
        let verdict = unrouted_verdict("AKIDLIVE", signing_bytes, None).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId));
    }
}

/// Negative — a live session credential presented with a different or empty form token answers
/// `InvalidAccessKeyId` whether its signature is wrong or valid.
#[tokio::test]
async fn n_unrouted_form_session_with_wrong_token_answers_invalid_access_key_id() {
    for signing_bytes in [WRONG_BYTES, KEY_BYTES] {
        for value in [OTHER_TOKEN, ""] {
            let verdict = unrouted_verdict("AKIDLIVE", signing_bytes, Some(("x-amz-security-token", value))).await;
            assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "value={value:?}");
        }
    }
}

/// Negative — an expired session with a valid signature but missing or wrong token answers
/// `InvalidAccessKeyId`, never `ExpiredToken`.
#[tokio::test]
async fn n_unrouted_form_expired_session_without_or_wrong_token_with_valid_signature_answers_invalid_access_key_id() {
    for token in [
        None,
        Some(("x-amz-security-token", OTHER_TOKEN)),
        Some(("x-amz-security-token", "")),
    ] {
        let verdict = unrouted_verdict("AKIDEXPIRED", KEY_BYTES, token).await;
        assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "{token:?}");
    }
}

/// Negative — a long-term key presented with a non-empty or empty form token answers
/// `InvalidAccessKeyId` whether its signature is wrong or valid.
#[tokio::test]
async fn n_unrouted_form_long_term_key_with_spurious_or_empty_token_answers_invalid_access_key_id() {
    for signing_bytes in [WRONG_BYTES, KEY_BYTES] {
        for value in [ISSUED_TOKEN, ""] {
            let verdict = unrouted_verdict("AKIDLONGTERM", signing_bytes, Some(("x-amz-security-token", value))).await;
            assert_eq!(verdict.rejection(), Some(AuthError::InvalidAccessKeyId), "value={value:?}");
        }
    }
}

/// Negative — control proving usable credentials with wrong signatures still answer
/// `SignatureDoesNotMatch` rather than collapsing every bad signature to `InvalidAccessKeyId`.
#[tokio::test]
async fn n_unrouted_form_live_key_with_wrong_signature_keeps_signature_does_not_match() {
    let long_term = unrouted_verdict("AKIDLONGTERM", WRONG_BYTES, None).await;
    assert_eq!(long_term.rejection(), Some(AuthError::SignatureDoesNotMatch));
    let session_live = unrouted_verdict("AKIDLIVE", WRONG_BYTES, Some(("x-amz-security-token", ISSUED_TOKEN))).await;
    assert_eq!(session_live.rejection(), Some(AuthError::SignatureDoesNotMatch));
}
