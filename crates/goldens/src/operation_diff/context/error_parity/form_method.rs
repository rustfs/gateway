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

//! Object-path multipart refusal parity (rustfs/gateway#1184).
//!
//! Responsible for: metadata and signature ordering before the RustFS profile's 405, with no
//! handler call, for SigV4 and SigV2 forms, and the legacy policy grammar and algorithm binding
//! the SigV4 metadata check reads (rustfs/gateway#1185).
//! NOT responsible for: upload storage or file consumption.
//! Upstream: the two pinned oracles and the assembled gateway. Downstream: no runtime code.

use http::Method;
use rustfs_gateway_sig::RequestNow;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::super::{ACCESS_KEY, ContextRequest, PATH_HOST, SECRET_KEY, amz_date};
use super::{Scenario, both};

const CONTENT_TYPE: &str = "multipart/form-data; boundary=form";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const METHOD_MESSAGE: &str = "The specified method is not allowed against this resource.";

struct Form {
    fields: Vec<(&'static str, String)>,
}

impl Form {
    fn unsigned() -> Self {
        Self {
            fields: vec![("key", "a.txt".into())],
        }
    }

    fn signed(expiration: &str, key_condition: &str) -> Self {
        let date = amz_date(RequestNow::capture().unix_seconds());
        Self::signed_at(ACCESS_KEY, &date, expiration, key_condition)
    }

    fn signed_at(access_key: &str, date: &str, expiration: &str, key_condition: &str) -> Self {
        Self::signed_document(access_key, date, |date, credential| {
            json!({
                "expiration": expiration,
                "conditions": [
                    {"x-amz-date": date}, {"x-amz-credential": credential},
                    {"x-amz-algorithm": ALGORITHM}, {"key": key_condition}, {"bucket": "photos"}
                ]
            })
        })
    }

    /// A SigV4 form signed now over the policy `document` builds from its date and credential.
    fn signed_policy(document: impl FnOnce(&str, &str) -> serde_json::Value) -> Self {
        let date = amz_date(RequestNow::capture().unix_seconds());
        Self::signed_document(ACCESS_KEY, &date, document)
    }

    fn signed_document(access_key: &str, date: &str, document: impl FnOnce(&str, &str) -> serde_json::Value) -> Self {
        let credential = format!("{access_key}/{}/us-east-1/s3/aws4_request", &date[..8]);
        let policy = base64(document(date, &credential).to_string().as_bytes());
        let mut key = hmac(format!("AWS4{SECRET_KEY}").as_bytes(), &date.as_bytes()[..8]);
        for part in [b"us-east-1".as_slice(), b"s3", b"aws4_request"] {
            key = hmac(&key, part);
        }
        let signature = hex::encode(hmac(&key, policy.as_bytes()));
        Self {
            fields: vec![
                ("key", "a.txt".into()),
                ("x-amz-algorithm", ALGORITHM.into()),
                ("x-amz-credential", credential),
                ("x-amz-date", date.into()),
                ("policy", policy),
                ("x-amz-signature", signature),
            ],
        }
    }

    /// A SigV2 form: `AWSAccessKeyId`, a policy, and its signature with `secret`.
    fn sigv2(secret: &str) -> Self {
        Self::sigv2_over(
            base64(
                json!({
                    "expiration": "2099-01-01T00:00:00Z",
                    "conditions": [{"bucket": "photos"}, ["starts-with", "$key", ""]]
                })
                .to_string()
                .as_bytes(),
            ),
            secret,
        )
    }

    /// A SigV2 form over `policy`, already encoded, signed with `secret`.
    fn sigv2_over(policy: String, secret: &str) -> Self {
        let signature = rustfs_gateway_sig::SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
            .expect("a signer")
            .post_policy_signature(&policy);
        Self {
            fields: vec![
                ("key", "a.txt".into()),
                ("AWSAccessKeyId", ACCESS_KEY.into()),
                ("policy", policy),
                ("signature", signature),
            ],
        }
    }

    fn with(mut self, name: &'static str, value: &str) -> Self {
        self.fields.retain(|(field, _)| *field != name);
        self.fields.push((name, value.into()));
        self
    }

    fn without(mut self, name: &str) -> Self {
        self.fields.retain(|(field, _)| *field != name);
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut body = String::new();
        for (name, value) in &self.fields {
            body.push_str(&format!("--form\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        body.push_str(
            "--form\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nfile bytes\r\n--form--\r\n",
        );
        body.into_bytes()
    }
}

fn hmac(key: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(bytes);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let word =
            (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(char::from(DIGITS[((word >> 18) & 63) as usize]));
        encoded.push(char::from(DIGITS[((word >> 12) & 63) as usize]));
        encoded.push(if chunk.len() > 1 {
            char::from(DIGITS[((word >> 6) & 63) as usize])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(DIGITS[(word & 63) as usize])
        } else {
            '='
        });
    }
    encoded
}

fn request(body: &[u8], query: &str, content_type: &str) -> ContextRequest {
    ContextRequest::new(Method::POST, PATH_HOST, "/photos/a.txt", query, body).header("content-type", content_type.as_bytes())
}

#[test]
fn n_an_object_form_refuses_before_dispatch_with_legacy_headers() {
    for form in [
        Form::unsigned(),
        Form::signed("2099-01-01T00:00:00Z", "a.txt"),
        Form::signed("2000-01-01T00:00:00Z", "a.txt"),
        Form::signed("2099-01-01T00:00:00Z", "another.txt"),
    ] {
        for query in ["", "unknown=1", "versionId=v", "acl"] {
            let scenario = Scenario::new(request(&form.bytes(), query, CONTENT_TYPE))
                .selecting_as_legacy_rustfs()
                .rustfs_identified();
            let pair = both(&scenario).expect("both stacks answer");
            assert_eq!((pair.gateway.status, pair.oracle.status), (405, 405), "{pair:#?}");
            assert_eq!(
                (pair.gateway.code(), pair.oracle.code()),
                (Some("MethodNotAllowed"), Some("MethodNotAllowed")),
                "{pair:#?}"
            );
            assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
            assert_eq!(pair.gateway.message(), Some(METHOD_MESSAGE), "{pair:#?}");
            for name in ["content-type", "x-request-id", "x-amz-request-id"] {
                assert_eq!(pair.gateway.header(name), pair.oracle.header(name), "{name}: {pair:#?}");
            }
            for name in ["allow", "etag", "x-amz-version-id", "x-amz-id-2"] {
                assert_eq!((pair.gateway.header(name), pair.oracle.header(name)), (None, None), "{name}: {pair:#?}");
            }
        }
    }
}

#[test]
fn a_outer_query_signatures_reach_a_registered_operation() {
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for forged in [false, true] {
        let mut request = ContextRequest::new(Method::GET, PATH_HOST, "/photos/a.txt", "", b"").signed("us-east-1");
        if forged {
            request = request.forged();
        }
        let scenario = Scenario::new(request).selecting_as_legacy_rustfs().presigned(300);
        let pair = both(&scenario).expect("both stacks answer");
        observed.push((
            pair.gateway.status,
            pair.oracle.status,
            pair.gateway.code().map(str::to_owned),
            pair.oracle.code().map(str::to_owned),
            pair.gateway.reached,
            pair.oracle.reached,
        ));
        let code = forged.then(|| "SignatureDoesNotMatch".to_owned());
        let status = if forged { 403 } else { 200 };
        expected.push((status, status, code.clone(), code, !forged, !forged));
    }
    assert_eq!(observed, expected, "the same query signer authenticates a registered operation");
}

#[test]
fn n_outer_signatures_do_not_replace_the_form_verdict() {
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for presigned in [false, true] {
        for forged_outer in [false, true] {
            for (form, kind, status, code) in [
                (Form::unsigned(), "unsigned", 405, "MethodNotAllowed"),
                (Form::signed("2099-01-01T00:00:00Z", "a.txt"), "valid", 405, "MethodNotAllowed"),
                (
                    Form::signed("2099-01-01T00:00:00Z", "a.txt").with("x-amz-signature", &"0".repeat(64)),
                    "forged",
                    403,
                    "SignatureDoesNotMatch",
                ),
                (
                    Form::signed("2099-01-01T00:00:00Z", "a.txt").without("policy"),
                    "missing-policy",
                    400,
                    "InvalidRequest",
                ),
            ] {
                let mut outer = request(&form.bytes(), "", CONTENT_TYPE).signed("us-east-1");
                if forged_outer {
                    outer = outer.forged();
                }
                let mut scenario = Scenario::new(outer).selecting_as_legacy_rustfs();
                if presigned {
                    scenario = scenario.presigned(300);
                }
                let pair = both(&scenario).expect("both stacks answer");
                observed.push((
                    presigned,
                    forged_outer,
                    kind,
                    pair.gateway.status,
                    pair.gateway.code().map(str::to_owned),
                    pair.oracle.status,
                    pair.oracle.code().map(str::to_owned),
                ));
                expected.push((
                    presigned,
                    forged_outer,
                    kind,
                    status,
                    Some(code.to_owned()),
                    status,
                    Some(code.to_owned()),
                ));
            }
        }
    }
    assert_eq!(observed, expected, "outer credentials do not replace form credentials");
}

#[test]
fn n_invalid_form_metadata_and_signatures_precede_the_method_refusal() {
    let valid = || Form::signed("2099-01-01T00:00:00Z", "a.txt");
    for (form, status, code) in [
        (valid().with("x-amz-signature", &"0".repeat(64)), 403, "SignatureDoesNotMatch"),
        (valid().with("x-amz-signature", "not-hex"), 403, "SignatureDoesNotMatch"),
        (valid().with("x-amz-signature", ""), 403, "SignatureDoesNotMatch"),
        (
            Form::signed("2000-01-01T00:00:00Z", "a.txt").with("x-amz-signature", &"0".repeat(64)),
            403,
            "SignatureDoesNotMatch",
        ),
        (
            Form::signed("2099-01-01T00:00:00Z", "another.txt").with("x-amz-signature", &"0".repeat(64)),
            403,
            "SignatureDoesNotMatch",
        ),
        (valid().without("x-amz-algorithm"), 400, "InvalidRequest"),
        (valid().without("x-amz-credential"), 400, "InvalidRequest"),
        (valid().without("x-amz-date"), 400, "InvalidRequest"),
        (valid().without("policy"), 400, "InvalidRequest"),
        (valid().with("x-amz-date", "not-a-date"), 400, "InvalidRequest"),
        (valid().with("x-amz-credential", "not-a-scope"), 400, "InvalidRequest"),
        (valid().with("x-amz-date", "20260102T030405Z"), 400, "InvalidPolicyDocument"),
        (
            valid().with("x-amz-credential", "AKIDUNKNOWN/20260102/us-east-1/s3/aws4_request"),
            400,
            "InvalidPolicyDocument",
        ),
        (valid().with("policy", "not-base64"), 400, "InvalidRequest"),
        (valid().with("policy", "e30="), 400, "InvalidPolicyDocument"),
        (Form::signed("not-an-expiration", "a.txt"), 400, "InvalidPolicyDocument"),
        (valid().with("x-amz-algorithm", "unsupported"), 501, "NotImplemented"),
        (
            Form::signed_at(ACCESS_KEY, "20000101T000000Z", "2099-01-01T00:00:00Z", "a.txt"),
            403,
            "RequestTimeTooSkewed",
        ),
        (
            Form::signed_at(ACCESS_KEY, "20990101T000000Z", "2099-01-01T00:00:00Z", "a.txt"),
            403,
            "RequestTimeTooSkewed",
        ),
    ] {
        let pair = both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs())
            .expect("both stacks answer");
        assert_eq!((pair.gateway.status, pair.oracle.status), (status, status), "{code}: {pair:#?}");
        assert_eq!((pair.gateway.code(), pair.oracle.code()), (Some(code), Some(code)), "{pair:#?}");
        assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
    }
    for (body, content_type, code) in [
        (b"--form--\r\n".as_slice(), CONTENT_TYPE, "MalformedPOSTRequest"),
        (
            b"--form\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\na.txt".as_slice(),
            CONTENT_TYPE,
            "MalformedPOSTRequest",
        ),
        (Form::unsigned().bytes().as_slice(), "multipart/form-data", "InvalidRequest"),
    ] {
        let pair =
            both(&Scenario::new(request(body, "", content_type)).selecting_as_legacy_rustfs()).expect("both stacks answer");
        assert_eq!((pair.gateway.status, pair.oracle.status), (400, 400), "{pair:#?}");
        assert_eq!((pair.gateway.code(), pair.oracle.code()), (Some(code), Some(code)), "{pair:#?}");
    }
}

#[test]
fn n_an_unknown_form_key_keeps_the_credential_callback_refusal() {
    let date = amz_date(RequestNow::capture().unix_seconds());
    let form = Form::signed_at("AKIDUNKNOWN", &date, "2099-01-01T00:00:00Z", "a.txt");
    let pair =
        both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs()).expect("both stacks answer");
    assert_eq!((pair.gateway.status, pair.oracle.status), (403, 403), "{pair:#?}");
    // The fixture's oracle callback answers NotSignedUp; RustFS IAM and the facade's existing
    // provider contract answer InvalidAccessKeyId. Neither reaches the method check or a handler.
    assert_eq!(pair.gateway.code(), Some("InvalidAccessKeyId"), "{pair:#?}");
    assert_eq!(pair.oracle.code(), Some("NotSignedUp"), "{pair:#?}");
    assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
}

#[test]
fn n_signature_presence_chooses_form_metadata_preparation() {
    let fields = [
        "policy",
        "x-amz-algorithm",
        "x-amz-credential",
        "x-amz-date",
        "x-amz-signature",
    ];
    let mut answers = Vec::new();
    let mut expected = Vec::new();
    for mask in 0..32 {
        let mut form = Form::signed("2099-01-01T00:00:00Z", "a.txt");
        for (bit, field) in fields.iter().enumerate() {
            if mask & (1 << bit) == 0 {
                form = form.without(field);
            }
        }
        let pair = both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs())
            .expect("both stacks answer");
        answers.push((
            pair.gateway.status,
            pair.oracle.status,
            pair.gateway.code().map(str::to_owned),
            pair.oracle.code().map(str::to_owned),
            pair.gateway.reached,
            pair.oracle.reached,
        ));
        let (status, code) = if mask & 16 == 0 || mask == 31 {
            (405, "MethodNotAllowed")
        } else {
            (400, "InvalidRequest")
        };
        expected.push((status, status, Some(code.to_owned()), Some(code.to_owned()), false, false));
    }
    assert_eq!(answers, expected);
    let form = Form::signed("2099-01-01T00:00:00Z", "a.txt")
        .without("x-amz-signature")
        .with("policy", "not-base64");
    let pair =
        both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs()).expect("both stacks answer");
    assert_eq!((pair.gateway.status, pair.oracle.status), (405, 405), "{pair:#?}");
    assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
}

#[test]
fn n_an_unsupported_form_signature_keeps_the_existing_floor_refusal() {
    let form = Form::unsigned().with("Signature", "");
    let pair =
        both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs()).expect("both stacks answer");
    assert_eq!((pair.gateway.status, pair.oracle.status), (403, 403), "{pair:#?}");
    assert_eq!(
        (pair.gateway.code(), pair.oracle.code()),
        (Some("AccessDenied"), Some("AccessDenied")),
        "{pair:#?}"
    );
    assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
}

#[test]
fn n_form_tokens_do_not_move_checks_ahead_of_the_method_refusal() {
    let mut answers = Vec::new();
    let mut expected = Vec::new();
    for token in ["", "extra-token"] {
        for (signature, status, code) in [
            (None, 405, "MethodNotAllowed"),
            (Some("0".repeat(64)), 403, "SignatureDoesNotMatch"),
        ] {
            let form = Form::signed("2099-01-01T00:00:00Z", "a.txt").with("x-amz-security-token", token);
            let form = match signature {
                Some(signature) => form.with("x-amz-signature", &signature),
                None => form,
            };
            let pair = both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs())
                .expect("both stacks answer");
            answers.push((
                pair.gateway.status,
                pair.oracle.status,
                pair.gateway.code().map(str::to_owned),
                pair.oracle.code().map(str::to_owned),
                pair.gateway.reached,
                pair.oracle.reached,
            ));
            expected.push((status, status, Some(code.to_owned()), Some(code.to_owned()), false, false));
        }
    }
    assert_eq!(answers, expected);
}

#[test]
fn n_upload_policy_checks_are_kept_on_the_bucket_path() {
    for form in [
        Form::signed("2000-01-01T00:00:00Z", "a.txt"),
        Form::signed("2099-01-01T00:00:00Z", "another.txt"),
        Form::signed("2099-01-01T00:00:00Z", "a.txt").with("x-amz-security-token", ""),
        Form::signed("2099-01-01T00:00:00Z", "a.txt").with("x-amz-security-token", "extra-token"),
    ] {
        let body = form.bytes();
        let request =
            ContextRequest::new(Method::POST, PATH_HOST, "/photos", "", &body).header("content-type", CONTENT_TYPE.as_bytes());
        let pair = both(&Scenario::new(request).selecting_as_legacy_rustfs()).expect("both stacks answer");
        assert!(!pair.gateway.reached, "{pair:#?}");
        assert_eq!(pair.gateway.status, 403, "{pair:#?}");
    }
}

#[test]
fn a_valid_bucket_form_can_reach_the_handler() {
    let body = Form::signed("2099-01-01T00:00:00Z", "a.txt").bytes();
    let request =
        ContextRequest::new(Method::POST, PATH_HOST, "/photos", "", &body).header("content-type", CONTENT_TYPE.as_bytes());
    let pair = both(&Scenario::new(request).selecting_as_legacy_rustfs()).expect("both stacks answer");
    assert!(pair.gateway.reached, "{pair:#?}");
}

/// Positive and negative — a SigV2 form on an object path is verified as legacy RustFS verifies one
/// (`v2_check_post_signature`), then refused `405` with nothing reached; a forged signature, an
/// unreadable policy and a missing access key or policy are refused first, with legacy RustFS's
/// code (rustfs/gateway#1184, #1185). The SigV2 check reads no condition and no expiry, so a policy
/// that names another key, has expired, is past the default 32 KiB policy ceiling or is not JSON
/// still reaches the method refusal.
#[test]
fn n_a_sigv2_object_form_is_verified_before_the_method_refusal() {
    let document = |expiration: &str, key: &str| {
        base64(
            json!({"expiration": expiration, "conditions": [{"bucket": "photos"}, {"key": key}]})
                .to_string()
                .as_bytes(),
        )
    };
    let padded = base64(
        json!({"expiration": "2099-01-01T00:00:00Z", "conditions": [{"bucket": "photos"}, ["starts-with", "$key", ""],
            ["starts-with", "$x-ignore-pad", "p".repeat(40 * 1024)]]})
        .to_string()
        .as_bytes(),
    );
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for (kind, form, status, code) in [
        ("valid", Form::sigv2(SECRET_KEY), 405, "MethodNotAllowed"),
        ("forged", Form::sigv2("not-the-secret"), 403, "SignatureDoesNotMatch"),
        ("unreadable", Form::sigv2(SECRET_KEY).with("policy", "not-base64"), 400, "InvalidRequest"),
        (
            "empty-signature",
            Form::sigv2(SECRET_KEY).with("signature", ""),
            403,
            "SignatureDoesNotMatch",
        ),
        (
            "another key",
            Form::sigv2_over(document("2099-01-01T00:00:00Z", "a.txt"), SECRET_KEY).with("key", "elsewhere.txt"),
            405,
            "MethodNotAllowed",
        ),
        (
            "expired",
            Form::sigv2_over(document("2000-01-01T00:00:00Z", "a.txt"), SECRET_KEY),
            405,
            "MethodNotAllowed",
        ),
        ("past 32 KiB", Form::sigv2_over(padded, SECRET_KEY), 405, "MethodNotAllowed"),
        ("not JSON", Form::sigv2_over(base64(b"not json"), SECRET_KEY), 405, "MethodNotAllowed"),
        ("no access key", Form::sigv2(SECRET_KEY).without("AWSAccessKeyId"), 400, "InvalidRequest"),
        ("no policy", Form::sigv2(SECRET_KEY).without("policy"), 400, "InvalidRequest"),
    ] {
        let scenario = Scenario::new(request(&form.bytes(), "", CONTENT_TYPE))
            .selecting_as_legacy_rustfs()
            .with_sigv2();
        let pair = both(&scenario).expect("both stacks answer");
        observed.push((
            kind,
            pair.gateway.status,
            pair.gateway.code().map(str::to_owned),
            pair.gateway.reached,
            pair.oracle.status,
            pair.oracle.code().map(str::to_owned),
            pair.oracle.reached,
        ));
        expected.push((kind, status, Some(code.to_owned()), false, status, Some(code.to_owned()), false));
    }
    assert_eq!(observed, expected);
}

/// Positive and negative — on the bucket path a SigV2 form whose signature verifies reaches
/// `PostObject` on both stacks, and one whose signature is empty or is not twenty base64 bytes is
/// looked up and refused `403 SignatureDoesNotMatch` with nothing reached, as legacy RustFS's
/// `v2_check_post_signature` refuses it (rustfs/gateway#1185). The fixture backend does not read
/// the file, so the answer after a reached handler is not compared, as for a SigV4 form above.
#[test]
fn n_a_sigv2_bucket_form_with_an_unreadable_signature_is_a_mismatch() {
    let thirty_two = base64(&[7; 32]);
    let nineteen = base64(&[7; 19]);
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for (kind, signature) in [
        ("valid", None),
        ("empty", Some("")),
        ("not-base64", Some("!!!!")),
        ("nineteen-bytes", Some(nineteen.as_str())),
        ("thirty-two-bytes", Some(thirty_two.as_str())),
    ] {
        let form = match signature {
            Some(signature) => Form::sigv2(SECRET_KEY).with("signature", signature),
            None => Form::sigv2(SECRET_KEY),
        };
        let body = form.bytes();
        let request =
            ContextRequest::new(Method::POST, PATH_HOST, "/photos", "", &body).header("content-type", CONTENT_TYPE.as_bytes());
        let pair = both(&Scenario::new(request).selecting_as_legacy_rustfs().with_sigv2()).expect("both stacks answer");
        if signature.is_none() {
            observed.push((kind, None, None, pair.gateway.reached, None, None, pair.oracle.reached));
            expected.push((kind, None, None, true, None, None, true));
            continue;
        }
        observed.push((
            kind,
            Some(pair.gateway.status),
            pair.gateway.code().map(str::to_owned),
            pair.gateway.reached,
            Some(pair.oracle.status),
            pair.oracle.code().map(str::to_owned),
            pair.oracle.reached,
        ));
        let code = Some("SignatureDoesNotMatch".to_owned());
        expected.push((kind, Some(403), code.clone(), false, Some(403), code, false));
    }
    assert_eq!(observed, expected);
}

/// Negative — a SigV2 form naming an access key nobody issued is refused `403` on both stacks and
/// reaches nothing; the oracle's callback answers `NotSignedUp` where RustFS IAM and the facade's
/// provider contract answer `InvalidAccessKeyId`, as for a SigV4 form.
#[test]
fn n_a_sigv2_object_form_with_an_unknown_key_is_refused() {
    let form = Form::sigv2(SECRET_KEY).with("AWSAccessKeyId", "AKIDUNKNOWN");
    let scenario = Scenario::new(request(&form.bytes(), "", CONTENT_TYPE))
        .selecting_as_legacy_rustfs()
        .with_sigv2();
    let pair = both(&scenario).expect("both stacks answer");
    assert_eq!((pair.gateway.status, pair.oracle.status), (403, 403), "{pair:#?}");
    assert_eq!(pair.gateway.code(), Some("InvalidAccessKeyId"), "{pair:#?}");
    assert_eq!(pair.oracle.code(), Some("NotSignedUp"), "{pair:#?}");
    assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
}

/// Negative — a SigV4 form's policy must bind its algorithm as it binds its date and credential:
/// an absent or different `x-amz-algorithm` condition is `400 InvalidPolicyDocument` on both
/// stacks, before the signature and the method check.
#[test]
fn n_an_object_form_policy_must_bind_its_algorithm() {
    for algorithm in [None, Some("AWS4-HMAC-SHA512"), Some("aws4-hmac-sha256")] {
        let form = Form::signed_policy(|date, credential| {
            let mut conditions = vec![json!({"x-amz-date": date}), json!({"x-amz-credential": credential})];
            if let Some(algorithm) = algorithm {
                conditions.push(json!({"x-amz-algorithm": algorithm}));
            }
            json!({"expiration": "2099-01-01T00:00:00Z", "conditions": conditions})
        });
        let pair = both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs())
            .expect("both stacks answer");
        assert_eq!((pair.gateway.status, pair.oracle.status), (400, 400), "{algorithm:?}: {pair:#?}");
        assert_eq!(
            (pair.gateway.code(), pair.oracle.code()),
            (Some("InvalidPolicyDocument"), Some("InvalidPolicyDocument")),
            "{algorithm:?}: {pair:#?}"
        );
        assert_eq!(pair.gateway.message(), pair.oracle.message(), "{algorithm:?}: {pair:#?}");
        assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
    }
}

/// Negative — the first exact condition naming a credential field decides, as legacy RustFS's
/// `eq_condition_value` reads it: a wrong first one is refused `400 InvalidPolicyDocument` on both
/// stacks although a later one names the right value.
#[test]
fn n_the_first_condition_naming_a_credential_field_decides() {
    for field in ["x-amz-algorithm", "x-amz-date", "x-amz-credential"] {
        let form = Form::signed_policy(|date, credential| {
            let right = |name: &str| match name {
                "x-amz-algorithm" => ALGORITHM.to_owned(),
                "x-amz-date" => date.to_owned(),
                _ => credential.to_owned(),
            };
            let mut conditions = vec![json!({field: "wrong"})];
            for name in ["x-amz-date", "x-amz-credential", "x-amz-algorithm"] {
                conditions.push(json!({name: right(name)}));
            }
            json!({"expiration": "2099-01-01T00:00:00Z", "conditions": conditions})
        });
        let pair = both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs())
            .expect("both stacks answer");
        assert_eq!((pair.gateway.status, pair.oracle.status), (400, 400), "{field}: {pair:#?}");
        assert_eq!(
            (pair.gateway.code(), pair.oracle.code()),
            (Some("InvalidPolicyDocument"), Some("InvalidPolicyDocument")),
            "{field}: {pair:#?}"
        );
        assert_eq!(pair.gateway.message(), pair.oracle.message(), "{field}: {pair:#?}");
        assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{field}: {pair:#?}");
    }
}

/// Positive — a SigV4 form's policy is read with legacy RustFS's grammar: operators in any ASCII
/// case and an expiration spelled with a space bind its credentials, and the form is refused `405`
/// on both stacks; an expired one too, because expiry belongs to the upload it never reaches.
#[test]
fn an_object_form_policy_is_read_with_legacy_rustfs_grammar() {
    for (kind, expiration, operator) in [
        ("mixed-case operators", "2099-01-01T00:00:00Z", "EQ"),
        // A control: the strict grammar already reads `eq`.
        ("lowercase operators", "2099-01-01T00:00:00Z", "eq"),
        ("space-separated expiration", "2099-01-01 00:00:00Z", "eq"),
        ("expired", "2000-01-01T00:00:00Z", "Eq"),
    ] {
        let form = Form::signed_policy(|date, credential| {
            json!({
                "expiration": expiration,
                "conditions": [
                    [operator, "$x-amz-date", date],
                    [operator, "$x-amz-credential", credential],
                    [operator, "$x-amz-algorithm", ALGORITHM]
                ]
            })
        });
        let pair = both(&Scenario::new(request(&form.bytes(), "", CONTENT_TYPE)).selecting_as_legacy_rustfs())
            .expect("both stacks answer");
        assert_eq!((pair.gateway.status, pair.oracle.status), (405, 405), "{kind}: {pair:#?}");
        assert_eq!(
            (pair.gateway.code(), pair.oracle.code()),
            (Some("MethodNotAllowed"), Some("MethodNotAllowed")),
            "{kind}: {pair:#?}"
        );
        assert_eq!((pair.gateway.reached, pair.oracle.reached), (false, false), "{pair:#?}");
    }
}

/// Positive and negative — the retain-until date of a bucket form is read with legacy RustFS's
/// grammar on both stacks (rustfs/gateway#1167): every spelling either reaches `PostObject` on both,
/// or is refused alike before it, `400 InvalidArgument` with the same message.
#[test]
fn a_retain_until_date_is_read_as_legacy_rustfs_reads_it() {
    let mut differences = Vec::new();
    for date in [
        "2030-01-01T00:00:00Z",
        "2030-01-01T00:00:00.123Z",
        "2030-01-01T00:00:00.123456789Z",
        "2030-01-01T00:00:00.1234567891Z",
        "2030-01-01T00:00:00+08:00",
        "2030-01-01T00:00:00-00:00",
        "2030-01-01t00:00:00z",
        "2030-01-01 00:00:00Z",
        "2030-01-01T00:00:00",
        "2030-01-01T00:00Z",
        "2030-01-01T24:00:00Z",
        "2030-02-30T00:00:00Z",
        "2030-12-31T23:59:60Z",
        "2030-01-01T00:00:00.Z",
        "+2030-01-01T00:00:00Z",
        "2030-1-01T00:00:00Z",
        "20300101T000000Z",
        "Tue, 01 Jan 2030 00:00:00 GMT",
        "2030-01-01_00:00:00Z",
        "2030-06-15T12:00:60Z",
        "2031-01-01T07:59:60+08:00",
        "2030-01-01T00:00:00+24:00",
        "2030-01-01T00:00:00+08:60",
        "2029-02-29T00:00:00Z",
        "2028-02-29T00:00:00Z",
        "2030-01-01T00:00:00Zx",
        "2030-12-31T23:59:60+01:00",
        "2030-01-01\u{e9}00:00:00Z",
        "2030-01-01T00:00:00+0800",
        "2030-01-01T00:60:00Z",
        "2030-00-01T00:00:00Z",
        "2030-13-01T00:00:00Z",
        "tomorrow",
        "",
    ] {
        let form = Form::signed_policy(|signed_at, credential| {
            json!({
                "expiration": "2099-01-01T00:00:00Z",
                "conditions": [
                    {"x-amz-date": signed_at}, {"x-amz-credential": credential}, {"x-amz-algorithm": ALGORITHM},
                    {"bucket": "photos"}, ["starts-with", "$key", ""],
                    ["starts-with", "$x-amz-object-lock-retain-until-date", ""]
                ]
            })
        })
        .with("x-amz-object-lock-retain-until-date", date);
        let body = form.bytes();
        let request =
            ContextRequest::new(Method::POST, PATH_HOST, "/photos", "", &body).header("content-type", CONTENT_TYPE.as_bytes());
        let pair = both(&Scenario::new(request).selecting_as_legacy_rustfs()).expect("both stacks answer");
        let outcome = |reply: &super::Reply| {
            if reply.reached {
                None
            } else {
                Some((reply.status, reply.code().map(str::to_owned), reply.message().map(str::to_owned)))
            }
        };
        let (gateway, oracle) = (outcome(&pair.gateway), outcome(&pair.oracle));
        if gateway != oracle {
            differences.push((date, gateway, oracle));
        }
    }
    assert!(differences.is_empty(), "(date, gateway, legacy): {differences:#?}");
}
