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

//! Unit tests for query-parameter redaction and credential-assignment matching.
//!
//! Responsible for: verifying refusal and sanitization of SigV2 presigned query parameters,
//! SSE-C customer-key query parameters, and case-exact placeholder matching in
//! `has_credential_assignment` for STS presigned URLs.
//! Not responsible for: multipart form body parsing (`form.rs`) or on-disk corpus storage.
//! Upstream: `super` (`crate::redact`) and `crate::form`.
//! Downstream: Cargo's unit test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::{Finding, PLACEHOLDER, Reason, SENSITIVE_QUERY_PARAMS, Site, admit, sanitize, scan};
use crate::form::SENSITIVE_FORM_FIELDS;
use crate::schema::{CORPUS_SCHEMA_VERSION, Capture, Entry, Sut};

fn entry_with_target(target: &str) -> Entry {
    Entry {
        v: CORPUS_SCHEMA_VERSION,
        op: "GetObject".to_owned(),
        src: "client-matrix:boto3@1.42.96".to_owned(),
        recorded: "2026-09-02".to_owned(),
        capture: Capture::HeadFull,
        sut: Sut::GatewayFsReference,
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: vec![("host".to_owned(), "127.0.0.1:9000".to_owned())],
        chunks: None,
        resp: None,
        redacted: Vec::new(),
    }
}

/// Negative — SigV2 presigned query parameters (`AWSAccessKeyId`, `Signature`) carry live
/// credential material and must be refused in any casing, together or individually.
#[test]
fn n_sigv2_presigned_query_parameters_are_refused() {
    for (target, expected_param) in [
        ("/bucket/key?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1700000000", "awsaccesskeyid"),
        ("/bucket/key?awsaccesskeyid=AKIAIOSFODNN7EXAMPLE&Expires=1700000000", "awsaccesskeyid"),
        ("/bucket/key?Expires=1700000000&Signature=0RavWzkygo6QX9caELEqKi9kDbU%3D", "signature"),
        ("/bucket/key?Expires=1700000000&signature=0RavWzkygo6QX9caELEqKi9kDbU%3D", "signature"),
    ] {
        let entry = entry_with_target(target);
        let refusal = admit(&entry).expect_err(target);
        assert!(
            refusal.findings.contains(&Finding {
                site: Site::QueryParam(expected_param.to_owned()),
                reason: Reason::LiveCredentialField,
            }),
            "{target}: {refusal}"
        );
    }
}

/// Negative — SSE-C plaintext customer keys passed as query parameters must be refused in any
/// casing for both the target object and the copy source.
#[test]
fn n_sse_c_customer_key_query_parameters_are_refused() {
    let key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY%3D";
    for (param, canonical) in [
        ("X-Amz-Server-Side-Encryption-Customer-Key", "x-amz-server-side-encryption-customer-key"),
        ("x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key"),
        (
            "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key",
            "x-amz-copy-source-server-side-encryption-customer-key",
        ),
        (
            "x-amz-copy-source-server-side-encryption-customer-key",
            "x-amz-copy-source-server-side-encryption-customer-key",
        ),
    ] {
        let entry = entry_with_target(&format!("/bucket/key?{param}={key}"));
        let refusal = admit(&entry).expect_err(param);
        assert!(
            refusal.findings.contains(&Finding {
                site: Site::QueryParam(canonical.to_owned()),
                reason: Reason::LiveCredentialField,
            }),
            "{param}: {refusal}"
        );
    }
}

/// Negative — a lowercase `__redacted__` spelling is not `PLACEHOLDER` and must still be refused
/// as a credential assignment, as must any live assignment value.
#[test]
fn n_lowercase_placeholder_in_credential_assignment_is_still_refused() {
    for target in [
        "/bucket/key?X-Amz-Security-Token=__redacted__",
        "/bucket/key?session_token=__redacted__",
        "/bucket/key?session_token=live-token-value",
    ] {
        let entry = entry_with_target(target);
        let findings = scan(&entry);
        assert!(
            findings.iter().any(|finding| finding.reason == Reason::CredentialAssignment),
            "{target}: {findings:?}"
        );
    }
}

/// Negative — sensitive parameter tables must stay strictly sorted without duplicates.
#[test]
fn n_sensitive_query_and_form_lists_stay_strictly_sorted() {
    for window in SENSITIVE_QUERY_PARAMS.windows(2) {
        assert!(
            window[0] < window[1],
            "SENSITIVE_QUERY_PARAMS out of order: {:?} >= {:?}",
            window[0],
            window[1]
        );
    }
    for window in SENSITIVE_FORM_FIELDS.windows(2) {
        assert!(
            window[0] < window[1],
            "SENSITIVE_FORM_FIELDS out of order: {:?} >= {:?}",
            window[0],
            window[1]
        );
    }
}

/// Positive — sanitizing a SigV4 STS presigned URL carrying `X-Amz-Security-Token` rewrites the
/// credential parameters to `PLACEHOLDER` and the resulting entry passes `admit`.
#[test]
fn sanitize_admits_sts_presigned_url_with_security_token() {
    let mut entry = entry_with_target(
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260902%2Fus-east-1%2Fs3%2Faws4_request\
         &X-Amz-Date=20260902T000000Z&X-Amz-Expires=900\
         &X-Amz-Security-Token=FwoGZXIvYXdzEBcaDLONGSESSIONTOKENVALUE%3D%3D\
         &X-Amz-SignedHeaders=host\
         &X-Amz-Signature=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
    );
    assert!(admit(&entry).is_err(), "live STS presigned URL must be refused before sanitize");
    let touched = sanitize(&mut entry);
    assert_eq!(touched, ["x-amz-credential", "x-amz-security-token", "x-amz-signature"]);
    assert!(entry.target.contains(&format!("X-Amz-Security-Token={PLACEHOLDER}")));
    admit(&entry).expect("a sanitized STS presigned URL must pass admit");
}

/// Positive — sanitizing SigV2 presigned and SSE-C query parameters rewrites only the sensitive
/// fields and passes `admit`.
#[test]
fn sanitize_redacts_sigv2_and_sse_c_query_params_and_admits() {
    let mut entry = entry_with_target(
        "/bucket/key?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1700000000\
         &Signature=0RavWzkygo6QX9caELEqKi9kDbU%3D\
         &X-Amz-Server-Side-Encryption-Customer-Key=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY%3D\
         &X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU%3D\
         &partNumber=1",
    );
    let touched = sanitize(&mut entry);
    assert_eq!(
        touched,
        [
            "awsaccesskeyid",
            "signature",
            "x-amz-copy-source-server-side-encryption-customer-key",
            "x-amz-server-side-encryption-customer-key",
        ]
    );
    assert!(entry.target.contains("Expires=1700000000"));
    assert!(entry.target.contains("partNumber=1"));
    admit(&entry).expect("sanitized SigV2 and SSE-C query params must pass admit");
}

/// Negative and positive — live `x-amz-s3session-token` in a header or presigned query is refused
/// by `admit`, rewritten to `PLACEHOLDER` by `sanitize`, and then admitted cleanly.
#[test]
fn sanitize_redacts_s3_express_session_token_header_and_query_and_admits() {
    let mut entry = entry_with_target(
        "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260902%2Fus-east-1%2Fs3express%2Faws4_request\
         &X-Amz-Date=20260902T000000Z&X-Amz-Expires=300\
         &X-Amz-S3session-Token=AQoDYXdzS3EXPRESSLIVEVALUE%3D%3D\
         &X-Amz-SignedHeaders=host\
         &X-Amz-Signature=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
    );
    entry
        .headers
        .push(("x-amz-s3session-token".to_owned(), "AQoDYXdzS3EXPRESSHEADERLIVE".to_owned()));
    assert!(admit(&entry).is_err(), "live s3session token must be refused before sanitize");
    let touched = sanitize(&mut entry);
    assert_eq!(touched, ["x-amz-credential", "x-amz-s3session-token", "x-amz-signature"]);
    assert!(entry.target.contains(&format!("X-Amz-S3session-Token={PLACEHOLDER}")));
    assert!(
        entry
            .headers
            .iter()
            .any(|(name, value)| name == "x-amz-s3session-token" && value == PLACEHOLDER)
    );
    admit(&entry).expect("sanitized S3 Express session token entry must pass admit");
}
