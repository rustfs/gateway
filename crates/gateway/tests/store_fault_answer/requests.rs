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

//! One correctly signed request per authentication form, for `store_fault_answer.rs`.
//!
//! Responsible for: building each form's request with a caller-chosen secret, the SigV4 POST
//! policy signature from an RFC 2104 HMAC written out here rather than from the crate under test.
//! NOT responsible for: sending requests or asserting anything.
//! Upstream: `rustfs-gateway`'s public signers, `crate::sts_body_signature::signed`. Downstream:
//! `super` and `super::edges`.

use bytes::Bytes;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway_sig::sig_v2::{SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway_sig::{RawQuery, percent_encode};
use sha2::{Digest as _, Sha256};

use super::{ACCESS_KEY, BOUNDARY, Form, SIGNED_AT_RFC1123};
use crate::support;

pub(super) fn request(form: Form, secret: &str) -> http::Request<Bytes> {
    match form {
        Form::V4Header => v4(secret, false),
        Form::V4Presigned => v4(secret, true),
        Form::V4Streaming => v4_streaming(secret),
        Form::V4Policy => v4_policy(secret, "/example-bucket"),
        Form::V4ObjectPath => v4_policy(secret, "/example-bucket/upload"),
        Form::V2Header => v2_header(secret),
        Form::V2Presigned => v2_presigned(secret),
        Form::V2Policy => v2_policy(secret, "/example-bucket"),
        Form::V2ObjectPath => v2_policy(secret, "/example-bucket/upload"),
        Form::StsBody => {
            let body = Bytes::from_static(b"sts-body");
            let mut request =
                crate::sts_body_signature::signed("/example-bucket/object", "sts", ACCESS_KEY, secret, &body, body.clone());
            request
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
            request
        }
    }
}

pub(super) fn v4_signer(secret: &str) -> (SigV4Signer, AmzDate) {
    let credentials = SigningCredentials::new(ACCESS_KEY, secret.as_bytes()).expect("signing credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    (SigV4Signer::new(credentials, scope), stamp)
}

pub(super) fn v4(secret: &str, presigned: bool) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let (mut signer, stamp) = v4_signer(secret);
    let method = http::Method::POST;
    // A presigned URL carries no body digest, so its canonical payload is `UNSIGNED-PAYLOAD`.
    let payload = if presigned {
        PayloadMode::Unsigned
    } else {
        PayloadMode::Empty
    };
    let signing = SigningRequest::new(&method, "/", "", &headers, &host, payload, stamp);
    let (uri, signed) = if presigned {
        let signed = signer.presign(&signing, 900).expect("a signable request");
        (format!("/?{}", signed.query()), signed)
    } else {
        let signed = signer
            .sign_headers(&signing.with_wire_content_length(0))
            .expect("a signable request");
        ("/".to_owned(), signed)
    };
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a valid request")
}

/// A `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` upload of one chunk and the terminal chunk.
pub(super) fn v4_streaming(secret: &str) -> http::Request<Bytes> {
    const OBJECT: &[u8] = b"streamed-object";
    let target = "/example-bucket/object";
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let (mut signer, stamp) = v4_signer(secret);
    // Per chunk: the hex size, `;chunk-signature=`, 64 hex digits and two CRLFs.
    let wire_length = format!("{:x}", OBJECT.len()).len() + 17 + 64 + 4 + OBJECT.len() + 1 + 17 + 64 + 4;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_length));
    let method = http::Method::PUT;
    let signing = SigningRequest::new(
        &method,
        target,
        "",
        &headers,
        &host,
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_decoded_content_length(OBJECT.len() as u64)
    .with_wire_content_length(wire_length as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut body = chain.encode_chunk(OBJECT);
    body.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(body.len(), wire_length, "the framing arithmetic above is the one the signer used");
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::from(body)).expect("a valid request")
}

pub(super) fn v2_header(secret: &str) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::DATE, http::HeaderValue::from_static(SIGNED_AT_RFC1123));
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &http::Method::POST, "/", &query, &headers, None);
    let authorization = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .authorization(&spec)
        .expect("a signable request");
    let mut builder = http::Request::builder().method(http::Method::POST).uri("/");
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    builder
        .header(http::header::AUTHORIZATION, authorization)
        .body(Bytes::new())
        .expect("a valid request")
}

pub(super) fn v2_presigned(secret: &str) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let expires = support::SIGNED_AT_UNIX_SECONDS + 900;
    let raw = format!("AWSAccessKeyId={ACCESS_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::POST, "/", &query, &headers, None);
    let signature = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .presigned_signature(&spec)
        .expect("a signable request");
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/?{raw}&Signature={}", percent_encode(signature.as_bytes())))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

pub(super) fn v4_policy(secret: &str, target: &str) -> http::Request<Bytes> {
    let credential = format!("{ACCESS_KEY}/20260102/us-east-1/s3/aws4_request");
    let policy = base64(&format!(
        r#"{{"expiration":"2026-01-02T04:04:05Z","conditions":[{{"bucket":"example-bucket"}},{{"key":"upload"}},{{"x-amz-algorithm":"AWS4-HMAC-SHA256"}},{{"x-amz-credential":"{credential}"}},{{"x-amz-date":"{}"}}]}}"#,
        support::SIGNED_AT_STAMP
    ));
    let signature = v4_policy_signature(secret.as_bytes(), &policy);
    form_request(
        target,
        &[
            ("key", "upload"),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", &credential),
            ("x-amz-date", support::SIGNED_AT_STAMP),
            ("policy", &policy),
            ("x-amz-signature", &signature),
        ],
    )
}

pub(super) fn v2_policy(secret: &str, target: &str) -> http::Request<Bytes> {
    let policy = base64(r#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"}]}"#);
    let signature = SigV2Signer::new(ACCESS_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .post_policy_signature(&policy);
    form_request(
        target,
        &[
            ("key", "upload"),
            ("AWSAccessKeyId", ACCESS_KEY),
            ("policy", &policy),
            ("signature", &signature),
        ],
    )
}

pub(super) fn form_request(target: &str, fields: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\n\
         Content-Type: application/octet-stream\r\n\r\nhello\r\n--{BOUNDARY}--\r\n"
    ));
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("http://host.invalid{target}"))
        .header(http::header::HOST, "host.invalid")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid request")
}

/// HMAC-SHA256 from RFC 2104, so the policy signature does not come from the crate under test.
pub(super) fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

pub(super) fn v4_policy_signature(secret: &[u8], policy: &str) -> String {
    let mut key = [b"AWS4".as_slice(), secret].concat();
    for step in ["20260102", "us-east-1", "s3", "aws4_request"] {
        key = hmac(&key, step.as_bytes()).to_vec();
    }
    hmac(&key, policy.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let bits = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                char::from(ALPHABET[((bits >> (18 - 6 * i)) & 0x3f) as usize])
            } else {
                '='
            });
        }
    }
    out
}
