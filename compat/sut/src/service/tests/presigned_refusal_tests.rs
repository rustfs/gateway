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

//! Presigned URLs recognised, and refused, by the RustFS-profile launcher as legacy RustFS
//! recognises and refuses them (rustfs/gateway#1130).
//!
//! Responsible for: pinning, through the served assembly, that a query string carrying presigned
//! parameters but no `X-Amz-Signature` is an anonymous request — served where the bucket admits
//! anonymous reads, `403 AccessDenied` otherwise, storing nothing; and that a presigned URL legacy
//! RustFS refuses before its credential lookup is answered with legacy RustFS's status, code and
//! sentence — one that does not read, another algorithm, an instant that does not exist — storing
//! nothing. (The clock rules are pinned by the unit suite, which holds the clock still.)
//! NOT responsible for: the credential scope's date and region (`scope_refusal_tests.rs`), the
//! headers a presigned URL must sign (`signed_header_reading_tests.rs`), or presigned uploads'
//! payload declarations (`presigned_payload_tests.rs`).
//! Upstream: the parent module's two-identity assembly, [`super::hand_signer`] and
//! [`super::policy_tests`]. Downstream: nothing.

use super::hand_signer::HandSigned;
use super::policy_tests::{policed, put_policy};
use super::*;

const PUBLIC_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::policed/*"}]}"#;
const PUBLIC_READ_MD5: &str = "+hGiD7fW/eONTk+z7PZOGA==";

/// Legacy RustFS's sentence for a presigned URL that does not read.
const UNREADABLE: &str = "The authorization query parameters that you provided are not valid.";

/// `request`, its query rewritten by `change` over its `(name, value)` pairs.
fn rewritten(request: http::Request<Bytes>, change: impl FnOnce(&mut Vec<(String, String)>)) -> http::Request<Bytes> {
    let (mut parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let mut pairs: Vec<(String, String)> = parts
        .uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name.to_owned(), value.to_owned())
        })
        .collect();
    change(&mut pairs);
    let query = pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    parts.uri = format!("{path}?{query}").parse().expect("a valid target");
    http::Request::from_parts(parts, body)
}

fn set(pairs: &mut [(String, String)], name: &str, value: &str) {
    for pair in pairs.iter_mut() {
        if pair.0 == name {
            pair.1 = value.to_owned();
        }
    }
}

fn remove(pairs: &mut Vec<(String, String)>, name: &str) {
    pairs.retain(|(existing, _)| existing != name);
}

fn refused(answer: &WireResponse, status: u16, code: &str, sentence: &str) {
    let body = body_of(answer);
    assert_eq!(answer.status(), status, "{sentence}: {body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{sentence}: {body}");
    assert!(body.contains(&format!("<Message>{sentence}</Message>")), "{sentence}: {body}");
}

async fn public_read(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    policed(&service).await;
    let written = put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await;
    assert!(written.status().is_success(), "{}", body_of(&written));
    let private = exchange(&service, as_main(http::Method::PUT, "/private", Bytes::new())).await;
    assert_eq!(private.status(), 200, "{}", body_of(&private));
    let stored = exchange(&service, as_main(http::Method::PUT, "/private/k", Bytes::from_static(b"private"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// Positive — presigned parameters without `X-Amz-Signature` are an anonymous request: a public
/// object is served, as legacy RustFS serves it, however many of the other parameters it carries.
#[tokio::test]
async fn a_url_without_its_signature_is_anonymous_and_reads_a_public_object() {
    let root = TestRoot::new();
    let service = public_read(&root).await;
    let url = || HandSigned::new(http::Method::GET, "/policed/open", Bytes::new()).presigned();
    for request in [
        rewritten(url(), |pairs| remove(pairs, "X-Amz-Signature")),
        rewritten(url(), |pairs| pairs.retain(|(name, _)| name == "X-Amz-Algorithm")),
    ] {
        let answer = exchange(&service, request).await;
        assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "open"));
    }
}

/// Negative — the same anonymous request is `403 AccessDenied` on a private object, and an
/// anonymous write stores nothing.
#[tokio::test]
async fn n_a_url_without_its_signature_is_denied_where_anonymous_access_is() {
    let root = TestRoot::new();
    let service = public_read(&root).await;
    let read = HandSigned::new(http::Method::GET, "/private/k", Bytes::new()).presigned();
    let answer = exchange(&service, rewritten(read, |pairs| remove(pairs, "X-Amz-Signature"))).await;
    assert_eq!(answer.status(), 403, "{}", body_of(&answer));
    assert!(body_of(&answer).contains("<Code>AccessDenied</Code>"), "{}", body_of(&answer));
    let write = HandSigned::new(http::Method::PUT, "/private/new", Bytes::from_static(b"written")).presigned();
    let answer = exchange(&service, rewritten(write, |pairs| remove(pairs, "X-Amz-Signature"))).await;
    assert_eq!(answer.status(), 403, "{}", body_of(&answer));
    let stored = exchange(&service, as_main(http::Method::GET, "/private/new", Bytes::new())).await;
    assert_eq!(stored.status(), 404, "{}", body_of(&stored));
}

/// Negative — a presigned URL legacy RustFS refuses before its credential lookup is answered with
/// its status, code and sentence, and a write under one stores nothing.
#[tokio::test]
async fn n_a_url_legacy_rustfs_refuses_is_answered_as_it_answers() {
    let root = TestRoot::new();
    let service = public_read(&root).await;
    let url = || HandSigned::new(http::Method::GET, "/private/k", Bytes::new()).presigned();
    let seconds = |stamp: &str| stamp.get(9..).map(str::to_owned).unwrap_or_default();
    for (request, status, code, sentence) in [
        (
            rewritten(url(), |pairs| set(pairs, "X-Amz-Signature", "")),
            400,
            "AuthorizationQueryParametersError",
            UNREADABLE,
        ),
        (
            rewritten(url(), |pairs| remove(pairs, "X-Amz-Credential")),
            400,
            "AuthorizationQueryParametersError",
            UNREADABLE,
        ),
        (
            rewritten(url(), |pairs| set(pairs, "X-Amz-Expires", "604801")),
            400,
            "AuthorizationQueryParametersError",
            UNREADABLE,
        ),
        (
            rewritten(url(), |pairs| set(pairs, "X-Amz-Algorithm", "AWS4-HMAC-SHA512")),
            501,
            "NotImplemented",
            "X-Amz-Algorithm other than AWS4-HMAC-SHA256 is not implemented",
        ),
        (
            rewritten(url(), |pairs| {
                let stamp = pairs
                    .iter()
                    .find(|(name, _)| name == "X-Amz-Date")
                    .map(|(_, value)| value.clone());
                let stamp = stamp.expect("a dated URL");
                let wrapped = format!("{}T{}60Z", &stamp[..8], &seconds(&stamp)[..4]);
                set(pairs, "X-Amz-Date", &wrapped);
            }),
            400,
            "InvalidRequest",
            "invalid amz date",
        ),
    ] {
        refused(&exchange(&service, request).await, status, code, sentence);
    }
    let write = HandSigned::new(http::Method::PUT, "/private/new", Bytes::from_static(b"written")).presigned();
    refused(
        &exchange(&service, rewritten(write, |pairs| set(pairs, "X-Amz-Signature", ""))).await,
        400,
        "AuthorizationQueryParametersError",
        UNREADABLE,
    );
    let stored = exchange(&service, as_main(http::Method::GET, "/private/new", Bytes::new())).await;
    assert_eq!(stored.status(), 404, "{}", body_of(&stored));
}
