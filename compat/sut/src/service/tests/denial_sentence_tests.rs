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

//! Authorization denials as the RustFS-profile launcher words them (rustfs/gateway#1349).
//!
//! Responsible for: an anonymous caller and a signed caller the policy refuses answering `403
//! AccessDenied` with legacy RustFS's sentence, for a read and a write, with nothing stored by a
//! refused write; and the refusals and grants the switch must not reach.
//! NOT responsible for: the decision itself (the launcher's `PolicyAuthorizer`) or the sentence
//! rule (`rustfs-gateway`'s `builder::denial_sentences`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, from source (rustfs/rustfs `95268a3b9`): every refusing branch of RustFS's
//! per-operation authorization ends in `DenialContext::deny`, which answers `403 AccessDenied`
//! with the sentence `Access Denied` for an anonymous and a signed caller alike
//! (`rustfs/src/storage/access.rs:1161-1164`).

use super::*;

const LEGACY_SENTENCE: &str = "Access Denied";

fn anonymous(method: http::Method, target: &str, body: &'static [u8]) -> http::Request<Bytes> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(Bytes::from_static(body))
        .expect("a valid unsigned request")
}

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    body.split_once(&format!("<{name}>"))
        .and_then(|(_, rest)| rest.split_once(&format!("</{name}>")))
        .map(|(value, _)| value)
}

async fn private_bucket(service: &S3Service) {
    let created = exchange(service, as_main(http::Method::PUT, "/denied", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(service, as_main(http::Method::PUT, "/denied/kept", Bytes::from_static(b"kept"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
}

fn assert_denied(response: &WireResponse, what: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 403, "{what}: {body}");
    assert_eq!(element(&body, "Code"), Some("AccessDenied"), "{what}: {body}");
    assert_eq!(element(&body, "Message"), Some(LEGACY_SENTENCE), "{what}: {body}");
}

/// Negative — an anonymous read and an anonymous write of a private bucket are refused with
/// legacy RustFS's sentence, and the refused write stores nothing: the object keeps its bytes and
/// no other key appears.
#[tokio::test]
async fn n_an_anonymous_caller_is_denied_in_legacy_rustfs_words_and_writes_nothing() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    private_bucket(&service).await;

    assert_denied(
        &exchange(&service, anonymous(http::Method::GET, "/denied/kept", b"")).await,
        "anonymous read",
    );
    assert_denied(
        &exchange(&service, anonymous(http::Method::PUT, "/denied/kept", b"overwritten")).await,
        "anonymous overwrite",
    );
    assert_denied(
        &exchange(&service, anonymous(http::Method::PUT, "/denied/new", b"new")).await,
        "anonymous new key",
    );

    let kept = exchange(&service, as_main(http::Method::GET, "/denied/kept", Bytes::new())).await;
    assert_eq!((kept.status().as_u16(), kept.body().as_ref()), (200, &b"kept"[..]));
    let absent = exchange(&service, as_main(http::Method::GET, "/denied/new", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
}

/// Negative — a signed caller the policy does not admit is refused in the same words: a read, a
/// write and a listing of another identity's bucket, and the write stores nothing.
#[tokio::test]
async fn n_a_signed_caller_the_policy_refuses_is_denied_in_legacy_rustfs_words() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    private_bucket(&service).await;

    assert_denied(
        &exchange(&service, as_alt(http::Method::GET, "/denied/kept", Bytes::new())).await,
        "alt read",
    );
    assert_denied(
        &exchange(&service, as_alt(http::Method::PUT, "/denied/kept", Bytes::from_static(b"alt"))).await,
        "alt overwrite",
    );
    assert_denied(
        &exchange(&service, as_alt(http::Method::GET, "/denied", Bytes::new())).await,
        "alt listing",
    );

    let kept = exchange(&service, as_main(http::Method::GET, "/denied/kept", Bytes::new())).await;
    assert_eq!((kept.status().as_u16(), kept.body().as_ref()), (200, &b"kept"[..]));
}

/// Negative — a HEAD the policy refuses keeps its bodyless `403`: the sentence has nowhere to go
/// and nothing else about the answer moves.
#[tokio::test]
async fn n_a_refused_head_stays_bodyless() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    private_bucket(&service).await;

    let head = exchange(&service, anonymous(http::Method::HEAD, "/denied/kept", b"")).await;
    assert_eq!(head.status(), 403);
    assert!(head.body().is_empty(), "{}", body_of(&head));
}

/// Negative — the switch reaches no other refusal: a forged signature keeps legacy RustFS's
/// credential sentence and code, which the authenticator decides before any policy is read.
#[tokio::test]
async fn n_a_credential_refusal_keeps_its_own_sentence() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    private_bucket(&service).await;

    let forged = signed(MAIN_KEY, "not-the-secret", http::Method::GET, "/denied/kept", Bytes::new(), &[]);
    let response = exchange(&service, forged).await;
    let body = body_of(&response);
    assert_eq!(response.status(), 403, "{body}");
    assert_eq!(element(&body, "Code"), Some("SignatureDoesNotMatch"), "{body}");
    assert_ne!(element(&body, "Message"), Some(LEGACY_SENTENCE), "{body}");
}

/// Positive — what the policy grants is still served: the owner reads its object, so the switch
/// turns no grant into a denial.
#[tokio::test]
async fn the_owner_is_still_served() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    private_bucket(&service).await;

    let read = exchange(&service, as_main(http::Method::GET, "/denied/kept", Bytes::new())).await;
    assert_eq!((read.status().as_u16(), read.body().as_ref()), (200, &b"kept"[..]));
}
