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

//! The store-fault cases outside the per-form matrix of `super` (the #1594 review, finding 5).
//!
//! Responsible for: the STS body path answering a fault before the body is read; a fault with a
//! session token presented; a fault on a request refused before the lookup; `HEAD`; the switch
//! reached through `SigV4Authenticator::rustfs_profile` rather than named; and the connection
//! verdict a custom authenticator's `Unavailable` now gets.
//! NOT responsible for: the per-form matrix (`super`), or building the forms' requests
//! (`super::requests`).
//! Upstream: `super`'s harness and store. Downstream: nothing.

use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use rustfs_gateway::dto::PutObject;
use rustfs_gateway::sig::{PayloadMode, SessionToken, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    Authentication, AuthenticationOutcome, Authenticator, BoxFuture, ConnectionIntent, CredentialProvider, ProviderError,
    Unavailable, allow_when,
};

use super::{ACCESS_KEY, Form, Harness, Reached, Record, SECRET, TOKEN, answer, request};
use crate::support;

/// A fault under the switch, and an unknown key, in both switch positions.
const FAULT: Record = Record::Fault(ProviderError::Backend);

/// A header-signed `method /` request, signed for `region`, optionally with a session token.
fn signed_v4(method: http::Method, region: &str, token: Option<&str>) -> http::Request<Bytes> {
    let mut credentials = SigningCredentials::new(ACCESS_KEY, SECRET.as_bytes()).expect("signing credentials");
    if let Some(token) = token {
        credentials = credentials.with_session_token(SessionToken::new(token).expect("a non-empty token"));
    }
    let stamp = rustfs_gateway::sig::AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), region, SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let signing = SigningRequest::new(&method, "/", "", &headers, &host, PayloadMode::Empty, stamp).with_wire_content_length(0);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut builder = http::Request::builder().method(method).uri("/");
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a valid request")
}

/// Negative — the STS body path answers a fault before it reads the body, as it answers an unknown
/// key (the stated deviation of ADR-0050). A body past the 8192-byte bound would be refused
/// `400 InvalidRequest` once read; a fault is `500` under the switch and the closed `403` without
/// it, so the read did not happen.
#[tokio::test]
async fn n_a_fault_on_the_sts_body_path_answers_before_the_body_is_read() {
    let over_length = || {
        let body = Bytes::from(vec![b'a'; 9_000]);
        let mut request =
            crate::sts_body_signature::signed("/example-bucket/object", "sts", ACCESS_KEY, SECRET, &body, body.clone());
        request
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
        request
    };
    let found = Harness::new(Form::StsBody, Record::Found, true)
        .send_request(over_length())
        .await;
    assert_eq!(found.status, StatusCode::BAD_REQUEST, "the length refusal control moved: {found:?}");
    for switch in [false, true] {
        let unknown = Harness::new(Form::StsBody, Record::NotFound, switch)
            .send_request(over_length())
            .await;
        assert_eq!(unknown.status, StatusCode::FORBIDDEN, "switch={switch}: {unknown:?}");
        let fault = Harness::new(Form::StsBody, FAULT, switch).send_request(over_length()).await;
        if switch {
            assert_eq!(fault.status, StatusCode::INTERNAL_SERVER_ERROR, "{fault:?}");
            assert_eq!(fault.connection, unknown.connection, "{fault:?}");
        } else {
            assert_eq!(fault, unknown);
        }
    }
}

/// Negative — a fault for a request that presents a session token is answered as one that does
/// not: the closed `403` of an unknown key without the switch, the same `500` with it.
#[tokio::test]
async fn n_a_fault_with_a_session_token_presented_is_answered_as_without_one() {
    let with_token = || signed_v4(http::Method::POST, "us-east-1", Some(TOKEN));
    for switch in [false, true] {
        let without = Harness::new(Form::V4Header, FAULT, switch).send(Form::V4Header, SECRET).await;
        let fault = Harness::new(Form::V4Header, FAULT, switch).send_request(with_token()).await;
        if switch {
            assert_eq!(fault.status, StatusCode::INTERNAL_SERVER_ERROR, "{fault:?}");
            assert_eq!(fault, without);
        } else {
            let unknown = Harness::new(Form::V4Header, Record::NotFound, false)
                .send_request(with_token())
                .await;
            assert_eq!(fault, unknown);
        }
    }
}

/// Negative — a request refused before the lookup (a scope region this deployment does not serve)
/// keeps its own refusal under a fault, in both positions, and the store is never asked.
#[tokio::test]
async fn n_a_request_refused_before_the_lookup_keeps_its_refusal_under_a_fault() {
    for switch in [false, true] {
        let unknown = Harness::new(Form::V4Header, Record::NotFound, switch)
            .send_request(signed_v4(http::Method::POST, "eu-west-1", None))
            .await;
        assert_eq!(unknown.status, StatusCode::BAD_REQUEST, "switch={switch}: {unknown:?}");
        let harness = Harness::new(Form::V4Header, FAULT, switch);
        let fault = harness.send_request(signed_v4(http::Method::POST, "eu-west-1", None)).await;
        assert_eq!(fault, unknown, "switch={switch}");
        assert_eq!(harness.store.calls(), 0, "switch={switch}: the store was asked");
    }
}

/// Negative — `HEAD`: under the switch a fault is a `500` with no body, and without it the closed
/// `403` an unknown key's `HEAD` gets; both keep the connection, as a bodyless refusal does.
#[tokio::test]
async fn n_a_fault_on_head_is_a_bodyless_answer_in_both_positions() {
    for switch in [false, true] {
        let service = |record: Record| {
            let store = super::Store::holding(record);
            let authenticator = super::authenticator(store as Arc<dyn CredentialProvider>);
            let authenticator = if switch {
                authenticator.answer_credential_store_faults_as_unavailable()
            } else {
                authenticator
            };
            support::wired()
                .authenticator(authenticator)
                .clock_with_skew_ack(
                    support::fixed_clock(),
                    rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
                )
                .register::<support::HeadPing, _>(Arc::new(support::Backend))
                .dialect(&support::head_ping_dialect())
                .build()
                .expect("a complete assembly")
        };
        let unknown = answer(&service(Record::NotFound), signed_v4(http::Method::HEAD, "us-east-1", None)).await;
        assert_eq!(unknown.status, StatusCode::FORBIDDEN, "switch={switch}: {unknown:?}");
        let fault = answer(&service(FAULT), signed_v4(http::Method::HEAD, "us-east-1", None)).await;
        assert!(fault.body.is_empty(), "switch={switch}: a HEAD answer carried a body: {fault:?}");
        assert_eq!(fault.connection, Some(ConnectionIntent::MayKeepAlive), "switch={switch}");
        if switch {
            assert_eq!(fault.status, StatusCode::INTERNAL_SERVER_ERROR, "{fault:?}");
        } else {
            assert_eq!(fault, unknown);
        }
    }
}

/// Negative — the RustFS profile's authenticator preset answers a fault `500`, with no switch named
/// by the caller: the preset is held to the switch by behaviour, not only by its `Debug` text. An
/// unknown key under the preset is still the closed `403`.
#[tokio::test]
async fn n_the_rustfs_profile_preset_answers_a_fault_with_a_500() {
    for form in [Form::V4Header, Form::V4Streaming, Form::V2Header] {
        let profiled = |record| Harness::with(form, record, rustfs_gateway::SigV4Authenticator::rustfs_profile);
        let fault = profiled(FAULT).send(form, SECRET).await;
        assert_eq!(fault.status, StatusCode::INTERNAL_SERVER_ERROR, "{form:?}: {fault:?}");
        let unknown = profiled(Record::NotFound).send(form, SECRET).await;
        assert_eq!(unknown.status, StatusCode::FORBIDDEN, "{form:?}: {unknown:?}");
    }
}

/// An authenticator whose store is always down.
struct AlwaysUnavailable;

impl Authenticator for AlwaysUnavailable {
    fn authenticate<'a>(&'a self, _request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        Box::pin(async { Err(Unavailable) })
    }
}

/// Negative — what this change gives a custom authenticator too: its `Unavailable` on a request
/// whose body is still owed is a `500` that closes the connection, where it used to keep it.
#[tokio::test]
async fn n_a_custom_authenticators_unavailable_closes_an_owed_body() {
    let service = support::wired()
        .authenticator(AlwaysUnavailable)
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<PutObject, _>(Arc::new(Reached::default()))
        .build()
        .expect("a complete assembly");
    let owed = answer(&service, request(Form::V4Streaming, SECRET)).await;
    assert_eq!(owed.status, StatusCode::INTERNAL_SERVER_ERROR, "{owed:?}");
    assert_eq!(owed.connection, Some(ConnectionIntent::Close), "{owed:?}");
}
