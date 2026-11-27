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

//! Unit tests for the ADR-0056 sealed cross-crate token verification bridge.
//!
//! Responsible for: verifying that `verify_bearer_alongside_signature` requires a real
//! `Verdict::Authenticated` proof before consulting the bearer verifier, enforces principal,
//! resource, and expiry bindings, and records `BearerReceipt::claim()`.
//! NOT responsible for: compile-fail enforcement (`tests/compile_fail/token_sealing_*.rs`).
//! Upstream: `super`. Downstream: `cargo test -p rustfs-gateway-sig`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::HeaderMap;
use rustfs_gateway_http::TransportExtensions;
use zeroize::Zeroizing;

use super::*;
use crate::bearer::{BearerGrant, BearerRefused, BearerTokenRequest};
use crate::header_token::{HeaderTokenClaim, HeaderTokenRefused};
use crate::query::RawQuery;
use crate::scheme::{AuthScheme, SigIdentity, SigService};
use crate::signature::{CtBytes, Signature};
use crate::verdict::Identity;

const CLAIM: QueryBearerClaim = QueryBearerClaim::new("token", ".zip");
const NOW: i64 = 1_000;

struct CountingBearer {
    calls: AtomicUsize,
    principal: &'static str,
    resource: &'static str,
    expires_at: i64,
}

impl BearerTokenVerifier for CountingBearer {
    fn verify(&self, _request: &BearerTokenRequest<'_>) -> Result<BearerGrant, BearerRefused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let identity = Identity::new(self.principal).map_err(|_| BearerRefused)?;
        Ok(BearerGrant::new(identity, self.resource, self.expires_at, Arc::new(7u8)))
    }
}

fn authenticated_verdict(principal: &str) -> Verdict {
    let sig = Signature::HmacSha256(CtBytes::from_array([7; 32]));
    let proof = sig.ct_verify(&sig).expect("matching fixture proof");
    let identity = Identity::new(principal).expect("valid fixture identity");
    Verdict::authenticated(identity, AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3), proof)
}

fn bearer_op() -> OperationFloor {
    with_query_bearer_claim(FacadeSeal::new(), OperationFloor::custom("fixture:ZipDownload", SigService::S3), CLAIM)
}

#[test]
fn n_verify_bearer_alongside_signature_refuses_non_authenticated_verdicts_without_calling_verifier() {
    #[derive(Clone)]
    struct Est;
    struct HeaderHost;
    impl HeaderTokenVerifier for HeaderHost {
        type Established = Est;
        fn identity(&self, _: &Est, _: RequestNow) -> Result<Identity, HeaderTokenRefused> {
            Identity::new("ALICE").map_err(|_| HeaderTokenRefused)
        }
    }

    let floor = SecurityFloor::new();
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("token=fixture"));
    let now = RequestNow::from_unix_seconds(NOW);
    let op = bearer_op();

    let anonymous = Verdict::anonymous(
        crate::floor::detect_credentials(&WireView::new(&headers, RawQuery::new("")))
            .into_evidence()
            .expect("no creds"),
    );
    let bearer_verdict = verify_bearer(
        FacadeSeal::new(),
        BearerAdmission::new("fixture:ZipDownload", CLAIM, Zeroizing::new("t".to_owned()), now),
        &CountingBearer {
            calls: AtomicUsize::new(0),
            principal: "ALICE",
            resource: "abc",
            expires_at: NOW + 60,
        },
        "/x/abc.zip",
    );
    let mut ht_headers = HeaderMap::new();
    ht_headers.insert("x-auth-token", http::HeaderValue::from_static("opaque"));
    let ht_floor = SecurityFloor::new().with_header_token_claim(HeaderTokenClaim::new("x-auth-token").expect("claim"));
    let Ok(crate::Admission::HeaderToken(ht_adm)) = ht_floor.admit(
        WireView::new(&ht_headers, RawQuery::new("")),
        &OperationFloor::builtin("GetObject", SigService::S3),
        now,
    ) else {
        panic!("expected header token admission");
    };
    let mut req = http::Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(())
        .expect("request");
    req.extensions_mut().insert(Est);
    let accepted = rustfs_gateway_http::WireRequest::accept(req, &rustfs_gateway_http::Limits::default()).expect("accepted");
    let header_verdict = verify_header_token(FacadeSeal::new(), ht_adm, &HeaderHost, accepted.transport_extensions());
    let rejected = Verdict::reject(AuthError::AccessDenied);

    let verifier = CountingBearer {
        calls: AtomicUsize::new(0),
        principal: "ALICE",
        resource: "abc",
        expires_at: NOW + 60,
    };
    for verdict in [anonymous, bearer_verdict, header_verdict, rejected] {
        let result =
            verify_bearer_alongside_signature(FacadeSeal::new(), &floor, &view, &op, now, &verdict, &verifier, "/x/abc.zip");
        assert_eq!(result.err(), Some(AuthError::AccessDenied));
    }
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);

    // Unclaimed operation also refuses before calling the verifier.
    let unclaimed = OperationFloor::custom("fixture:Other", SigService::S3);
    let signed = authenticated_verdict("ALICE");
    let result =
        verify_bearer_alongside_signature(FacadeSeal::new(), &floor, &view, &unclaimed, now, &signed, &verifier, "/x/abc.zip");
    assert_eq!(result.err(), Some(AuthError::AccessDenied));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    let _ = TransportExtensions::default();
}

#[test]
fn n_verify_bearer_alongside_signature_refuses_principal_resource_and_expiry_mismatches() {
    let floor = SecurityFloor::new();
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("token=fixture"));
    let now = RequestNow::from_unix_seconds(NOW);
    let op = bearer_op();
    let signed = authenticated_verdict("ALICE");

    for (principal, resource, expires_at) in [
        ("BOB", "abc", NOW + 60),
        ("ALICE", "xyz", NOW + 60),
        ("ALICE", "abc", NOW),
        ("ALICE", "abc", NOW - 1),
    ] {
        let verifier = CountingBearer {
            calls: AtomicUsize::new(0),
            principal,
            resource,
            expires_at,
        };
        let result =
            verify_bearer_alongside_signature(FacadeSeal::new(), &floor, &view, &op, now, &signed, &verifier, "/x/abc.zip");
        assert_eq!(result.err(), Some(AuthError::AccessDenied));
    }
}

#[test]
fn verify_bearer_alongside_signature_accepts_matching_signed_verdict_and_records_claim() {
    let floor = SecurityFloor::new();
    let headers = HeaderMap::new();
    let view = WireView::new(&headers, RawQuery::new("token=fixture"));
    let now = RequestNow::from_unix_seconds(NOW);
    let op = bearer_op();
    let signed = authenticated_verdict("ALICE");
    let verifier = CountingBearer {
        calls: AtomicUsize::new(0),
        principal: "ALICE",
        resource: "abc",
        expires_at: NOW + 60,
    };
    let receipt = verify_bearer_alongside_signature(FacadeSeal::new(), &floor, &view, &op, now, &signed, &verifier, "/x/abc.zip")
        .expect("matching signed verdict and bearer grant must verify");
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(receipt.identity().access_key_id(), "ALICE");
    assert_eq!(receipt.operation(), "fixture:ZipDownload");
    assert_eq!(receipt.resource(), "abc");
    assert_eq!(receipt.claim(), CLAIM);
    assert_eq!(receipt.state().get::<u8>(), Some(&7));
}
