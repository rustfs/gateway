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

//! The host-verified header token claim through the assembled service (ADR-0051,
//! rustfs/gateway#1586).
//!
//! Responsible for: a request whose only credential is the claimed header served as the principal
//! the host's verifier reports, in the governor's class, both authorization stages, the audit and
//! observer events and the handler; the header ignored exactly as before when the opt-in is
//! absent; refusal before any verifier, credential lookup, authorizer question or handler of the
//! header beside an AWS credential surface and on an operation whose floor refuses the scheme; a
//! closed `403`, never an anonymous request, when the verifier refuses, panics, finds no identity
//! or is not installed; and a header-token verdict accepted only from the request's own admission.
//! NOT responsible for: the floor's own rules over every surface and operation
//! (`rustfs-gateway-sig`'s `tests/header_token.rs`), where the token may not appear and the
//! unsigned payload rules (`header_token_secrecy.rs`), or the fixtures (`header_token/fixtures.rs`).
//! Upstream: `rustfs_gateway::ServiceBuilder`, `support`. Downstream: nothing.

use std::sync::Mutex;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use rustfs_gateway::sig::{
    AuthError, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, Identity, PayloadMode, SecurityFloor, SigService,
    SignatureVerifier, Verdict,
};
use rustfs_gateway::{AuthSchemeRef, ClassKind, HeaderTokenRefused, HeaderTokenRequest, HeaderTokenVerifier};
use rustfs_gateway_sig::OperationFloor;

use crate::support;

#[path = "header_token/fixtures.rs"]
pub(crate) mod fixtures;

use self::fixtures::{
    Answer, Established, Fixture, HEADER, PRINCIPAL, PROBE_PATH, RequestCase, SIGNED_PRINCIPAL, TOKEN, assemble, assemble_on,
    builder, claim, floors, status_and_code, token_only, with_token,
};

// ── admission ──────────────────────────────────────────────────────────────────────────────────

/// Positive — a request whose only credential is the claimed header is served as the principal
/// the host's verifier reports: the governor classes it as credential work, both authorization
/// stages and both audit events judge that principal under the header-token scheme, the observer
/// names it, and the handler reads it as a header-token principal and not a signed one.
#[tokio::test]
async fn a_verified_header_token_serves_the_request_as_the_principal_the_host_reports() {
    let fixture = assemble(Some(Answer::Accepts));
    let response = fixture.exchange(token_only(http::Method::GET, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 1, "asked exactly once");
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0, "no AWS credential was looked up");
    assert_eq!(*fixture.classes.0.lock().expect("not poisoned"), [ClassKind::CredentialLookup]);

    let asked = fixture.stages.take();
    assert_eq!(asked.iter().map(|asked| asked.stage).collect::<Vec<_>>(), ["route", "input"]);
    for stage in &asked {
        assert_eq!(stage.scheme, AuthSchemeRef::HeaderToken, "{stage:?}");
        assert_eq!(stage.identity.as_deref(), Some(PRINCIPAL), "{stage:?}");
        assert!(stage.scheme.is_authenticated() && !stage.scheme.is_presigned());
    }
    let audited = fixture.events.audited.lock().expect("not poisoned").clone();
    assert_eq!(audited.len(), 2, "{audited:?}");
    for event in &audited {
        assert_eq!(event, &(AuthSchemeRef::HeaderToken, Some(PRINCIPAL.to_owned())));
    }
    let observed = fixture.events.observed.lock().expect("not poisoned").clone();
    assert_eq!(observed, [(200, Some(PRINCIPAL.to_owned()))]);

    let handed = fixture.backend.take();
    assert_eq!(handed.len(), 1, "{handed:?}");
    assert_eq!(handed[0].operation, "ListBuckets");
    assert_eq!(handed[0].header_token.as_deref(), Some(PRINCIPAL));
    assert!(handed[0].signed.is_none() && !handed[0].anonymous, "{:?}", handed[0]);
}

/// Negative — without the opt-in the header is read by nothing: a request carrying it is answered
/// byte for byte as the same request without it, on an operation that refuses anonymous requests
/// and on one that admits them, and the handler still receives the header as an ordinary line.
/// The opted-in service beside it is the control that the header can decide anything.
#[tokio::test]
async fn n_without_the_opt_in_the_header_is_ignored_exactly_as_before() {
    for (method, uri, status) in [(http::Method::GET, "/", 403), (http::Method::POST, "/", 200)] {
        let fixture = assemble(None);
        let without = fixture.exchange(support::plain(method.clone(), uri)).await;
        let asked_without = fixture.stages.take();
        let handed_without = fixture.backend.take();
        let with = fixture.exchange(token_only(method.clone(), uri)).await;
        let asked_with = fixture.stages.take();
        let handed_with = fixture.backend.take();

        assert_eq!(with.status().as_u16(), status, "{method} {uri}");
        assert_eq!(with.status(), without.status(), "{method} {uri}");
        assert_eq!(with.headers(), without.headers(), "{method} {uri}");
        assert_eq!(with.body(), without.body(), "{method} {uri}");
        assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 0);
        assert_eq!(asked_with.len(), asked_without.len(), "{method} {uri}");
        for stage in &asked_with {
            assert_eq!((stage.scheme, stage.identity.as_deref()), (AuthSchemeRef::Anonymous, None), "{stage:?}");
        }
        assert_eq!(handed_with.len(), handed_without.len(), "{method} {uri}");
        for handed in &handed_with {
            assert!(handed.anonymous && handed.header_token.is_none(), "{handed:?}");
            let token_line = (HEADER.to_owned(), TOKEN.as_bytes().to_vec());
            assert!(handed.headers.contains(&token_line), "the header is an ordinary line: {handed:?}");
        }
        assert!(!fixture.service.startup_posture().contains("HEADER_TOKEN"));
    }
    let opted_in = assemble(Some(Answer::Accepts));
    let response = opted_in.exchange(token_only(http::Method::GET, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK, "the control: the same request, opted in");
}

/// Negative — a floor that carries the claim while no verifier is installed refuses every request
/// presenting the header, on an operation that admits anonymous requests too. It never serves the
/// request as anonymous.
#[tokio::test]
async fn n_a_claim_without_a_verifier_refuses_and_never_serves_anonymously() {
    let fixture = assemble_on(SecurityFloor::new().with_header_token_claim(claim()), None);
    for method in [http::Method::GET, http::Method::POST] {
        let response = fixture.exchange(token_only(method.clone(), "/")).await;
        assert_eq!(status_and_code(&response), (403, Some("AccessDenied".to_owned())), "{method}");
        assert!(fixture.stages.take().is_empty() && fixture.backend.take().is_empty(), "{method}");
    }
    let anonymous = fixture.exchange(support::plain(http::Method::POST, "/")).await;
    assert_eq!(
        anonymous.status(),
        http::StatusCode::OK,
        "the control: the same request without the header"
    );
}

/// Negative — the token beside any AWS credential surface is refused before any verifier runs:
/// the host's verifier is a spy that is never asked, no credential is looked up, and neither the
/// authorizer nor a handler runs. Each signed request is admitted by its signature on a service
/// without the opt-in, which is what makes the refusal the token's doing.
#[tokio::test]
async fn n_the_token_beside_an_aws_credential_surface_is_refused_before_any_verifier_runs() {
    let signed_token = || support::signed_with(http::Method::GET, "/", &[(HEADER, TOKEN)]);
    let presigned = || support::presigned_with_body(Bytes::new(), PayloadMode::Unsigned);
    let cases: Vec<RequestCase> = vec![
        ("a valid header signature covering the token", Box::new(signed_token)),
        (
            "a valid header signature beside an unsigned token",
            Box::new(|| with_token(support::signed(http::Method::GET, "/"))),
        ),
        ("a valid presigned URL", Box::new(move || with_token(presigned()))),
        (
            "another scheme's authorization",
            Box::new(|| {
                let mut request = token_only(http::Method::GET, "/");
                request
                    .headers_mut()
                    .insert("authorization", http::HeaderValue::from_static("Bearer opaque"));
                request
            }),
        ),
        (
            "a SigV2 authorization",
            Box::new(|| {
                let mut request = token_only(http::Method::GET, "/");
                request.headers_mut().insert(
                    "authorization",
                    http::HeaderValue::from_static("AWS AKIDEXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg="),
                );
                request
            }),
        ),
        (
            "a session token header",
            Box::new(|| {
                let mut request = token_only(http::Method::GET, "/");
                request
                    .headers_mut()
                    .insert("x-amz-security-token", http::HeaderValue::from_static("session"));
                request
            }),
        ),
        (
            "a partial presigned query",
            Box::new(|| {
                token_only(
                    http::Method::GET,
                    "/?X-Amz-Credential=AKIDEXAMPLE%2F20260102%2Fus-east-1%2Fs3%2Faws4_request",
                )
            }),
        ),
        (
            "a presigned algorithm alone",
            Box::new(|| token_only(http::Method::GET, "/?X-Amz-Algorithm=AWS4-HMAC-SHA256")),
        ),
        (
            "a SigV2 presigned query",
            Box::new(|| token_only(http::Method::GET, "/?AWSAccessKeyId=AKIDEXAMPLE&Expires=1767326645&Signature=frJIUN8D")),
        ),
        (
            "a SigV2 access key alone",
            Box::new(|| token_only(http::Method::GET, "/?AWSAccessKeyId=AKIDEXAMPLE")),
        ),
        (
            "a session token in the query",
            Box::new(|| token_only(http::Method::GET, "/?X-Amz-Security-Token=session")),
        ),
    ];
    for (floor_name, floor) in floors() {
        for (name, request) in &cases {
            let fixture = assemble_on(floor.clone(), Some(Answer::Accepts));
            let response = fixture.exchange(request()).await;
            fixture.refused_before_any_verifier(&response, &format!("{floor_name}: {name}"));
        }
    }
    // The controls: without the opt-in each signed request is its signer's, token header or not.
    for (name, request) in cases.iter().take(3) {
        let fixture = assemble(None);
        let response = fixture.exchange(request()).await;
        assert_eq!(response.status(), http::StatusCode::OK, "{name}: {:?}", response.body());
        let asked = fixture.stages.take();
        assert!(
            !asked.is_empty() && asked.iter().all(|stage| stage.identity.as_deref() == Some(SIGNED_PRINCIPAL)),
            "{name}: {asked:?}"
        );
    }
}

/// Negative — an operation whose floor refuses the scheme is refused before the verifier is asked,
/// while its signed request is served and a standard operation admits the token.
#[tokio::test]
async fn n_an_operation_whose_floor_refuses_the_scheme_never_reaches_the_verifier() {
    for (floor_name, floor) in floors() {
        let fixture = assemble_on(floor, Some(Answer::Accepts));
        let response = fixture.exchange(token_only(http::Method::HEAD, PROBE_PATH)).await;
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN, "{floor_name}");
        fixture.nothing_ran(floor_name);

        let signed = fixture.exchange(support::signed(http::Method::HEAD, PROBE_PATH)).await;
        assert_eq!(
            signed.status(),
            http::StatusCode::OK,
            "{floor_name}: the privileged operation serves its signer"
        );
        assert_eq!(fixture.backend.take().len(), 1, "{floor_name}");
        let _ = fixture.stages.take();

        let admitted = fixture.exchange(token_only(http::Method::GET, "/")).await;
        assert_eq!(
            admitted.status(),
            http::StatusCode::OK,
            "{floor_name}: a standard operation admits the token"
        );
        assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 1, "{floor_name}");
    }
}

// ── the verifier's answers ─────────────────────────────────────────────────────────────────────

/// Negative — a verifier that refuses is a closed `403` on an operation that admits anonymous
/// requests too: neither the authorizer nor a handler runs, and the request is never served as
/// anonymous. The accepting host beside it is the control.
#[tokio::test]
async fn n_a_verifier_that_refuses_is_a_closed_403_and_never_anonymous() {
    for (floor_name, floor) in floors() {
        let fixture = assemble_on(floor.clone(), Some(Answer::Refuses));
        for method in [http::Method::GET, http::Method::POST] {
            let response = fixture.exchange(token_only(method.clone(), "/")).await;
            assert_eq!(
                status_and_code(&response),
                (403, Some("AccessDenied".to_owned())),
                "{floor_name}: {method}"
            );
            assert!(fixture.stages.take().is_empty(), "{floor_name}: {method}: the authorizer was asked");
            assert!(fixture.backend.take().is_empty(), "{floor_name}: {method}: a handler ran");
        }
        assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 2, "{floor_name}: asked once per request");
        let observed = fixture.events.observed.lock().expect("not poisoned").clone();
        assert_eq!(observed, [(403, None), (403, None)], "{floor_name}: a refused request names nobody");

        let accepting = assemble_on(floor, Some(Answer::Accepts));
        let response = accepting.exchange(token_only(http::Method::POST, "/")).await;
        assert_eq!(response.status(), http::StatusCode::OK, "{floor_name}: the control");
        let handed = accepting.backend.take();
        assert_eq!(
            handed[0].header_token.as_deref(),
            Some(PRINCIPAL),
            "{floor_name}: served as the principal"
        );
        assert!(!handed[0].anonymous, "{floor_name}");
    }
}

/// Negative — a verifier that panics is a closed `403`, and the next request on the same service
/// is verified and served: the panic poisons nothing. A payload whose own destructor panics is
/// contained the same way.
#[tokio::test]
async fn n_a_verifier_that_panics_is_a_closed_403_and_poisons_nothing() {
    for answer in [Answer::PanicsOnce, Answer::PanicsOnceWithAPayloadThatPanics] {
        let fixture = assemble(Some(answer));
        let response = fixture.exchange(token_only(http::Method::POST, "/")).await;
        assert_eq!(status_and_code(&response), (403, Some("AccessDenied".to_owned())), "{answer:?}");
        assert!(fixture.stages.take().is_empty() && fixture.backend.take().is_empty(), "{answer:?}");

        let next = fixture.exchange(token_only(http::Method::POST, "/")).await;
        assert_eq!(next.status(), http::StatusCode::OK, "{answer:?}: {:?}", next.body());
        assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 2, "{answer:?}");
        assert_eq!(fixture.backend.take()[0].header_token.as_deref(), Some(PRINCIPAL), "{answer:?}");
    }
}

/// Negative and positive — a host verifier that reports what its outer layer installed refuses a
/// request in which nothing was installed, with a closed `403` and no anonymous service, and
/// serves the same request as the installed identity when one was.
#[tokio::test]
async fn n_a_request_in_which_no_identity_was_established_is_a_closed_403() {
    let fixture = assemble(Some(Answer::ReportsInstalled));
    let response = fixture.exchange(token_only(http::Method::POST, "/")).await;
    assert_eq!(status_and_code(&response), (403, Some("AccessDenied".to_owned())));
    assert!(fixture.stages.take().is_empty() && fixture.backend.take().is_empty());
    assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 1);

    let mut request = token_only(http::Method::POST, "/");
    request.extensions_mut().insert(Established("PROJECTMEMBER"));
    let response = fixture.exchange(request).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(fixture.backend.take()[0].header_token.as_deref(), Some("PROJECTMEMBER"));

    // An established identity without the header establishes nothing: the request is anonymous.
    let mut request = support::plain(http::Method::POST, "/");
    request.extensions_mut().insert(Established("PROJECTMEMBER"));
    let response = fixture.exchange(request).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let handed = fixture.backend.take();
    assert!(handed[0].anonymous && handed[0].header_token.is_none(), "{:?}", handed[0]);
    assert_eq!(
        fixture.verifier_calls.load(Ordering::SeqCst),
        2,
        "not asked for a request without the header"
    );
}

// ── a verdict from another admission ───────────────────────────────────────────────────────────

/// Hands out a header-token verdict some other admission minted.
struct ReusesAVerdict(Mutex<Option<Verdict>>);

impl SignatureVerifier for ReusesAVerdict {
    fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
        self.0
            .lock()
            .expect("not poisoned")
            .take()
            .unwrap_or_else(|| Verdict::reject(AuthError::AccessDenied))
    }
}

/// Reports the named principal for every request.
struct Reports(&'static str);

impl HeaderTokenVerifier for Reports {
    fn verify(&self, _request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
        Identity::new(self.0).map_err(|_| HeaderTokenRefused)
    }
}

/// Negative — a header-token verdict that host code minted from its own call to the floor cannot
/// authenticate another request: the service accepts one only from that request's own
/// header-token admission.
#[tokio::test]
async fn n_a_header_token_verdict_from_another_admission_authenticates_nothing() {
    use rustfs_gateway_sig::{Admission, RawQuery, RequestNow, WireView};

    let mut headers = http::HeaderMap::new();
    headers.insert(HEADER, http::HeaderValue::from_static(TOKEN));
    let operation = OperationFloor::builtin("ListBuckets", SigService::S3);
    let floor = SecurityFloor::new().with_header_token_claim(claim());
    let view = WireView::new(&headers, RawQuery::new(""));
    let Ok(Admission::HeaderToken(admission)) = floor.admit(view, &operation, RequestNow::from_unix_seconds(1)) else {
        panic!("the fixture must exercise header-token admission");
    };
    let minted = admission.verify(&Reports("FORGEDPRINCIPAL"), &rustfs_gateway::TransportExtensions::default());
    assert!(minted.header_token_receipt().is_some(), "the fixture must hold a header-token verdict");

    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("a legal custom prefix"))
        .expect("the first scheme is unique");
    let (builder, recorders) = builder(SecurityFloor::new().with_custom_schemes(registry));
    let fixture = Fixture::of(builder.custom_signature_verifier(ReusesAVerdict(Mutex::new(Some(minted)))), recorders);
    let mut request = support::plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert("x-vendor-auth-token", http::HeaderValue::from_static("opaque"));
    let response = fixture.exchange(request).await;
    assert_eq!(status_and_code(&response), (403, Some("AccessDenied".to_owned())));
    assert!(fixture.stages.take().is_empty() && fixture.backend.take().is_empty());
}

// ── the start-up report ────────────────────────────────────────────────────────────────────────

/// Negative — the start-up report names the claimed header, whether a verifier is installed and
/// exactly the operations that admit the scheme, and only when the claim is installed.
#[test]
fn n_the_startup_report_names_the_claim_only_when_it_is_installed() {
    let line = |fixture: &Fixture| {
        fixture
            .service
            .startup_posture()
            .lines()
            .find(|line| line.starts_with("HEADER_TOKEN_POSTURE"))
            .map(str::to_owned)
    };
    assert_eq!(line(&assemble(None)), None);
    assert_eq!(
        line(&assemble(Some(Answer::Accepts))).as_deref(),
        Some(
            "HEADER_TOKEN_POSTURE header_token=x-auth-token header_token_verifier=installed header_token_ops=[ListBuckets,example:Ping]"
        ),
        "the privileged probe is not listed"
    );
    assert_eq!(
        line(&assemble_on(SecurityFloor::new().with_header_token_claim(claim()), None)).as_deref(),
        Some(
            "HEADER_TOKEN_POSTURE header_token=x-auth-token header_token_verifier=none header_token_ops=[ListBuckets,example:Ping]"
        ),
    );
}

/// Positive — the claim is written onto the floor when the service is built, so a floor installed
/// after the opt-in keeps both the claim and its own policy: the token is still verified, and the
/// later floor's anonymous delegation still admits a request without one.
#[tokio::test]
async fn the_claim_is_applied_at_build_whatever_the_order_of_the_builder_calls() {
    let (builder, recorders) = builder(SecurityFloor::new());
    let later = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    let fixture = Fixture::of(
        builder
            .host_verified_header_token(claim(), Reports(PRINCIPAL))
            .security_floor(later),
        recorders,
    );
    let response = fixture.exchange(token_only(http::Method::GET, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(fixture.backend.take()[0].header_token.as_deref(), Some(PRINCIPAL));

    let anonymous = fixture.exchange(support::plain(http::Method::GET, "/")).await;
    assert_eq!(anonymous.status(), http::StatusCode::OK, "the later floor's own policy is in force");
    assert!(fixture.backend.take()[0].anonymous);
}
