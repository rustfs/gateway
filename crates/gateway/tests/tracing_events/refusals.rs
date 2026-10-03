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

//! The events of the requests the gateway refuses, and of the extensions that panic while serving
//! one (rustfs/gateway#1162).
//!
//! Responsible for: that each stage's refusal is one `gateway_request_refused` event at the level
//! `docs/observability.md` gives its subsystem, naming the identifier the caller received, the
//! operation, the status and the code; that an authorization refusal names its decision and
//! stage; that a panicking handler or authorizer is one `gateway_extension_panicked`; and that
//! what the deployment answered, an allowed request and the visibility check are not reported.
//! NOT responsible for: the start-up and report-panic events and the credential scan (`super`).
//! Upstream: `super`'s capture. Downstream: nothing.

use super::*;

/// A handler whose every call panics with deployment text.
struct Panics;

impl rustfs_gateway::Handler<Ping> for Panics {
    async fn call(&self, _request: rustfs_gateway::Req<Ping>) -> rustfs_gateway::HandlerResult<Ping> {
        std::panic::panic_any(PANIC_PAYLOAD.to_owned())
    }
}

/// A handler whose every call refuses as a backend does: the refusal is the handler's own answer.
struct MissingKey;

impl rustfs_gateway::Handler<Ping> for MissingKey {
    async fn call(&self, _request: rustfs_gateway::Req<Ping>) -> rustfs_gateway::HandlerResult<Ping> {
        Err(rustfs_gateway::HandlerErrorContext::missing_object(
            rustfs_gateway::MissingObject::Key,
            rustfs_gateway::ResourceVisibility::Visible,
        )
        .into())
    }
}

/// Sends `request` through `service` and returns the answer's status and request identifier.
fn answer(runtime: &tokio::runtime::Runtime, service: &S3Service, request: http::Request<bytes::Bytes>) -> (u16, String) {
    runtime.block_on(async {
        let response = service.call_bytes(request).await;
        let id = response
            .headers()
            .get("x-amz-request-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (response.status().as_u16(), id)
    })
}

/// The one refusal event `capture` holds, held to the shape and the request it reports on.
fn one_refusal(capture: &Capture, level: Level, subsystem: &str, request_id: &str) -> Captured {
    let events = capture.named("gateway_request_refused");
    assert_eq!(events.len(), 1, "{:?}", capture.events());
    let refusal = events[0].clone();
    assert_eq!(refusal.level, level, "{refusal:?}");
    rustfs_shaped(&refusal, subsystem);
    assert_eq!(refusal.field("result"), Some("refused"), "{refusal:?}");
    assert_eq!(refusal.field("request_id"), Some(request_id), "{refusal:?}");
    refusal
}

/// Negative — a forged signature is one `warn` event naming the code the caller was answered with,
/// the status and the request; never the access key it claimed.
#[test]
fn an_authentication_refusal_is_one_warn_event_with_its_code() {
    let ((status, id), capture) = captured(|runtime| {
        let service = ping_service(support::wired_at_signed_time());
        let mut forged = support::signed(http::Method::POST, "/");
        forged.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
            ),
        );
        answer(runtime, &service, forged)
    });
    assert_eq!(status, 403);
    let refusal = one_refusal(&capture, Level::WARN, "authentication", &id);
    assert_eq!(refusal.field("status"), Some("403"), "{refusal:?}");
    assert_eq!(refusal.field("code"), Some("SignatureDoesNotMatch"), "{refusal:?}");
    assert_eq!(refusal.field("operation"), Some("example:Ping"), "{refusal:?}");
    assert!(!refusal.rendered().contains("AKIDEXAMPLE"), "{refusal:?}");
}

/// Negative — a denied request is one `warn` event naming the decision, the stage it was made at
/// and the action; `indeterminate` (the policy source could not answer) apart from `deny`.
#[test]
fn an_authorization_denial_is_one_warn_event_with_its_decision() {
    let ((status, id), capture) = captured(|runtime| {
        let service = ping_service(support::wired_denying());
        answer(runtime, &service, support::plain(http::Method::POST, "/"))
    });
    assert_eq!(status, 403);
    let denial = one_refusal(&capture, Level::WARN, "authorization", &id);
    assert_eq!(denial.field("decision"), Some("deny"), "{denial:?}");
    assert_eq!(denial.field("authorization_stage"), Some("route"), "{denial:?}");
    assert_eq!(denial.field("action"), Some("example:Ping"), "{denial:?}");
    assert_eq!(denial.field("operation"), Some("example:Ping"), "{denial:?}");

    let ((status, id), capture) = captured(|runtime| {
        let unavailable = rustfs_gateway::policy_from(|_| Err(rustfs_gateway::PolicyError::unavailable()));
        let service = ping_service(support::wired().policy_source(unavailable));
        answer(runtime, &service, support::plain(http::Method::POST, "/"))
    });
    assert_eq!(status, 403);
    let indeterminate = one_refusal(&capture, Level::WARN, "authorization", &id);
    assert_eq!(indeterminate.field("decision"), Some("indeterminate"), "{indeterminate:?}");
}

/// Negative — a limiter's refusal is one `debug` event, as RustFS logs its own rate-limit refusals:
/// shedding load must not cost a log line per request.
#[test]
fn a_governor_refusal_is_one_debug_event() {
    let ((status, id), capture) = captured(|runtime| {
        let service = ping_service(support::wired().governor(support::RefuseEverything));
        answer(runtime, &service, support::plain(http::Method::POST, "/"))
    });
    assert_eq!(status, 503);
    let refusal = one_refusal(&capture, Level::DEBUG, "governor", &id);
    assert_eq!(refusal.field("code"), Some("SlowDown"), "{refusal:?}");
}

/// Positive — a refusal names the identifier the host handed over, which is the one the caller was
/// answered with, so the host's own log lines and this event name one request (rustfs/gateway#1150).
#[test]
fn a_refusal_names_the_identifier_the_host_handed_over() {
    const HOST_ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    let ((status, id), capture) = captured(|runtime| {
        let service = ping_service(support::wired().governor(support::RefuseEverything));
        let mut request = support::plain(http::Method::POST, "/");
        request
            .extensions_mut()
            .insert(rustfs_gateway::HostRequestId::new(HOST_ID).expect("an identifier in the closed alphabet"));
        answer(runtime, &service, request)
    });
    assert_eq!((status, id.as_str()), (503, HOST_ID));
    one_refusal(&capture, Level::DEBUG, "governor", HOST_ID);
}

/// Negative — a request that names no operation is one `debug` event, and a malformed input one
/// more: neither is an operator's to act on, and neither is logged above `debug`.
#[test]
fn a_malformed_request_is_one_debug_event() {
    let ((status, id), capture) = captured(|runtime| {
        let service = ping_service(support::wired());
        answer(runtime, &service, support::plain(http::Method::PATCH, "/nowhere"))
    });
    assert_eq!(status, 501);
    let refusal = one_refusal(&capture, Level::DEBUG, "wire", &id);
    assert_eq!(refusal.field("operation"), Some("unknown"), "{refusal:?}");
}

/// Negative — a panicking handler is one `error` event naming the extension; the payload is in no
/// field, and no refusal event doubles it.
#[test]
fn a_handler_panic_is_one_error_event_without_its_payload() {
    let ((status, id), capture) = captured(|runtime| {
        let service = support::wired()
            .register::<Ping, _>(Arc::new(Panics))
            .dialect(&support::ping_dialect())
            .build()
            .expect("a complete assembly");
        answer(runtime, &service, support::plain(http::Method::POST, "/"))
    });
    assert_eq!(status, 500);
    let events = capture.named("gateway_extension_panicked");
    assert_eq!(events.len(), 1, "{:?}", capture.events());
    let panicked = &events[0];
    assert_eq!(panicked.level, Level::ERROR);
    rustfs_shaped(panicked, "extension");
    assert_eq!(panicked.field("extension"), Some("handler"));
    assert_eq!(panicked.field("suppressed"), Some("0"));
    assert_eq!(panicked.field("request_id"), Some(id.as_str()));
    assert!(capture.named("gateway_request_refused").is_empty(), "{:?}", capture.events());
    for captured in capture.events() {
        assert!(!captured.rendered().contains("wJalrXUtnFEMI"), "{captured:?}");
    }
}

/// Positive — an answered request, and a refusal the handler answered itself, emit no refusal
/// event: the gateway reports only what it refused.
#[test]
fn only_the_gateways_own_refusals_are_reported() {
    let (statuses, capture) = captured(|runtime| {
        let answered = answer(runtime, &ping_service(support::wired()), support::plain(http::Method::POST, "/"));
        let missing = support::wired()
            .register::<Ping, _>(Arc::new(MissingKey))
            .dialect(&support::ping_dialect())
            .build()
            .expect("a complete assembly");
        let refused_by_handler = answer(runtime, &missing, support::plain(http::Method::POST, "/"));
        (answered.0, refused_by_handler.0)
    });
    assert_eq!(statuses, (200, 404));
    assert!(capture.named("gateway_request_refused").is_empty(), "{:?}", capture.events());
    assert!(capture.named("gateway_extension_panicked").is_empty(), "{:?}", capture.events());
}

/// A `PutBucketVersioning` handler no test reaches: the refusal comes first.
struct Versioning;

impl rustfs_gateway::Handler<rustfs_gateway::dto::PutBucketVersioning> for Versioning {
    async fn call(
        &self,
        _request: rustfs_gateway::Req<rustfs_gateway::dto::PutBucketVersioning>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::PutBucketVersioning> {
        Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::PutBucketVersioningOutput::default()))
    }
}

/// Negative — a body the operation cannot read is one `debug` event naming the code the caller was
/// answered with.
#[test]
fn an_unreadable_body_is_one_debug_event() {
    let ((status, id), capture) = captured(|runtime| {
        let service = support::wired_at_signed_time()
            .register::<rustfs_gateway::dto::PutBucketVersioning, _>(Arc::new(Versioning))
            .build()
            .expect("a complete assembly");
        let body = b"not a versioning document";
        let request = support::signed_target_with_body_and_headers(
            http::Method::PUT,
            "/bucket?versioning",
            &[("content-md5", &crate::tagging_reachability::content_md5(body))],
            Bytes::from_static(body),
        );
        answer(runtime, &service, request)
    });
    assert_eq!(status, 400);
    let refusal = one_refusal(&capture, Level::DEBUG, "decode", &id);
    assert_eq!(refusal.field("code"), Some("MalformedXML"), "{refusal:?}");
    assert_eq!(refusal.field("operation"), Some("PutBucketVersioning"), "{refusal:?}");
}

/// Negative — a body that fails its declared digest is one `debug` event too: the body could not be
/// read into the operation's input.
#[test]
fn a_body_failing_its_digest_is_one_debug_event() {
    let ((status, id), capture) = captured(|runtime| {
        let service = support::wired_at_signed_time()
            .register::<rustfs_gateway::dto::PutBucketVersioning, _>(Arc::new(Versioning))
            .build()
            .expect("a complete assembly");
        let body = b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
        let request = support::signed_target_with_body_and_headers(
            http::Method::PUT,
            "/bucket?versioning",
            &[("content-md5", &crate::tagging_reachability::content_md5(b"another body"))],
            Bytes::from_static(body),
        );
        answer(runtime, &service, request)
    });
    assert_eq!(status, 400);
    let refusal = one_refusal(&capture, Level::DEBUG, "decode", &id);
    assert_eq!(refusal.field("code"), Some("BadDigest"), "{refusal:?}");
}

/// An authorizer whose route decision panics with deployment text.
struct PanicsOnRoute;

impl rustfs_gateway::Authorizer for PanicsOnRoute {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a rustfs_gateway::RequestContext<'a>,
        _request: &'a rustfs_gateway::AuthzRequest<'a>,
    ) -> rustfs_gateway::BoxFuture<'a, rustfs_gateway::Decision> {
        Box::pin(async { std::panic::panic_any(PANIC_PAYLOAD.to_owned()) })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a rustfs_gateway::RequestContext<'a>,
        request: &'a rustfs_gateway::InputAuthzRequest<'a>,
    ) -> rustfs_gateway::BoxFuture<'a, rustfs_gateway::InputDecisions> {
        let decisions = request.decide_all(rustfs_gateway::Decision::Allow, |_| rustfs_gateway::Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// Negative — a panicking authorizer is one `error` event naming the extension, answered `500`;
/// the payload is in no field, and no refusal event doubles it.
#[test]
fn an_authorizer_panic_is_one_error_event_without_its_payload() {
    let ((status, id), capture) = captured(|runtime| {
        let service = ping_service(support::wired().authorizer(PanicsOnRoute));
        answer(runtime, &service, support::plain(http::Method::POST, "/"))
    });
    assert_eq!(status, 500);
    let events = capture.named("gateway_extension_panicked");
    assert_eq!(events.len(), 1, "{:?}", capture.events());
    let panicked = &events[0];
    assert_eq!(panicked.level, Level::ERROR);
    rustfs_shaped(panicked, "extension");
    assert_eq!(panicked.field("extension"), Some("authorizer"));
    assert_eq!(panicked.field("suppressed"), Some("0"));
    assert_eq!(panicked.field("request_id"), Some(id.as_str()));
    assert!(capture.named("gateway_request_refused").is_empty(), "{:?}", capture.events());
    for captured in capture.events() {
        assert!(!captured.rendered().contains("wJalrXUtnFEMI"), "{captured:?}");
    }
}

/// Every decision the audit sink was handed, by action.
#[derive(Clone, Default)]
struct Decisions(Arc<Mutex<Vec<(String, rustfs_gateway::Decision)>>>);

impl rustfs_gateway::AuthzAuditSink for Decisions {
    fn on_decision(&self, event: &rustfs_gateway::AuthzAuditEvent<'_>) {
        self.0
            .lock()
            .expect("not poisoned")
            .push((event.action.to_owned(), event.decision));
    }
}

/// Positive — the `s3:ListBucket` visibility check refuses nothing on its own: a caller allowed to
/// read an object and not to list its bucket is answered, the audit sink sees the denied check,
/// and no refusal is reported.
#[test]
fn a_denied_visibility_check_is_audited_and_not_reported() {
    let decisions = Decisions::default();
    let ((status, _), capture) = captured(|runtime| {
        let service = support::wired_at_signed_time()
            .authorizer(rustfs_gateway::decide_with(|request| {
                if request.action == "s3:ListBucket" {
                    rustfs_gateway::Decision::Deny
                } else {
                    rustfs_gateway::Decision::Allow
                }
            }))
            .authz_audit(decisions.clone())
            .register::<rustfs_gateway::dto::GetObject, _>(Arc::new(Present))
            .build()
            .expect("a complete assembly");
        answer(runtime, &service, support::signed(http::Method::GET, "/bucket/key"))
    });
    assert_eq!(status, 200);
    let audited = decisions.0.lock().expect("not poisoned").clone();
    assert!(
        audited.contains(&("s3:ListBucket".to_owned(), rustfs_gateway::Decision::Deny)),
        "{audited:?}"
    );
    assert!(capture.named("gateway_request_refused").is_empty(), "{:?}", capture.events());
}

/// A `PutObject` handler that refuses without reading the body, as a backend refuses a write whose
/// precondition fails.
struct Precondition;

impl rustfs_gateway::Handler<rustfs_gateway::dto::PutObject> for Precondition {
    async fn call(
        &self,
        _request: rustfs_gateway::Req<rustfs_gateway::dto::PutObject>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::PutObject> {
        Err(rustfs_gateway::HandlerError::precondition_failed("If-Match"))
    }
}

/// Positive — a handler's refusal over a body it never read is the handler's answer, not a refusal
/// of the gateway's, although it leaves the body stage: no refusal event.
#[test]
fn a_handler_refusal_over_an_unread_body_is_not_reported() {
    let (status, capture) = captured(|runtime| {
        let service = support::wired_at_signed_time()
            .register::<rustfs_gateway::dto::PutObject, _>(Arc::new(Precondition))
            .build()
            .expect("a complete assembly");
        let body = Bytes::from_static(b"a body the handler never reads");
        let length = body.len().to_string();
        let request = support::signed_target_with_body_and_headers(
            http::Method::PUT,
            "/bucket/key",
            &[("content-length", length.as_str())],
            body,
        );
        answer(runtime, &service, request).0
    });
    assert_eq!(status, 412);
    assert!(capture.named("gateway_request_refused").is_empty(), "{:?}", capture.events());
}
