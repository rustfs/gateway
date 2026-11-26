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

//! Handler panic isolation at the assembled service boundary.
//!
//! Responsible for: proving a panicking handler becomes a `500` and cannot poison the service for
//! the following request.
//! NOT responsible for: authorizer and credential-provider panics, which their own suites cover.
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::panic)]

#[path = "handler_panic/host.rs"]
mod panicking_host;
use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{Handler, HandlerResult, Req, Resp};
use support::{Ping, PingOutput, exchange, plain, wired};

struct PanicsOnce {
    calls: AtomicUsize,
}

impl Handler<Ping> for PanicsOnce {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("handler panic fixture");
        }
        Ok(Resp::new(PingOutput {
            message: "recovered".to_owned(),
        }))
    }

    async fn call_with_context(&self, _request: Req<Ping>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("handler panic fixture");
        }
        Ok(Resp::new(PingOutput {
            message: "recovered".to_owned(),
        }))
    }
}

/// a-asm-0019. A handler panic is rendered as a protocol response and the same service remains
/// usable for the next request.
#[tokio::test]
async fn a_handler_panic_is_a_500_and_the_next_request_still_runs() {
    let service = wired()
        .register::<Ping, _>(Arc::new(PanicsOnce {
            calls: AtomicUsize::new(0),
        }))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let first = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(first.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", first.1);

    let second = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(second.0, http::StatusCode::OK, "{}", second.1);
    assert!(second.1.contains("recovered"), "{}", second.1);
}

/// c-mw-0022. A panic inside an `OpLayer` is contained where a handler panic is: the request is a
/// `500`, and the same service answers the next request through the same layer.
#[tokio::test]
async fn an_op_layer_panic_is_a_500_and_the_next_request_still_runs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let layer_calls = Arc::clone(&calls);
    let service = wired()
        .register::<Ping, _>(Arc::new(support::Backend))
        .op_layer::<Ping, _>(rustfs_gateway::op_layer(
            move |request: Req<Ping>, next: rustfs_gateway::Next<'_, Ping>| {
                let first = layer_calls.fetch_add(1, Ordering::SeqCst) == 0;
                Box::pin(async move {
                    if first {
                        panic!("op layer panic fixture");
                    }
                    next.run(request).await
                }) as rustfs_gateway::BoxFuture<'_, HandlerResult<Ping>>
            },
        ))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let first = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(first.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", first.1);

    let second = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(second, (http::StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the second request did not pass through the layer");
}

/// Negative — a `PolicySource::snapshot` panic (both synchronous construction and async poll)
/// is contained as 500 fail-closed, audits `Decision::Indeterminate`, never runs the handler,
/// and leaves the service usable for subsequent requests.
#[tokio::test]
async fn n_policy_source_sync_and_async_panics_are_500_fail_closed_and_next_request_runs() {
    use rustfs_gateway::{AuthzAuditEvent, AuthzAuditSink, BoxFuture, Decision, PolicyError, PolicySnapshot, PolicySource};
    use std::sync::Mutex;

    struct PanickingPolicySource {
        calls: AtomicUsize,
    }

    impl PolicySource for PanickingPolicySource {
        fn snapshot<'a>(
            &'a self,
            _identity: Option<&'a rustfs_gateway::sig::Identity>,
        ) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("sync policy_source panic fixture"),
                1 => Box::pin(async { panic!("async policy_source panic fixture") }),
                _ => Box::pin(async { Ok(PolicySnapshot::empty()) }),
            }
        }
    }

    struct AuditRecorder(Arc<Mutex<Vec<Decision>>>);

    impl AuthzAuditSink for AuditRecorder {
        fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
            self.0.lock().expect("not poisoned").push(event.decision);
        }
    }

    let reached = Arc::new(AtomicUsize::new(0));
    let audited = Arc::new(Mutex::new(Vec::new()));
    let service = wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&reached)))
        .dialect(&crate::support::ping_dialect())
        .policy_source(PanickingPolicySource {
            calls: AtomicUsize::new(0),
        })
        .authz_audit(AuditRecorder(Arc::clone(&audited)))
        .build()
        .expect("complete assembly");

    let first = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(first.0, http::StatusCode::INTERNAL_SERVER_ERROR, "sync panic: {}", first.1);
    assert!(!first.1.contains("sync policy_source panic fixture"), "must not leak panic text");

    let second = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(second.0, http::StatusCode::INTERNAL_SERVER_ERROR, "async panic: {}", second.1);
    assert!(!second.1.contains("async policy_source panic fixture"), "must not leak panic text");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "handler must not run when policy_source panics");
    assert_eq!(
        *audited.lock().expect("not poisoned"),
        vec![Decision::Indeterminate, Decision::Indeterminate],
        "both sync and async PolicySource::snapshot panics must audit Decision::Indeterminate"
    );

    let third = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(third.0, http::StatusCode::OK, "recovery: {}", third.1);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Negative — panics in `StageFilter::on_wire`, `on_routed`, and `on_response` each return 500
/// without unwinding and leave the service usable for subsequent requests.
#[tokio::test]
async fn n_stage_filter_wire_routed_and_response_panics_are_500_and_next_request_runs() {
    use rustfs_gateway::{Body, HandlerError, ResponseView, RoutedView, StageFilter, WireHead};

    struct PanickingFilter {
        step: AtomicUsize,
    }

    impl StageFilter for PanickingFilter {
        fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), HandlerError> {
            if self.step.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("on_wire panic fixture");
            }
            Ok(())
        }

        fn on_routed(&self, _routed: &RoutedView<'_>) -> Result<(), HandlerError> {
            if self.step.load(Ordering::SeqCst) == 2 {
                panic!("on_routed panic fixture");
            }
            Ok(())
        }

        fn on_response(&self, _view: &ResponseView<'_>, _response: &mut http::Response<Body>) -> Result<(), HandlerError> {
            if self.step.load(Ordering::SeqCst) == 3 {
                panic!("on_response panic fixture");
            }
            Ok(())
        }
    }

    let service = wired()
        .register::<Ping, _>(Arc::new(support::Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(PanickingFilter {
            step: AtomicUsize::new(0),
        })
        .build()
        .expect("complete assembly");

    // Request 1: panics in on_wire (step 0 -> 1).
    let wire_panic = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(wire_panic.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", wire_panic.1);
    assert!(!wire_panic.1.contains("on_wire panic fixture"));

    // Request 2: panics in on_routed (step 1 -> 2).
    let routed_panic = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(routed_panic.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", routed_panic.1);
    assert!(!routed_panic.1.contains("on_routed panic fixture"));

    // Request 3: panics in on_response (step 2 -> 3).
    let resp_panic = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(resp_panic.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", resp_panic.1);
    assert!(!resp_panic.1.contains("on_response panic fixture"));

    // Request 4: succeeds cleanly (step 3 -> 4).
    let ok = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(ok, (http::StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
}

/// Negative — panics in `HostResolver::resolve`, `signing_bucket`, and `refusal` are contained as
/// 500 without unwinding, and subsequent requests recover.
#[tokio::test]
async fn n_host_resolver_panics_are_500_and_next_request_runs() {
    let service = wired()
        .register::<Ping, _>(Arc::new(support::Backend))
        .dialect(&crate::support::ping_dialect())
        .host_resolver(panicking_host::PanickingResolver::new())
        .build()
        .expect("complete assembly");

    for label in ["resolve", "signing_bucket", "refusal"] {
        let resp = exchange(&service, plain(http::Method::POST, "/")).await;
        assert_eq!(
            resp.0,
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "host resolver {label} panic must return 500: {}",
            resp.1
        );
        assert!(!resp.1.contains("panic fixture"));
    }

    let ok = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(ok, (http::StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
}

/// Negative — panics in `Authenticator::authenticate` (SigV4, sync & async) and
/// `Authenticator::authenticate_sigv2` (sync & async) return 500 fail-closed without reaching handler.
#[tokio::test]
async fn n_authenticator_sigv4_and_sigv2_panics_are_500_fail_closed() {
    use rustfs_gateway::sig::{AuthError, Verdict};
    use rustfs_gateway::{Authentication, AuthenticationOutcome, Authenticator, BoxFuture, SigV2Authentication, Unavailable};

    struct PanickingAuthenticator {
        v4_calls: AtomicUsize,
        v2_calls: AtomicUsize,
    }

    impl Authenticator for PanickingAuthenticator {
        fn authenticate<'a>(
            &'a self,
            _request: &'a Authentication<'a>,
        ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
            match self.v4_calls.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("sigv4 sync auth panic fixture"),
                1 => Box::pin(async { panic!("sigv4 async auth panic fixture") }),
                _ => Box::pin(async { Ok(AuthenticationOutcome::ordinary(Verdict::reject(AuthError::AccessDenied))) }),
            }
        }

        fn authenticate_sigv2<'a>(
            &'a self,
            _request: &'a SigV2Authentication<'a>,
        ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
            match self.v2_calls.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("sigv2 sync auth panic fixture"),
                1 => Box::pin(async { panic!("sigv2 async auth panic fixture") }),
                _ => Box::pin(async { Ok(AuthenticationOutcome::ordinary(Verdict::reject(AuthError::AccessDenied))) }),
            }
        }
    }

    let reached = Arc::new(AtomicUsize::new(0));
    let service = support::wired_at_signed_time()
        .security_floor(
            rustfs_gateway::SecurityFloor::new().with_sigv2_policy(rustfs_gateway_sig::sig_v2::SigV2Policy::HeaderAndPresigned),
        )
        .authenticator(PanickingAuthenticator {
            v4_calls: AtomicUsize::new(0),
            v2_calls: AtomicUsize::new(0),
        })
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&reached)))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("complete assembly");

    // SigV4 sync + async panics.
    for label in ["v4-sync", "v4-async"] {
        let resp = exchange(&service, support::signed(http::Method::POST, "/")).await;
        assert_eq!(resp.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{label}: {}", resp.1);
        assert!(!resp.1.contains("panic fixture"));
    }

    // SigV2 sync + async panics.
    let sigv2_req = || {
        http::Request::builder()
            .method(http::Method::POST)
            .uri("/")
            .header(http::header::HOST, "s3.example.test")
            .header(http::header::DATE, "Fri, 02 Jan 2026 03:04:05 GMT")
            .header(http::header::AUTHORIZATION, "AWS AKIAIOSFODNN7EXAMPLE:AAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .body(bytes::Bytes::new())
            .expect("sigv2 request")
    };
    for label in ["v2-sync", "v2-async"] {
        let resp = exchange(&service, sigv2_req()).await;
        assert_eq!(resp.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{label}: {}", resp.1);
        assert!(!resp.1.contains("panic fixture"));
    }
    assert_eq!(reached.load(Ordering::SeqCst), 0, "handler must never run on authenticator panic");

    // Recovery: third SigV4 call runs cleanly and returns 403.
    let after = exchange(&service, support::signed(http::Method::POST, "/")).await;
    assert_eq!(after.0, http::StatusCode::FORBIDDEN, "{}", after.1);
}

/// Negative — a panic inside `CustomSignatureVerifier::verify` is contained as 500 fail-closed
/// without reaching the handler, and subsequent requests recover.
#[tokio::test]
async fn n_custom_signature_verifier_panic_is_500_fail_closed() {
    use rustfs_gateway::sig::{AuthError, CustomAuthRequest, CustomAuthScheme, CustomSchemeRegistry, SignatureVerifier, Verdict};

    struct PanickingCustomVerifier {
        calls: AtomicUsize,
    }

    impl SignatureVerifier for PanickingCustomVerifier {
        fn verify(&self, _request: &CustomAuthRequest<'_>) -> Verdict {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("custom verifier panic fixture");
            }
            Verdict::reject(AuthError::AccessDenied)
        }
    }

    let mut registry = CustomSchemeRegistry::new();
    registry
        .register(CustomAuthScheme::new("x-vendor-auth-").expect("custom scheme"))
        .expect("unique");
    let reached = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .security_floor(rustfs_gateway::SecurityFloor::new().with_custom_schemes(registry))
        .custom_signature_verifier(PanickingCustomVerifier {
            calls: AtomicUsize::new(0),
        })
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&reached)))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("complete assembly");

    let custom_req = || {
        http::Request::builder()
            .method(http::Method::POST)
            .uri("/")
            .header(http::header::HOST, "s3.example.test")
            .header("x-vendor-auth-token", "opaque")
            .body(bytes::Bytes::new())
            .expect("custom request")
    };
    let first = exchange(&service, custom_req()).await;
    assert_eq!(first.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", first.1);
    assert!(!first.1.contains("custom verifier panic fixture"));
    assert_eq!(reached.load(Ordering::SeqCst), 0);

    let second = exchange(&service, custom_req()).await;
    assert_eq!(second.0, http::StatusCode::FORBIDDEN, "{}", second.1);
}

/// Negative — synchronous and asynchronous panics inside `Authenticator::authenticate_sigv2` and
/// `Authenticator::authenticate` on an unrouted RustFS object-path `POST /bucket/key` multipart
/// form (`service/refused_post.rs`) must be contained as `500 InternalError` without unwinding or
/// leaking panic text, and subsequent requests must recover.
#[tokio::test]
async fn n_unrouted_object_post_form_authenticator_sigv4_and_sigv2_panics_are_500_fail_closed() {
    use rustfs_gateway::sig::{AuthError, Verdict};
    use rustfs_gateway::{Authentication, AuthenticationOutcome, Authenticator, BoxFuture, SigV2Authentication, Unavailable};

    struct PanickingFormAuthenticator {
        v4_calls: AtomicUsize,
        v2_calls: AtomicUsize,
    }

    impl Authenticator for PanickingFormAuthenticator {
        fn authenticate<'a>(
            &'a self,
            _request: &'a Authentication<'a>,
        ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
            match self.v4_calls.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("unrouted form sigv4 sync panic fixture"),
                1 => Box::pin(async { panic!("unrouted form sigv4 async panic fixture") }),
                _ => Box::pin(async { Ok(AuthenticationOutcome::ordinary(Verdict::reject(AuthError::AccessDenied))) }),
            }
        }

        fn authenticate_sigv2<'a>(
            &'a self,
            _request: &'a SigV2Authentication<'a>,
        ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
            match self.v2_calls.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("unrouted form sigv2 sync panic fixture"),
                1 => Box::pin(async { panic!("unrouted form sigv2 async panic fixture") }),
                _ => Box::pin(async { Ok(AuthenticationOutcome::ordinary(Verdict::reject(AuthError::AccessDenied))) }),
            }
        }
    }

    let reached = Arc::new(AtomicUsize::new(0));
    let service = support::wired_at_signed_time()
        .security_floor(
            rustfs_gateway::SecurityFloor::new()
                .enable_sigv2_presigned_compatibility()
                .recognize_signatures_as_legacy_rustfs(),
        )
        .select_operations_as_legacy_rustfs()
        .legacy_rustfs_post_forms()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&reached)))
        .dialect(&crate::support::ping_dialect())
        .authenticator(PanickingFormAuthenticator {
            v4_calls: AtomicUsize::new(0),
            v2_calls: AtomicUsize::new(0),
        })
        .build()
        .expect("complete legacy-form assembly");

    let build_form_request = |fields: &[(&str, &str)]| {
        let mut body = String::new();
        for (name, value) in fields {
            body.push_str(&format!("--form\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        body.push_str("--form\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhello\r\n--form--\r\n");
        let bytes = bytes::Bytes::from(body);
        http::Request::builder()
            .method(http::Method::POST)
            .uri("/bkt/obj")
            .header(http::header::HOST, "s3.example.test")
            .header(http::header::CONTENT_TYPE, "multipart/form-data; boundary=form")
            .header(http::header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
            .expect("valid multipart request")
    };

    let sigv4_fields = [
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20260102T030405Z"),
        (
            "policy",
            "eyJleHBpcmF0aW9uIjogIjIwOTktMDEtMDFUMDA6MDA6MDBaIiwgImNvbmRpdGlvbnMiOiBbeyJ4LWFtei1kYXRlIjogIjIwMjYwMTAyVDAzMDQwNVoifSwgeyJ4LWFtei1jcmVkZW50aWFsIjogIkFLSURFWEFNUExFLzIwMjYwMTAyL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QifSwgeyJ4LWFtei1hbGdvcml0aG0iOiAiQVdTNC1ITUFDLVNIQTI1NiJ9XX0=",
        ),
        ("x-amz-signature", "0000000000000000000000000000000000000000000000000000000000000000"),
    ];
    let sigv2_fields = [
        ("key", "upload"),
        ("AWSAccessKeyId", "AKIDEXAMPLE"),
        ("policy", "eyJleHBpcmF0aW9uIjogIjIwOTktMDEtMDFUMDA6MDA6MDBaIiwgImNvbmRpdGlvbnMiOiBbXX0="),
        ("signature", "2ZkeVZV3N4SN7bWn9jlgrNF9b5A="),
    ];

    for label in ["unrouted-v4-sync", "unrouted-v4-async"] {
        let resp = exchange(&service, build_form_request(&sigv4_fields)).await;
        assert_eq!(resp.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{label}: {}", resp.1);
        assert!(resp.1.contains("<Code>InternalError</Code>"), "{label}: {}", resp.1);
        assert!(!resp.1.contains("panic fixture"), "{label}: {}", resp.1);
    }
    let after_v4 = exchange(&service, build_form_request(&sigv4_fields)).await;
    assert_eq!(after_v4.0, http::StatusCode::FORBIDDEN, "v4 recovery: {}", after_v4.1);

    for label in ["unrouted-v2-sync", "unrouted-v2-async"] {
        let resp = exchange(&service, build_form_request(&sigv2_fields)).await;
        assert_eq!(resp.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{label}: {}", resp.1);
        assert!(resp.1.contains("<Code>InternalError</Code>"), "{label}: {}", resp.1);
        assert!(!resp.1.contains("panic fixture"), "{label}: {}", resp.1);
    }
    let after_v2 = exchange(&service, build_form_request(&sigv2_fields)).await;
    assert_eq!(after_v2.0, http::StatusCode::FORBIDDEN, "v2 recovery: {}", after_v2.1);
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}
