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

//! The caller's secret on RustFS's STS endpoint (rustfs/gateway#1587, ADR-0022): RustFS's
//! `AssumeRole` compares the secret that authenticated the request with a fresh IAM lookup, so
//! `rustfs:StsFormPost` opts in to the hand-off.
//!
//! Responsible for: what the STS handler holds through an assembled service whose authenticator
//! hands the secret over — the caller's own bytes when a SigV4 header signature covers the body,
//! whatever the action; nothing for `UNSIGNED-PAYLOAD`, a presigned form or SigV2, whose body the
//! signature does not cover (SigV2 also a known divergence that rustfs/gateway#1592 removes);
//! nothing for an anonymous form action; no handler at all for a query-authenticated
//! `AssumeRole`; nothing without the authenticator's hand-off — that an operation which
//! did not opt in still holds nothing in the same assembly, that the start-up posture names the
//! STS endpoint among the holders, and that no log event, error body or `Debug` rendering carries
//! the secret.
//! NOT responsible for: the legacy comparison or action admission (`super`, `super::sec1`), what
//! RustFS's handler does with the secret, or the generated opt-in itself (the dialect crate's
//! `sts_form` tests and xtask's `form_tests`).
//! Upstream: `super`'s assembly, requests and constants. Downstream: nothing.

use rustfs_gateway::dto::{CreateMultipartUpload, CreateMultipartUploadOutput};
use rustfs_gateway::{HandlerError, RequestContextView};
use rustfs_gateway_types::ErrorCode;

use super::*;
use crate::rustfs_admin_dialect::zip_token_tests::{Capture, Undecided};
use crate::rustfs_admin_proof::same_bytes;

const WEB_IDENTITY: &[u8] = b"Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=x.y.z";

/// What a handler held.
#[derive(Debug)]
struct Held {
    /// Whether the request ran as an authenticated principal.
    principal: bool,
    /// `None` when no secret was handed over; otherwise whether it is the caller's own, non-empty.
    secret: Option<bool>,
    /// The request's `Debug` rendering.
    debug: String,
}

fn held(context: &RequestContextView, debug: String) -> Held {
    let principal = context.principal();
    Held {
        principal: principal.is_some(),
        secret: principal
            .and_then(|principal| principal.secret_key_from_authenticator_lookup())
            .map(|secret| !secret.expose_secret().is_empty() && same_bytes(secret.expose_secret(), SECRET_KEY.as_bytes())),
        debug,
    }
}

/// Records what it held; the STS half answers RustFS's refusal of a rotated credential instead
/// when `refuse` is set.
struct Holder {
    held: Arc<Mutex<Option<Held>>>,
    refuse: bool,
}

impl Handler<StsFormPost> for Holder {
    async fn call(&self, request: Req<StsFormPost>) -> HandlerResult<StsFormPost> {
        *self.held.lock().expect("uncontended") = Some(held(request.context(), format!("{request:?}")));
        if self.refuse {
            // A careless handler: it logs the key it was handed and echoes it into its refusal, so
            // only the key type's own redaction keeps it out of the log and the answer.
            let key = request
                .context()
                .principal()
                .and_then(|principal| principal.secret_key_from_authenticator_lookup());
            tracing::warn!(key = ?key, "refusing a rotated credential");
            return Err(HandlerError::new(ErrorCode::INVALID_REQUEST, format!("refused for {key:?}")));
        }
        Ok(Resp::new(AdminResponse::bytes("", ANSWER.to_vec())))
    }
}

impl Handler<CreateMultipartUpload> for Holder {
    async fn call(&self, request: Req<CreateMultipartUpload>) -> HandlerResult<CreateMultipartUpload> {
        *self.held.lock().expect("uncontended") = Some(held(request.context(), String::new()));
        Ok(Resp::new(CreateMultipartUploadOutput::default()))
    }
}

/// Allows every request at both stages, so only the hand-off decides what a handler holds.
struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// The RustFS-profile assembly, its authenticator handing the secret over when `hand_off` is set,
/// with a recording STS handler and a recording handler for one standard operation.
fn assembled(now: RequestNow, hand_off: bool, refuse: bool) -> (S3Service, Arc<Mutex<Option<Held>>>) {
    let held = Arc::new(Mutex::new(None));
    let authenticator = if hand_off {
        authenticator().hand_caller_secret_to_handlers()
    } else {
        authenticator()
    };
    let service = gateway_builder_with(now, &Arc::new(Mutex::new(Vec::new())), authenticator)
        .authorizer(AllowAll)
        .register::<StsFormPost, _>(Arc::new(Holder {
            held: Arc::clone(&held),
            refuse,
        }))
        .register::<CreateMultipartUpload, _>(Arc::new(Holder {
            held: Arc::clone(&held),
            refuse,
        }))
        .build()
        .expect("a complete assembly");
    (service, held)
}

/// The status and body `sent` is answered with, and what the handler held, if it ran.
fn exchange(sent: &Sent, hand_off: bool, refuse: bool) -> (u16, String, Option<Held>) {
    let now = RequestNow::capture();
    let (service, held) = assembled(now, hand_off, refuse);
    let response = block_on(service.call_bytes(sent.request(now)));
    let response = block_on(rustfs_gateway::collect(response)).expect("an in-memory answer");
    let body = String::from_utf8_lossy(response.body()).into_owned();
    let held = held.lock().expect("uncontended").take();
    (response.status().as_u16(), body, held)
}

/// SigV4 header signatures that cover the form body: the `sts`-scoped signature over the body's own
/// digest, which the authenticator computes when no `x-amz-content-sha256` is sent, and a declared
/// digest the facade compares with the body. SigV2 is pinned apart, as a known divergence
/// (rustfs/gateway#1592).
const SIGNED: [Signing; 2] = [
    Signing::Header {
        service: "sts",
        send_digest: false,
        secret: STS_SECRET,
    },
    Signing::Header {
        service: "s3",
        send_digest: true,
        secret: STS_SECRET,
    },
];

/// Positive — a SigV4 header-signed `AssumeRole` whose signature covers its body, the body digest
/// computed by the authenticator or a declared digest, under either service, reaches the STS handler
/// with the caller's own non-empty secret.
#[test]
fn a_header_signed_assume_role_hands_its_handler_the_callers_secret() {
    for signing in SIGNED.into_iter().chain([Signing::Header {
        service: "sts",
        send_digest: true,
        secret: STS_SECRET,
    }]) {
        let (status, body, held) = exchange(&Sent::new(signing), true, false);
        assert_eq!(status, 200, "{signing:?}: {body}");
        let held = held.expect("the STS handler ran");
        assert!(held.principal, "{signing:?}");
        assert_eq!(held.secret, Some(true), "{signing:?}: the caller's own secret");
    }
}

/// KNOWN DIVERGENCE, removed by rustfs/gateway#1592 — RustFS refuses SigV2 on this route; the
/// gateway still admits a SigV2 header-signed `AssumeRole` and a SigV2-presigned Web Identity form.
/// SigV2 does not sign the form body, so neither handler holds the caller's secret, and RustFS's
/// comparison fails closed as it did before the opt-in. When #1592 refuses SigV2 on the STS form
/// floor, both requests stop before the handler and this case must be flipped to assert the
/// refusal.
#[test]
fn known_divergence_until_1592_a_sigv2_form_request_reaches_the_handler_without_the_secret() {
    for sent in [
        Sent::new(Signing::V2Header { secret: STS_SECRET }),
        Sent::new(Signing::V2Presigned).body(Bytes::from_static(WEB_IDENTITY)),
    ] {
        let (status, body, held) = exchange(&sent, true, false);
        assert_eq!(status, 200, "{sent:?}: {body}");
        let held = held.expect("today the STS handler runs");
        assert!(held.principal, "{sent:?}");
        assert_eq!(held.secret, None, "{sent:?}: SigV2 signs no body, so no secret");
    }
}

/// Positive — the opt-in is the operation's, not the action's: every request whose SigV4 header
/// signature covers its body holds the caller's own secret, whatever action the form names —
/// signed Web Identity, an unknown action, an empty form. Session credentials are not pinned: this
/// harness's store holds only a long-term key.
#[test]
fn every_form_request_with_a_signed_body_holds_the_secret_whatever_its_action() {
    let header = SIGNED[0];
    for sent in [
        Sent::new(header).body(Bytes::from_static(WEB_IDENTITY)),
        Sent::new(header).body(Bytes::from_static(b"Action=NotAnAction&Version=2011-06-15")),
        Sent::new(header).body(Bytes::new()),
    ] {
        let (status, body, held) = exchange(&sent, true, false);
        assert_eq!(status, 200, "{sent:?}: {body}");
        let held = held.expect("the STS handler ran");
        assert!(held.principal, "{sent:?}");
        assert_eq!(held.secret, Some(true), "{sent:?}");
    }
}

/// Negative — an authenticated request whose signature does not cover the body reaches the handler
/// without the secret, so RustFS's comparison fails closed as it did before the opt-in: an
/// `UNSIGNED-PAYLOAD` header-signed `AssumeRole` (its body could be rewritten under a captured
/// head) or Web Identity form, and a SigV4-presigned Web Identity form under either service.
#[test]
fn n_a_form_request_whose_body_is_not_signed_holds_no_secret() {
    for sent in [
        Sent::new(Signing::HeaderUnsigned { service: "s3" }),
        Sent::new(Signing::HeaderUnsigned { service: "sts" }),
        Sent::new(Signing::HeaderUnsigned { service: "s3" }).body(Bytes::from_static(WEB_IDENTITY)),
        Sent::new(Signing::Presigned {
            service: SigService::Sts,
            secret: STS_SECRET,
        })
        .body(Bytes::from_static(WEB_IDENTITY)),
        Sent::new(Signing::Presigned {
            service: SigService::S3,
            secret: STS_SECRET,
        })
        .body(Bytes::from_static(WEB_IDENTITY)),
    ] {
        let (status, body, held) = exchange(&sent, true, false);
        assert_eq!(status, 200, "{sent:?}: {body}");
        let held = held.expect("the STS handler ran");
        assert!(held.principal, "{sent:?}: the request still authenticated");
        assert_eq!(held.secret, None, "{sent:?}: an unsigned body earns no secret");
    }
}

/// Negative — a query-authenticated `AssumeRole`, SigV4 under either service or SigV2, is refused
/// by the codec before the handler, so the secret it authenticated with reaches no handler
/// (ADR-0044).
#[test]
fn n_a_presigned_assume_role_never_reaches_the_handler() {
    for signing in [
        Signing::Presigned {
            service: SigService::Sts,
            secret: STS_SECRET,
        },
        Signing::Presigned {
            service: SigService::S3,
            secret: STS_SECRET,
        },
        Signing::V2Presigned,
    ] {
        let (status, body, held) = exchange(&Sent::new(signing), true, false);
        assert_eq!(status, 403, "{signing:?}: {body}");
        assert!(held.is_none(), "{signing:?}");
        assert!(!body.contains(SECRET_KEY), "{signing:?}: {body}");
    }
}

/// Negative — an anonymous form action reaches the STS handler with no principal and so no
/// secret: absent, never an empty or placeholder one a comparison could accept. An anonymous
/// ordinary `AssumeRole` does not reach the handler at all (ADR-0044).
#[test]
fn n_an_anonymous_form_action_hands_its_handler_no_secret() {
    for body in [WEB_IDENTITY, b"Action=AssumeRoleWithClientGrants&Token=x.y.z", b""] {
        let sent = Sent::new(Signing::Anonymous).body(Bytes::from_static(body));
        let (status, answer, held) = exchange(&sent, true, false);
        assert_eq!(status, 200, "{answer}");
        let held = held.expect("the STS handler ran");
        assert_eq!(held.secret, None, "{body:?}: no secret, not even an empty one");
        assert!(!held.principal, "{body:?}");
    }
    let (status, _, held) = exchange(&Sent::new(Signing::Anonymous), true, false);
    assert_eq!(status, 403);
    assert!(held.is_none(), "an anonymous AssumeRole never reaches the handler");
}

/// Negative — the operation's opt-in alone hands nothing over: an authenticator that does not hand
/// the secret over leaves a header-signed `AssumeRole` without one.
#[test]
fn n_without_the_authenticators_hand_off_the_sts_handler_holds_no_secret() {
    for signing in SIGNED {
        let (status, body, held) = exchange(&Sent::new(signing), false, false);
        assert_eq!(status, 200, "{signing:?}: {body}");
        let held = held.expect("the STS handler ran");
        assert!(held.principal, "{signing:?}");
        assert_eq!(held.secret, None, "{signing:?}");
    }
}

/// Negative — in the same assembly, with the hand-off on, a standard operation that did not opt in
/// still holds no secret for a header-signed request.
#[test]
fn n_an_operation_that_did_not_opt_in_holds_no_secret() {
    let sent = Sent::new(Signing::Header {
        service: "s3",
        send_digest: true,
        secret: STS_SECRET,
    })
    .path("/photos/object")
    .query("uploads")
    .content_type(None)
    .body(Bytes::new());
    let (status, body, held) = exchange(&sent, true, false);
    assert_eq!(status, 200, "{body}");
    let held = held.expect("the CreateMultipartUpload handler ran");
    assert!(held.principal);
    assert_eq!(held.secret, None);
}

/// Negative — with the secret handed over, no log event, error body or `Debug` rendering holds
/// it: a signed `AssumeRole` served, one whose handler logs the key it holds and echoes it into its
/// refusal, and a forged signature. The forged request's refusal and the handler's own event are
/// among the captured events, and the echoed key is in the refusal, so each scan read something
/// the key reached.
#[test]
fn n_no_log_event_error_body_or_debug_holds_the_secret() {
    // Another case may have installed one first; one only has to exist.
    let _ = tracing::subscriber::set_global_default(Undecided);
    let capture = Capture::default();
    let signed = Sent::new(SIGNED[0]);
    let forged = Sent::new(Signing::Header {
        service: "sts",
        send_digest: false,
        secret: FORGED,
    });
    let (served, refused, rejected) = tracing::subscriber::with_default(capture.clone(), || {
        tracing::callsite::rebuild_interest_cache();
        (
            exchange(&signed, true, false),
            exchange(&signed, true, true),
            exchange(&forged, true, false),
        )
    });
    let held = served.2.expect("the STS handler ran");
    assert_eq!(held.secret, Some(true));
    assert!(!held.debug.contains(SECRET_KEY), "{}", held.debug);
    assert!(held.debug.contains("<redacted>"), "the secret was present and redacted: {}", held.debug);
    assert_eq!((refused.0, rejected.0), (400, 403));
    assert_eq!(refused.2.and_then(|held| held.secret), Some(true), "the refusing handler held it");
    // The handler echoed the key it held into its refusal: the answer carries the key type's
    // rendering, so the scan below reads a body the key reached.
    assert!(refused.1.contains("CallerSecretKey(&lt;redacted&gt;)"), "{}", refused.1);
    for body in [&served.1, &refused.1, &rejected.1] {
        assert!(!body.contains(SECRET_KEY), "an answer holds the secret: {body}");
    }
    let events = capture.0.lock().expect("uncontended").clone();
    assert!(events.iter().any(|event| event.contains("gateway_request_refused")), "{events:#?}");
    assert!(
        events.iter().any(|event| event.contains("CallerSecretKey(<redacted>)")),
        "the handler's log event holding the key was captured: {events:#?}"
    );
    for event in &events {
        assert!(!event.contains(SECRET_KEY), "a log event holds the secret: {event}");
    }
}

/// Positive and negative — the start-up posture lists the registered operations handed the
/// caller's secret: the STS endpoint, and not the standard operation registered beside it.
#[test]
fn the_posture_names_the_sts_endpoint_as_a_secret_holder() {
    let (service, _) = assembled(RequestNow::capture(), true, false);
    let posture = service.startup_posture();
    let line = posture
        .lines()
        .find(|line| line.starts_with("DIALECT_POSTURE "))
        .unwrap_or_else(|| panic!("no DIALECT_POSTURE line in {posture}"));
    let ops = line
        .split_once("caller_secret_ops=[")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(ops, _)| ops.split(',').collect::<Vec<_>>())
        .unwrap_or_else(|| panic!("no caller_secret_ops in {line}"));
    assert_eq!(ops, ["rustfs:StsFormPost"], "{line}");
    assert!(line.ends_with("caller_secret_scope=opted-in"), "{line}");
}
