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

//! SEC-1 action-specific credential and declared-request signing controls.
//!
//! Responsible for: actual service refusals and handler calls for ordinary AssumeRole,
//! preservation of Web Identity's downstream decision, and SigV2 resource selection on
//! form-claimed and ordinary S3 routes.
//! NOT responsible for: token verification or the legacy comparison (`super`).
//! Upstream: the generated STS codec, facade pipeline, and `super`'s independent signers.
//! Downstream: nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

use http::HeaderValue;
use rustfs_gateway::dto::{HeadObject, HeadObjectOutput};
use rustfs_gateway::{HandlerError, StageFilter, WireHead};
use rustfs_gateway_sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};
use rustfs_gateway_types::ErrorCode;

use super::*;

const WEB_IDENTITY: &[u8] = b"Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=fixture";

fn denied(sent: Sent) {
    let now = RequestNow::capture();
    let (answer, _) = gateway_answer(&sent.request(now), now);
    assert_eq!(answer.status, 403);
    assert_eq!(answer.code.as_deref(), Some("AccessDenied"));
    assert!(answer.handed.is_none(), "a refused ordinary action must not reach its handler");
}

/// Negative — a valid SigV4 query credential is not an ordinary-action header credential.
#[test]
fn sec1_09() {
    for service in [SigService::Sts, SigService::S3] {
        denied(Sent::new(Signing::Presigned {
            service,
            secret: SECRET_KEY,
        }));
    }
}

/// Negative — a valid SigV2 query credential is refused before the ordinary handler.
#[test]
fn sec1_10() {
    denied(Sent::new(Signing::V2Presigned));
}

/// Negative — an anonymous ordinary action is refused before the handler.
#[test]
fn sec1_11() {
    denied(Sent::new(Signing::Anonymous));
}

/// Negative — form decoding cannot change which ordinary-action contract is enforced.
#[test]
fn sec1_12() {
    denied(Sent::new(Signing::Anonymous).body(Bytes::from_static(b"%41ction=Assume%52ole&Version=2011-06-15")));
}

/// Negative — conflicting actions are refused in either order, including encoded keys.
#[test]
fn sec1_13() {
    for body in [
        &b"Action=AssumeRoleWithWebIdentity&Action=AssumeRole"[..],
        &b"Action=AssumeRole&Action=AssumeRoleWithWebIdentity"[..],
        &b"Action=AssumeRoleWithWebIdentity&%41ction=AssumeRole"[..],
    ] {
        let now = RequestNow::capture();
        let request = Sent::new(Signing::Anonymous).body(Bytes::from_static(body)).request(now);
        let (answer, _) = gateway_answer(&request, now);
        assert_eq!(answer.status, 400);
        assert_eq!(answer.code.as_deref(), Some("InvalidRequest"));
        assert!(answer.handed.is_none());
    }
}

/// Positive — verified SigV4 and SigV2 header modes retain the caller and exact form bytes.
#[test]
fn sec1_14() {
    for signing in [
        Signing::Header {
            service: "sts",
            send_digest: false,
            secret: SECRET_KEY,
        },
        Signing::Header {
            service: "s3",
            send_digest: true,
            secret: SECRET_KEY,
        },
        Signing::V2Header { secret: SECRET_KEY },
    ] {
        let now = RequestNow::capture();
        let sent = Sent::new(signing);
        let (answer, _) = gateway_answer(&sent.request(now), now);
        assert_eq!(answer.status, 200);
        assert!(
            answer.handed == handed(Some(ACCESS_KEY), &sent),
            "the handler retains its caller and form"
        );
    }
}

/// Positive — Web Identity retains its independent action contract and exact token bytes.
#[test]
fn sec1_15() {
    for signing in [
        Signing::Anonymous,
        Signing::Presigned {
            service: SigService::Sts,
            secret: SECRET_KEY,
        },
        Signing::V2Presigned,
    ] {
        let now = RequestNow::capture();
        let sent = Sent::new(signing).body(Bytes::from_static(WEB_IDENTITY));
        let (answer, _) = gateway_answer(&sent.request(now), now);
        assert_eq!(answer.status, 200);
        let caller = if matches!(signing, Signing::Anonymous) {
            None
        } else {
            Some(ACCESS_KEY)
        };
        assert!(
            answer.handed == handed(caller, &sent),
            "the handler retains the independent action contract"
        );
    }
}

/// Re-sign the actual request, independently selecting the SigV2 canonical-resource bucket.
fn sign_v2(request: &mut Request<Bytes>, bucket: Option<&str>) {
    request.headers_mut().remove(http::header::AUTHORIZATION);
    let query = RawQuery::new(request.uri().query().unwrap_or_default());
    let spec = SigV2StringToSignSpec::new(
        SigV2Mode::HeaderAuth,
        request.method(),
        request.uri().path(),
        &query,
        request.headers(),
        bucket,
    );
    let authorization = SigV2Signer::new(ACCESS_KEY, SECRET_KEY.as_bytes())
        .expect("a fixture signer")
        .authorization(&spec)
        .expect("a signable fixture");
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&authorization).expect("a header credential"),
    );
}

/// Negative — a form-claimed request does not authenticate a host-derived bucket resource.
#[test]
fn sec1_16() {
    let now = RequestNow::capture();
    let request = Sent::new(Signing::V2Header { secret: SECRET_KEY })
        .host("photos.example.test")
        .request(now);
    let (answer, _) = gateway_answer(&request, now);
    assert_eq!(answer.status, 403);
    assert_eq!(answer.code.as_deref(), Some("SignatureDoesNotMatch"));
    assert!(answer.handed.is_none());
}

/// Positive — the same claimed request authenticates its service-level canonical resource.
#[test]
fn sec1_17() {
    let now = RequestNow::capture();
    let sent = Sent::new(Signing::V2Header { secret: SECRET_KEY }).host("photos.example.test");
    let mut request = sent.request(now);
    sign_v2(&mut request, None);
    let (answer, _) = gateway_answer(&request, now);
    assert_eq!(answer.status, 200);
    assert!(
        answer.handed == handed(Some(ACCESS_KEY), &sent),
        "the handler retains its caller and form"
    );
}

struct ObjectHandler(Arc<AtomicUsize>);

impl Handler<HeadObject> for ObjectHandler {
    async fn call(&self, _request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(HeadObjectOutput::default()))
    }
}

struct ObjectAuthorizer;

impl Authorizer for ObjectAuthorizer {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = if request.action == "s3:GetObject" {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decision = if request.route().action == "s3:GetObject" {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Box::pin(async move { request.decide_all(decision, |_| Decision::Allow) })
    }
}

fn ordinary_s3(bucket: Option<&str>) -> (u16, usize) {
    let now = RequestNow::capture();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = gateway_builder(now, &Arc::new(Mutex::new(Vec::new())))
        .authorizer(ObjectAuthorizer)
        .register::<HeadObject, _>(Arc::new(ObjectHandler(Arc::clone(&calls))))
        .build()
        .expect("an ordinary S3 assembly");
    let mut request = Sent::new(Signing::V2Header { secret: SECRET_KEY })
        .host("photos.example.test")
        .path("/object")
        .content_type(None)
        .body(Bytes::new())
        .request(now);
    *request.method_mut() = Method::HEAD;
    sign_v2(&mut request, bucket);
    let response = block_on(service.call_bytes(request));
    let response = block_on(rustfs_gateway::collect(response)).expect("an in-memory response");
    (response.status().as_u16(), calls.load(Ordering::SeqCst))
}

/// Negative — ordinary S3 still requires its virtual-host bucket in the canonical resource.
#[test]
fn sec1_18() {
    assert_eq!(ordinary_s3(None), (403, 0));
}

/// Positive — ordinary S3 keeps its successful virtual-host signature and handler invocation.
#[test]
fn sec1_19() {
    assert_eq!(ordinary_s3(Some("photos")), (200, 1));
}

struct RefuseWebIdentity(Arc<AtomicUsize>);

impl Handler<StsFormPost> for RefuseWebIdentity {
    async fn call(&self, request: Req<StsFormPost>) -> HandlerResult<StsFormPost> {
        assert!(request.context().principal().is_none());
        assert!(
            request.input().as_ref() == WEB_IDENTITY,
            "the downstream validator receives the unchanged form"
        );
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(HandlerError::new(ErrorCode::ACCESS_DENIED, "Web Identity validation refused"))
    }
}

/// Negative — accepting Web Identity's form never overrides a downstream validation refusal.
#[test]
fn sec1_20() {
    let now = RequestNow::capture();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = gateway_builder(now, &Arc::new(Mutex::new(Vec::new())))
        .register::<StsFormPost, _>(Arc::new(RefuseWebIdentity(Arc::clone(&calls))))
        .build()
        .expect("a downstream-refusal assembly");
    let request = Sent::new(Signing::Anonymous)
        .body(Bytes::from_static(WEB_IDENTITY))
        .request(now);
    let response = block_on(service.call_bytes(request));
    let response = block_on(rustfs_gateway::collect(response)).expect("an in-memory response");
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(
        element(std::str::from_utf8(response.body()).expect("XML"), "Code").as_deref(),
        Some("AccessDenied")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the downstream validator must make this decision");
}

/// Negative — only the form body chooses the action-specific contract.
#[test]
fn sec1_21() {
    denied(Sent::new(Signing::Anonymous).query("Action=AssumeRoleWithWebIdentity"));
}

/// Negative — Web Identity does not turn an invalid presented header into an anonymous request.
#[test]
fn sec1_22() {
    let now = RequestNow::capture();
    let request = Sent::new(Signing::Header {
        service: "sts",
        send_digest: false,
        secret: FORGED,
    })
    .body(Bytes::from_static(WEB_IDENTITY))
    .request(now);
    let (answer, _) = gateway_answer(&request, now);
    assert_eq!(answer.status, 403);
    assert!(answer.handed.is_none());
}

/// Negative — an Authorization field alone is never an authenticated ordinary request.
#[test]
fn sec1_23() {
    for authorization in ["", "not-an-authorization", "AWS4-HMAC-SHA256 incomplete"] {
        let now = RequestNow::capture();
        let mut request = Sent::new(Signing::Anonymous).request(now);
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, HeaderValue::from_static(authorization));
        let (answer, _) = gateway_answer(&request, now);
        assert!((400..500).contains(&answer.status), "an unreadable credential must be refused");
        assert!(answer.handed.is_none(), "an unreadable credential must not reach the handler");
    }
}

/// Rewrites only the codec-facing header; authentication must retain the original snapshot.
struct RewriteAuthorization(bool);

impl StageFilter for RewriteAuthorization {
    fn on_wire(&self, head: &mut WireHead<'_>) -> Result<(), HandlerError> {
        if self.0 {
            head.set_header(http::header::AUTHORIZATION, HeaderValue::from_static("AWS fixture:fixture"))
                .expect("Authorization is intentionally mutable at the wire seam");
        } else {
            head.remove_header(&http::header::AUTHORIZATION)
                .expect("Authorization is intentionally mutable at the wire seam");
        }
        Ok(())
    }
}

fn filtered_answer(sent: &Sent, inject: bool) -> Answered {
    let now = RequestNow::capture();
    let handed = Arc::new(Mutex::new(None));
    let service = gateway_builder(now, &Arc::new(Mutex::new(Vec::new())))
        .stage_filter(RewriteAuthorization(inject))
        .register::<StsFormPost, _>(Arc::new(Sts {
            handed: Arc::clone(&handed),
        }))
        .build()
        .expect("a filtered STS assembly");
    let response = block_on(service.call_bytes(sent.request(now)));
    let response = block_on(rustfs_gateway::collect(response)).expect("an in-memory response");
    let handed = handed.lock().expect("uncontended").take();
    answered(response.status().as_u16(), false, response.body(), handed)
}

fn filter_cannot_supply_header(signing: Signing) {
    let answer = filtered_answer(&Sent::new(signing), true);
    assert_eq!(answer.status, 403);
    assert_eq!(answer.code.as_deref(), Some("AccessDenied"));
    assert!(answer.handed.is_none(), "a wire filter must not supply the authenticated location");
}

/// Negative — an injected header cannot authenticate the anonymous ordinary action.
#[test]
fn sec1_24_anonymous() {
    filter_cannot_supply_header(Signing::Anonymous);
}

/// Negative — an injected header cannot change the authenticated SigV4 credential location.
#[test]
fn sec1_24_v4_query() {
    filter_cannot_supply_header(Signing::Presigned {
        service: SigService::Sts,
        secret: SECRET_KEY,
    });
}

/// Negative — an injected header cannot change the authenticated SigV2 credential location.
#[test]
fn sec1_24_v2_query() {
    filter_cannot_supply_header(Signing::V2Presigned);
}

fn filter_cannot_erase_header(signing: Signing) {
    let sent = Sent::new(signing);
    let answer = filtered_answer(&sent, false);
    assert_eq!(answer.status, 200);
    assert!(
        answer.handed == handed(Some(ACCESS_KEY), &sent),
        "verified identity and form remain intact"
    );
}

/// Positive — removing the displayed header cannot erase verified SigV4 authentication.
#[test]
fn sec1_25_v4_header() {
    filter_cannot_erase_header(Signing::Header {
        service: "sts",
        send_digest: false,
        secret: SECRET_KEY,
    });
}

/// Positive — removing the displayed header cannot erase verified SigV2 authentication.
#[test]
fn sec1_25_v2_header() {
    filter_cannot_erase_header(Signing::V2Header { secret: SECRET_KEY });
}
