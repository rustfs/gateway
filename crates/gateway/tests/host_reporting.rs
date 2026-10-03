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

//! A host's metrics and audit, fed from the two report hooks (rustfs/gateway#1183).
//!
//! Responsible for: that a recorder shaped like RustFS's per-request counter
//! (`rustfs_s3_http_requests_total{method, op, outcome}`) and its audit entry is fed by `Observer`
//! and `AuthzAuditSink` alone, joined by the request identifier the caller received, for an
//! answered read, a refused signature, a request naming no operation, a denied read and a committed
//! answer.
//! NOT responsible for: the hooks' own contracts (`observer_panic.rs`, `authz_contract.rs`), or the
//! facts RustFS's layers and handler code keep producing (`docs/metrics-and-audit.md`).
//! Upstream: `rustfs-gateway`, `support`. Downstream: nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rustfs_gateway::{
    AuthzAuditEvent, AuthzAuditSink, Decision, Handler, HandlerResult, Observer, Req, RequestEvent, Resp, S3Service,
    WireResponse, decide_with, dto,
};

use crate::support;

/// One audit entry, as RustFS writes one per request: what the observer says about the answer and
/// what the audit sink says about the resource, the principal and the decisions.
#[derive(Clone, Debug, Default, PartialEq)]
struct Entry {
    operation: Option<String>,
    status: u16,
    error: Option<String>,
    access_key: Option<String>,
    bucket: Option<String>,
    object: Option<String>,
    decisions: Vec<(String, String)>,
}

/// Both hooks at once: every counter increment as its label triple, in order, and the entries by
/// request identifier.
#[derive(Default)]
struct Recorder {
    counted: Mutex<Vec<(String, String, String)>>,
    entries: Mutex<BTreeMap<String, Entry>>,
}

/// The methods RustFS's counter keeps apart; any other is `OTHER`, since a caller chooses the
/// method and a label must not grow with it (rustfs/rustfs `3268c42e00`,
/// `crates/io-metrics/src/s3_http_metrics.rs:32-34`, `:130-133`).
const METHODS: [&str; 9] = ["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

fn method_label(method: &http::Method) -> &'static str {
    METHODS
        .iter()
        .find(|known| **known == method.as_str())
        .copied()
        .unwrap_or("OTHER")
}

impl Observer for Recorder {
    fn on_response(&self, event: &RequestEvent<'_>) {
        let operation = event.operation.unwrap_or("unknown").to_owned();
        let outcome = format!("{}xx", event.status / 100);
        let labels = (method_label(event.method()).to_owned(), operation, outcome);
        self.counted.lock().expect("not poisoned").push(labels);
        let mut entries = self.entries.lock().expect("not poisoned");
        let entry = entries.entry(event.request_id.as_str().to_owned()).or_default();
        entry.operation = event.operation.map(str::to_owned);
        entry.status = event.status;
        entry.error = event.error.map(|code| code.as_str().to_owned());
        entry.access_key = event.identity.map(|identity| identity.access_key_id().to_owned());
    }
}

impl AuthzAuditSink for Recorder {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        let mut entries = self.entries.lock().expect("not poisoned");
        let entry = entries.entry(event.request_id.as_str().to_owned()).or_default();
        entry.bucket = event.bucket.map(|bucket| bucket.as_str().to_owned());
        entry.object = event.key.map(|key| key.as_str().to_owned());
        entry
            .decisions
            .push((event.action.to_owned(), event.decision.as_str().to_owned()));
    }
}

/// A `GetObject` handler that finds the object.
struct Present;

impl Handler<dto::GetObject> for Present {
    async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

/// The key the authorizer refuses.
const PRIVATE: &str = "private";

/// `GetObject` behind a recorder, with an authorizer that refuses [`PRIVATE`].
fn service(recorder: &Arc<Recorder>) -> S3Service {
    support::wired_at_signed_time()
        .authorizer(decide_with(|request| {
            if request.key.map(|key| key.as_str()) == Some(PRIVATE) {
                Decision::Deny
            } else {
                Decision::Allow
            }
        }))
        .observer(Arc::clone(recorder))
        .authz_audit(Arc::clone(recorder))
        .register::<dto::GetObject, _>(Arc::new(Present))
        .build()
        .expect("a complete assembly")
}

/// The request identifier the caller received.
fn request_id(answer: &WireResponse) -> String {
    answer
        .header("x-amz-request-id")
        .expect("every answer names its request")
        .to_owned()
}

fn labels(method: &str, operation: &str, outcome: &str) -> (String, String, String) {
    (method.to_owned(), operation.to_owned(), outcome.to_owned())
}

fn counted(recorder: &Recorder) -> Vec<(String, String, String)> {
    recorder.counted.lock().expect("not poisoned").clone()
}

/// The one entry the recorder holds, which must be the caller's request.
fn only_entry(recorder: &Recorder, request_id: &str) -> Entry {
    let entries = recorder.entries.lock().expect("not poisoned");
    assert_eq!(entries.keys().collect::<Vec<_>>(), [request_id], "{entries:?}");
    entries.get(request_id).cloned().expect("the caller's request")
}

/// Positive — an answered read is counted under its method, operation and outcome, and audited
/// under the identifier the caller received: the answer from the observer, the bucket, the object,
/// the principal and every decision — the read's own two and its visibility check — from the
/// audit sink.
#[tokio::test]
async fn an_answered_read_is_counted_and_audited_under_the_callers_request_id() {
    let recorder = Arc::new(Recorder::default());
    let answer = support::exchange_wire(&service(&recorder), support::signed(http::Method::GET, "/bucket/key")).await;
    assert_eq!(answer.status(), http::StatusCode::OK);
    assert_eq!(counted(&recorder), [labels("GET", "GetObject", "2xx")]);
    let entry = only_entry(&recorder, &request_id(&answer));
    assert_eq!(entry.operation.as_deref(), Some("GetObject"));
    assert_eq!(entry.status, 200);
    assert_eq!(entry.error, None);
    assert_eq!(entry.access_key.as_deref(), Some("AKIDEXAMPLE"));
    assert_eq!((entry.bucket.as_deref(), entry.object.as_deref()), (Some("bucket"), Some("key")));
    let allow = |action: &str| (action.to_owned(), "allow".to_owned());
    assert_eq!(entry.decisions, [allow("s3:GetObject"), allow("s3:GetObject"), allow("s3:ListBucket")]);
}

/// Negative — a read whose signature fails is counted under the operation routing chose and the
/// code it was answered with, attributed to no one, and has no decision: authorization never ran.
#[tokio::test]
async fn a_refused_signature_is_counted_and_attributed_to_no_one() {
    let recorder = Arc::new(Recorder::default());
    let mut forged = support::signed(http::Method::GET, "/bucket/key");
    forged.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    let answer = support::exchange_wire(&service(&recorder), forged).await;
    assert_eq!(answer.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(counted(&recorder), [labels("GET", "GetObject", "4xx")]);
    let entry = only_entry(&recorder, &request_id(&answer));
    assert_eq!(entry.error.as_deref(), Some("SignatureDoesNotMatch"));
    assert_eq!(entry.access_key, None);
    assert!(entry.decisions.is_empty(), "{entry:?}");
    assert_eq!(entry.bucket, None);
}

/// Negative — a request that names no operation is counted as `unknown`, as RustFS counts one no
/// handler recorded, under a method label that does not grow with what the caller sent, and is
/// still audited under its identifier; two of them are two increments of one series.
#[tokio::test]
async fn a_request_naming_no_operation_is_counted_as_unknown() {
    let recorder = Arc::new(Recorder::default());
    let service = service(&recorder);
    let patch = support::exchange_wire(&service, support::plain(http::Method::PATCH, "/nowhere")).await;
    let method = http::Method::from_bytes(b"BREW").expect("an extension method");
    let brew = support::exchange_wire(&service, support::plain(method, "/nowhere")).await;
    assert_eq!(
        (patch.status(), brew.status()),
        (http::StatusCode::NOT_IMPLEMENTED, http::StatusCode::NOT_IMPLEMENTED)
    );
    assert_eq!(counted(&recorder), [labels("PATCH", "unknown", "5xx"), labels("OTHER", "unknown", "5xx")]);
    let entries = recorder.entries.lock().expect("not poisoned");
    let entry = entries.get(&request_id(&patch)).expect("the first request's entry");
    assert_eq!((entry.operation.as_deref(), entry.error.as_deref()), (None, Some("NotImplemented")));
    assert!(entries.contains_key(&request_id(&brew)), "{entries:?}");
}

/// Negative — a denied read is counted as a refusal and audited with the resource it named, the
/// principal that asked — authentication succeeded, so the event names it — and the decision that
/// refused it.
#[tokio::test]
async fn a_denied_read_is_audited_with_its_resource_and_decision() {
    let recorder = Arc::new(Recorder::default());
    let target = format!("/bucket/{PRIVATE}");
    let answer = support::exchange_wire(&service(&recorder), support::signed(http::Method::GET, &target)).await;
    assert_eq!(answer.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(counted(&recorder), [labels("GET", "GetObject", "4xx")]);
    let entry = only_entry(&recorder, &request_id(&answer));
    assert_eq!(entry.error.as_deref(), Some("AccessDenied"));
    assert_eq!(entry.access_key.as_deref(), Some("AKIDEXAMPLE"));
    assert_eq!((entry.bucket.as_deref(), entry.object.as_deref()), (Some("bucket"), Some(PRIVATE)));
    assert_eq!(entry.decisions, [("s3:GetObject".to_owned(), "deny".to_owned())]);
}

/// Positive — a committed answer is counted once its work ends, under the method it was asked with
/// and the head's status: the event the observer is handed then is the one built for the work the
/// handler handed back to finish after the head.
#[tokio::test]
async fn a_committed_answer_is_counted_under_its_method_when_its_work_ends() {
    let recorder = Arc::new(Recorder::default());
    let service = support::copy_commit_builder(support::CopyCommit::Answer)
        .observer(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");
    let answer = support::exchange_wire(&service, support::copy_commit_request()).await;
    assert_eq!(answer.status(), http::StatusCode::OK);
    assert_eq!(counted(&recorder), [labels("PUT", "CopyObject", "2xx")]);
    assert_eq!(only_entry(&recorder, &request_id(&answer)).operation.as_deref(), Some("CopyObject"));
}
