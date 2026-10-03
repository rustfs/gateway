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

//! A host's own request identifier, and the RustFS profile's identifiers, through the assembled
//! service (rustfs/backlog#1677, ruling R10).
//!
//! Responsible for: that a [`HostRequestId`] in the request's extensions is the identifier of every
//! header, error document and event the service writes, whichever answer shape the assembly uses;
//! that nothing a caller sends becomes it; and that
//! `ServiceBuilder::identify_requests_as_legacy_rustfs` answers as legacy RustFS on an S3 path, on a
//! claimed path and on a committed answer.
//! NOT responsible for: the identifier types themselves (`src/trace.rs` and its modules) or the
//! legacy-side comparison (`crates/goldens`'s error-parity diff).
//! Upstream: `rustfs-gateway`, the RustFS admin dialect, `support`. Downstream: nothing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{
    AuthzAuditEvent, AuthzAuditSink, HandlerError, HostRequestId, MintedTraces, Observer, RequestEvent, ResponseView, S3Service,
    ServiceBuilder, StageFilter, WireResponse,
};

use crate::support::{self, Backend, Ping, element_text, exchange_wire, plain};

/// RustFS's own shape: a server-owned UUID.
const HOST_ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/// Every identifier an event reached the deployment with, in arrival order.
#[derive(Default)]
struct Seen(Mutex<Vec<String>>);

impl Seen {
    fn push(&self, id: &str) {
        self.0.lock().expect("not poisoned").push(id.to_owned());
    }

    fn all(&self) -> Vec<String> {
        self.0.lock().expect("not poisoned").clone()
    }
}

struct SeenByObserver(Arc<Seen>);

impl Observer for SeenByObserver {
    fn on_response(&self, event: &RequestEvent<'_>) {
        self.0.push(event.request_id.as_str());
    }
}

struct SeenByAudit(Arc<Seen>);

impl AuthzAuditSink for SeenByAudit {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        self.0.push(event.request_id.as_str());
    }
}

struct SeenByFilter(Arc<Seen>);

/// What the response filter writes under the service's identifier names, so a case can prove the
/// service's answer replaced or removed it.
const FILTER_CHOSEN: &str = "FILTERCHOSEN0000";

impl StageFilter for SeenByFilter {
    fn on_response(
        &self,
        view: &ResponseView<'_>,
        response: &mut http::Response<rustfs_gateway::Body>,
    ) -> Result<(), HandlerError> {
        self.0.push(view.request_id().as_str());
        let headers = response.headers_mut();
        headers.insert("x-amz-request-id", http::HeaderValue::from_static(FILTER_CHOSEN));
        headers.insert("x-amz-id-2", http::HeaderValue::from_static(FILTER_CHOSEN));
        Ok(())
    }
}

/// The three sinks of one service, each recording what it was told.
struct Sinks {
    observer: Arc<Seen>,
    audit: Arc<Seen>,
    filter: Arc<Seen>,
}

fn sinks() -> Sinks {
    Sinks {
        observer: Arc::default(),
        audit: Arc::default(),
        filter: Arc::default(),
    }
}

/// `example:Ping` (anonymously reachable, so both authorization stages report) and every sink.
fn assembled(builder: ServiceBuilder, sinks: &Sinks) -> S3Service {
    builder
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .observer(SeenByObserver(Arc::clone(&sinks.observer)))
        .authz_audit(SeenByAudit(Arc::clone(&sinks.audit)))
        .stage_filter(SeenByFilter(Arc::clone(&sinks.filter)))
        .build()
        .expect("a complete assembly")
}

/// The RustFS profile's identifiers on top of `builder`.
fn rustfs(builder: ServiceBuilder) -> ServiceBuilder {
    builder.identify_requests_as_legacy_rustfs()
}

fn with_host_id(mut request: http::Request<Bytes>) -> http::Request<Bytes> {
    request
        .extensions_mut()
        .insert(HostRequestId::new(HOST_ID).expect("RustFS's shape"));
    request
}

fn body(response: &WireResponse) -> String {
    String::from_utf8(response.body().to_vec()).expect("utf-8")
}

fn is_uuid_v4(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.iter().map(|group| group.len()).eq([8, 4, 4, 4, 12])
        && text
            .bytes()
            .all(|byte| byte == b'-' || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && groups.get(2).is_some_and(|group| group.starts_with('4'))
}

// ── the host's identifier, in the default answer shape ──────────────────────────────────────────

/// Negative — a refusal names the host's request in its header and in its document, and the
/// observer is told the same value. Before the hand-over the host overwrote the header, so the two
/// halves of one answer named two requests (rd-err-0001).
#[tokio::test]
async fn a_refusal_names_the_hosts_request_in_the_head_the_document_and_the_event() {
    let sinks = sinks();
    let service = assembled(support::wired(), &sinks);
    let response = exchange_wire(&service, with_host_id(plain(http::Method::PATCH, "/nowhere"))).await;
    let body = body(&response);
    assert_eq!(response.status(), http::StatusCode::NOT_IMPLEMENTED, "{body}");
    assert_eq!(response.header("x-amz-request-id"), Some(HOST_ID));
    assert_eq!(element_text(&body, "RequestId"), Some(HOST_ID), "{body}");
    assert_eq!(sinks.observer.all(), [HOST_ID]);
    assert_eq!(sinks.filter.all(), [HOST_ID]);
    // The default answer keeps its minted host identifier, in both places, and writes nothing
    // under RustFS's second name.
    let host_id = response.header("x-amz-id-2").expect("a host id header");
    assert_eq!(element_text(&body, "HostId"), Some(host_id), "{body}");
    assert_eq!(response.header("x-request-id"), None);
}

/// Positive — an answered request reports the host's identifier from both authorization stages,
/// the observer and the response filter, and answers with it: one identifier per request.
#[tokio::test]
async fn every_event_of_an_answered_request_carries_the_hosts_identifier() {
    let sinks = sinks();
    let service = assembled(support::wired(), &sinks);
    let response = exchange_wire(&service, with_host_id(plain(http::Method::POST, "/"))).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{}", body(&response));
    assert_eq!(response.header("x-amz-request-id"), Some(HOST_ID));
    // One event from each of the two authorization stages.
    assert_eq!(sinks.audit.all(), [HOST_ID, HOST_ID]);
    assert_eq!(sinks.observer.all(), [HOST_ID]);
    assert_eq!(sinks.filter.all(), [HOST_ID]);
}

/// Negative — identifiers the caller sends in headers never become the request's, whichever name
/// they use: only the host's process can hand one over.
#[tokio::test]
async fn a_caller_header_is_never_the_hosts_identifier() {
    for builder in [support::wired(), rustfs(support::wired())] {
        let sinks = sinks();
        let service = assembled(builder, &sinks);
        let request = http::Request::builder()
            .method(http::Method::PATCH)
            .uri("/nowhere")
            .header("host", "s3.example.com")
            .header("x-request-id", HOST_ID)
            .header("x-amz-request-id", HOST_ID)
            .body(Bytes::new())
            .expect("a valid request");
        let response = exchange_wire(&service, request).await;
        let answered = response.header("x-amz-request-id").expect("a request id header");
        assert_ne!(answered, HOST_ID);
        assert_eq!(sinks.observer.all(), [answered]);
        assert!(!body(&response).contains(HOST_ID), "{}", body(&response));
    }
}

// ── the RustFS profile ─────────────────────────────────────────────────────────────────────────

/// Negative — under the RustFS profile a refusal names the host's request in `x-amz-request-id`
/// and `x-request-id` and, by ruling R10, in its document too; it carries no `x-amz-id-2` and no
/// `<HostId>`, as legacy RustFS carries neither; the events carry the host's identifier.
#[tokio::test]
async fn the_rustfs_profile_answers_a_refusal_as_legacy_rustfs() {
    let sinks = sinks();
    let service = assembled(rustfs(support::wired()), &sinks);
    let response = exchange_wire(&service, with_host_id(plain(http::Method::PATCH, "/nowhere"))).await;
    let body = body(&response);
    assert_eq!(response.status(), http::StatusCode::NOT_IMPLEMENTED, "{body}");
    assert_eq!(response.header("x-amz-request-id"), Some(HOST_ID));
    assert_eq!(response.header("x-request-id"), Some(HOST_ID));
    assert_eq!(response.header("x-amz-id-2"), None);
    assert!(body.contains("<Code>NotImplemented</Code>"), "{body}");
    assert_eq!(element_text(&body, "RequestId"), Some(HOST_ID), "{body}");
    assert_eq!(body.matches("<RequestId>").count(), 1, "{body}");
    assert!(!body.contains("HostId"), "{body}");
    assert_eq!(sinks.observer.all(), [HOST_ID]);
}

/// Negative — a success under the RustFS profile is identified the same way, whatever its encoder
/// and a response filter wrote under the identifier names.
#[tokio::test]
async fn the_rustfs_profile_answers_a_success_as_legacy_rustfs() {
    let sinks = sinks();
    let service = assembled(rustfs(support::wired()), &sinks);
    let response = exchange_wire(&service, with_host_id(plain(http::Method::POST, "/"))).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{}", body(&response));
    assert_eq!(response.header_values("x-amz-request-id").collect::<Vec<_>>(), [HOST_ID]);
    assert_eq!(response.header_values("x-request-id").collect::<Vec<_>>(), [HOST_ID]);
    assert_eq!(response.header("x-amz-id-2"), None, "the encoder's own value must not survive");
    assert_eq!(sinks.audit.all(), [HOST_ID, HOST_ID]);
}

/// Positive — with no host in front of it, the RustFS profile mints its identifier in RustFS's
/// shape when the assembly asks for it, and writes the same value under both names.
#[tokio::test]
async fn the_rustfs_profile_without_a_host_answers_with_a_uuid() {
    let sinks = sinks();
    let service = assembled(rustfs(support::wired()).trace_source(MintedTraces::with_uuid_request_ids()), &sinks);
    let first = exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    let second = exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    let id = first.header("x-amz-request-id").expect("a request id header");
    assert!(is_uuid_v4(id), "{id}");
    assert_eq!(first.header("x-request-id"), Some(id));
    let next = second.header("x-amz-request-id").expect("a request id header");
    assert_ne!(next, id);
    assert_eq!(sinks.observer.all(), [id, next]);
}

/// Negative — on a path RustFS's admin router owns, the RustFS profile writes no identifier of its
/// own, not even the caller's `x-request-id`, which legacy RustFS writes back there and only the
/// host does. The default answer on the same path keeps AWS's identifiers.
#[tokio::test]
async fn the_rustfs_profile_leaves_a_claimed_paths_identifier_to_the_host() {
    let admin = rustfs_gateway_dialect_rustfs_admin::rustfs_admin_dialect().expect("the RustFS admin dialect");
    for (builder, rustfs_profile) in [(support::wired(), false), (rustfs(support::wired()), true)] {
        let sinks = sinks();
        let service = assembled(builder.dialect(&admin), &sinks);
        for path in ["/rustfs/admin/v3/info", "/minio/admin/v3/info", "/rustfs/admin"] {
            let mut request = with_host_id(plain(http::Method::GET, path));
            request
                .headers_mut()
                .insert("x-request-id", http::HeaderValue::from_static("caller-chosen-0001"));
            let response = exchange_wire(&service, request).await;
            let body = body(&response);
            assert!(
                response.status().is_client_error() || response.status().is_server_error(),
                "{path}: {body}"
            );
            assert!(body.contains("<Code>"), "{path}: a refusal document: {body}");
            assert_eq!(response.header("x-request-id"), None, "{path}: the host writes it");
            if rustfs_profile {
                assert_eq!(response.header_values("x-amz-request-id").count(), 0, "{path}");
                assert_eq!(response.header_values("x-amz-id-2").count(), 0, "{path}");
                assert!(!body.contains("RequestId") && !body.contains("HostId"), "{path}: {body}");
            } else {
                assert_eq!(response.header("x-amz-request-id"), Some(HOST_ID), "{path}");
                assert!(response.header("x-amz-id-2").is_some(), "{path}");
            }
            assert!(!body.contains("caller-chosen"), "{path}: {body}");
        }
        // A path that only starts with the same letters is S3's, and is answered as S3.
        let response = exchange_wire(&service, with_host_id(plain(http::Method::GET, "/rustfs/administrator"))).await;
        assert_eq!(response.header("x-amz-request-id"), Some(HOST_ID));
        assert_eq!(sinks.observer.all(), [HOST_ID, HOST_ID, HOST_ID, HOST_ID]);
    }
}

/// Negative — a committed answer's terminal document follows the assembly too: under the RustFS
/// profile the failure reported after `200` names the host's request and no host, as its head does.
#[tokio::test]
async fn a_committed_failure_under_the_rustfs_profile_names_the_hosts_request() {
    let service = rustfs(support::copy_commit_builder(support::CopyCommit::Fail))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, with_host_id(support::copy_commit_request())).await;
    let body = body(&response);
    assert_eq!(response.status(), http::StatusCode::OK, "{body}");
    assert!(body.contains("<Code>NoSuchKey</Code>"), "{body}");
    assert_eq!(element_text(&body, "RequestId"), Some(HOST_ID), "{body}");
    assert!(!body.contains("HostId"), "{body}");
    assert_eq!(response.header("x-amz-request-id"), Some(HOST_ID));
    assert_eq!(response.header("x-request-id"), Some(HOST_ID));
    assert_eq!(response.header("x-amz-id-2"), None);
}
