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

//! The P10-01 proof: three RustFS admin routes as extension operations, below and through the
//! assembled service.
//!
//! Responsible for: the operations' actions agreeing with the recorded inventory; routing with and
//! without the admin rows, every declared overlap being necessary and no undeclared one passing;
//! and, through a real assembled service, SigV4 before the authorizer, the admin action at the
//! authorizer, the caller's secret reaching a handler only when the authenticator hands it over,
//! and every refusal happening before a handler runs.
//! NOT responsible for: the rows themselves (`rustfs_admin_proof.rs`), RustFS behaviour behind the
//! handlers, or the inventory's own validation.
//! Upstream: the parent module, `operation_diff::context`'s signer, the recorded inventory.
//! Downstream: nothing.

use http::{HeaderValue, Method, Request};
use rustfs_gateway::AuthzRequest;
use rustfs_gateway_core::dialect::{Dialect, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::route::{HostClass, Predicate, RouteRequestParts, ShadowingDecl, TargetKind};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::RequestNow;

use super::{
    ADD_SERVICE_ACCOUNT, ADD_SERVICE_ACCOUNT_ACTION, ADD_SERVICE_ACCOUNT_ALIAS, ADD_SERVICE_ACCOUNT_PATH,
    ADD_SERVICE_ACCOUNT_SHADOWS, AddServiceAccount, Assembled, AuthzCall, Options, REPLICATION_METRICS_ACTION,
    REPLICATION_METRICS_QUERY, REPLICATION_METRICS_SHADOWS, REPLICATION_METRICS_V2, ReplicationMetricsV2, SERVER_INFO,
    SERVER_INFO_ACTION, SERVER_INFO_PATH, SERVER_INFO_SHADOWS, ServerInfo, Shadows, admin_dialect, admin_dialect_with, assemble,
    open, seal,
};
use crate::operation_diff::s3s_f3e17541::context::{ACCESS_KEY, ContextRequest, PATH_HOST, SECRET_KEY};
use crate::operation_diff::s3s_f3e17541::harness::block_on;
use crate::{RouteMethod, rustfs_admin_route_inventory};

const REGION: &str = "us-east-1";
const CREATED: &str = "svc-proof";
const HAND_OFF: Options = Options {
    secret_hand_off: true,
    delegate_anonymous: false,
};
const NO_HAND_OFF: Options = Options {
    secret_hand_off: false,
    delegate_anonymous: false,
};

// ── helpers ───────────────────────────────────────────────────────────────────────────────────

/// What a path-style host resolver says a path addresses.
fn path_style_target(path: &str) -> TargetKind {
    match path.trim_start_matches('/') {
        "" => TargetKind::Service,
        rest if rest.contains('/') => TargetKind::Object,
        _ => TargetKind::Bucket,
    }
}

/// The operation `method target` reaches, with `dialect` installed or none.
fn routed(dialect: Option<&Dialect>, method: &str, target: &str) -> Option<&'static str> {
    let request = Request::builder()
        .method(method)
        .uri(format!("http://{PATH_HOST}{target}"))
        .header("host", PATH_HOST)
        .body(())
        .expect("a fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let mut builder = RouterBuilder::new();
    if let Some(dialect) = dialect {
        builder = builder.dialect(dialect);
    }
    let router = builder.build().expect("the table builds");
    let path = wire.raw_path().as_str();
    let parts = RouteRequestParts {
        method: wire.method(),
        path,
        target: path_style_target(path),
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
    };
    router.resolve(&parts).map(|entry| entry.op_name)
}

/// Why the table refuses the admin rows with `shadows`.
fn table_refusal(shadows: Shadows) -> String {
    let dialect = admin_dialect_with(shadows).expect("the record and the declarations still agree");
    match RouterBuilder::new().dialect(&dialect).build() {
        Ok(_) => panic!("the table built"),
        Err(error) => format!("{error:?}"),
    }
}

fn leaked(declarations: Vec<ShadowingDecl>) -> &'static [ShadowingDecl] {
    Box::leak(declarations.into_boxed_slice())
}

/// One answer from the assembled service.
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn send_with(assembled: &Assembled, request: &ContextRequest, edit: impl FnOnce(&mut http::HeaderMap)) -> Answer {
    let mut headers = request.wire_headers(RequestNow::capture()).expect("fixture headers");
    edit(&mut headers);
    let http_request = request
        .http_head(&headers)
        .body(request.body.clone())
        .expect("a fixture request");
    let response = block_on(assembled.service.call_bytes(http_request));
    let collected = block_on(rustfs_gateway::collect(response)).expect("an in-memory body");
    Answer {
        status: collected.status().as_u16(),
        content_type: collected
            .headers()
            .iter()
            .find(|(name, _)| name.as_str() == "content-type")
            .and_then(|(_, value)| value.to_str().ok())
            .map(str::to_owned),
        body: collected.body().to_vec(),
    }
}

fn send(assembled: &Assembled, request: &ContextRequest) -> Answer {
    send_with(assembled, request, |_| {})
}

fn server_info() -> ContextRequest {
    ContextRequest::get(PATH_HOST, SERVER_INFO_PATH, "")
}

fn add_service_account(sealed_under: &[u8]) -> ContextRequest {
    let asked = format!("{{\"accessKey\":\"{CREATED}\"}}");
    ContextRequest::put(PATH_HOST, ADD_SERVICE_ACCOUNT_ALIAS, &seal(sealed_under, asked.as_bytes()))
}

fn metrics(query: &str) -> ContextRequest {
    ContextRequest::get(PATH_HOST, "/photos", query)
}

fn only(action: &'static str) -> impl Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static {
    move |request| request.action == action
}

fn route_calls(calls: &[AuthzCall]) -> Vec<&AuthzCall> {
    calls.iter().filter(|call| call.stage == "route").collect()
}

fn assert_refused_before_the_handler(assembled: &Assembled, answer: &Answer, status: u16) {
    assert_eq!(answer.status, status, "{}", answer.text());
    assert!(assembled.backend.seen().is_empty(), "a handler ran: {:?}", assembled.backend.seen());
    assert!(assembled.backend.created().is_empty());
}

// ── the rows and the inventory ────────────────────────────────────────────────────────────────

/// Positive — each operation declares the action and path the inventory records for its route,
/// and each is privileged and header-signed only.
#[test]
fn the_proof_operations_declare_what_the_inventory_records() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    let info = inventory.route(RouteMethod::Get, SERVER_INFO_PATH).expect("a recorded route");
    let add = inventory
        .route(RouteMethod::Put, ADD_SERVICE_ACCOUNT_PATH)
        .expect("a recorded route");
    let metrics = inventory
        .extension_route("ReplicationExtRoute::MetricsV2")
        .expect("a recorded extension route");

    let action = |spec: &'static rustfs_gateway_core::registry::OperationSpec| spec.auth.expect("an action").action;
    assert_eq!(info.iam_action_wire.as_deref(), Some(action(ServerInfo::spec())));
    assert_eq!(add.iam_action_wire.as_deref(), Some(action(AddServiceAccount::spec())));
    assert_eq!(metrics.iam_action_wire, action(ReplicationMetricsV2::spec()));
    assert!(add.minio_admin_alias && add.caller_secret_body.needs_caller_secret());
    assert_eq!(
        ADD_SERVICE_ACCOUNT_ALIAS.strip_prefix("/minio/admin"),
        ADD_SERVICE_ACCOUNT_PATH.strip_prefix("/rustfs/admin")
    );
    assert_eq!(metrics.query_discriminator.key, REPLICATION_METRICS_QUERY.0);
    assert_eq!(metrics.query_discriminator.rule, format!("equals:{}", REPLICATION_METRICS_QUERY.1));
    for floor in [ServerInfo::floor(), AddServiceAccount::floor(), ReplicationMetricsV2::floor()] {
        assert!(floor.privileged());
        assert!(!floor.allowed_schemes().allows_anonymous());
        assert!(!floor.allowed_schemes().allows_presigned());
    }
}

// ── routing ───────────────────────────────────────────────────────────────────────────────────

/// Positive — each admin request reaches its extension operation once the rows are installed.
#[test]
fn each_admin_request_reaches_its_extension_operation() {
    let dialect = admin_dialect();
    assert_eq!(routed(Some(&dialect), "GET", SERVER_INFO_PATH), Some(SERVER_INFO));
    assert_eq!(routed(Some(&dialect), "PUT", ADD_SERVICE_ACCOUNT_ALIAS), Some(ADD_SERVICE_ACCOUNT));
    assert_eq!(
        routed(Some(&dialect), "GET", "/photos?replication-metrics=2"),
        Some(REPLICATION_METRICS_V2)
    );
}

/// Positive — like RustFS's router, a row answers every query on its path and value.
#[test]
fn the_admin_rows_answer_every_query_on_their_path_as_rustfs_does() {
    let dialect = admin_dialect();
    assert_eq!(routed(Some(&dialect), "GET", "/rustfs/admin/v3/info?tagging"), Some(SERVER_INFO));
    assert_eq!(
        routed(Some(&dialect), "PUT", "/minio/admin/v3/add-service-account?uploadId=u&partNumber=1"),
        Some(ADD_SERVICE_ACCOUNT)
    );
    assert_eq!(
        routed(Some(&dialect), "GET", "/photos?location&replication-metrics=2"),
        Some(REPLICATION_METRICS_V2)
    );
}

/// Negative — the rows are off unless installed: the same requests are ordinary S3 requests.
#[test]
fn n_without_the_rows_the_admin_requests_are_ordinary_s3_requests() {
    assert_eq!(routed(None, "GET", SERVER_INFO_PATH), Some("GetObject"));
    assert_eq!(routed(None, "PUT", ADD_SERVICE_ACCOUNT_ALIAS), Some("PutObject"));
    assert_eq!(routed(None, "GET", "/photos?replication-metrics=2"), Some("ListObjects"));
}

/// Negative — installing the rows moves no request that is not exactly theirs.
#[test]
fn n_the_admin_rows_leave_every_s3_neighbour_where_it_was() {
    let dialect = admin_dialect();
    for (method, target, expected) in [
        ("GET", "/photos/a.png", "GetObject"),
        ("GET", "/rustfs/other.txt", "GetObject"),
        ("GET", "/rustfs/admin/v3/infox", "GetObject"),
        ("GET", "/rustfs/admin/v3", "GetObject"),
        ("PUT", SERVER_INFO_PATH, "PutObject"),
        ("GET", ADD_SERVICE_ACCOUNT_ALIAS, "GetObject"),
        // One route row per operation: the canonical path is a second row this slice does not add.
        ("PUT", ADD_SERVICE_ACCOUNT_PATH, "PutObject"),
        ("GET", "/photos?replication-metrics=1", "ListObjects"),
        ("GET", "/photos?replication-metrics", "ListObjects"),
        ("GET", "/photos?location", "GetBucketLocation"),
        ("GET", "/photos?list-type=2", "ListObjectsV2"),
        ("PUT", "/photos?replication-metrics=2", "CreateBucket"),
    ] {
        assert_eq!(routed(Some(&dialect), method, target), Some(expected), "{method} {target}");
    }
}

/// Negative — every declared overlap is necessary: dropping any one of them is a start-up
/// refusal naming exactly that pair, so the declarations are neither padded nor short.
#[test]
fn n_every_declared_overlap_is_necessary() {
    let mut checked = 0;
    for (name, declarations) in [
        ("server_info", SERVER_INFO_SHADOWS),
        ("add_service_account", ADD_SERVICE_ACCOUNT_SHADOWS),
        ("replication_metrics", REPLICATION_METRICS_SHADOWS),
    ] {
        for index in 0..declarations.len() {
            let mut kept = declarations.to_vec();
            let dropped = kept.remove(index);
            let mut shadows = Shadows::DECLARED;
            match name {
                "server_info" => shadows.server_info = leaked(kept),
                "add_service_account" => shadows.add_service_account = leaked(kept),
                _ => shadows.replication_metrics = leaked(kept),
            }
            let refusal = table_refusal(shadows);
            assert!(refusal.contains("UndeclaredShadowing"), "{refusal}");
            assert!(
                refusal.contains(dropped.winner) && refusal.contains(dropped.shadowed),
                "dropping {} over {} was refused for another pair: {refusal}",
                dropped.winner,
                dropped.shadowed
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked,
        SERVER_INFO_SHADOWS.len() + ADD_SERVICE_ACCOUNT_SHADOWS.len() + REPLICATION_METRICS_SHADOWS.len()
    );
}

/// Negative — a declaration over a row the admin row cannot overlap is refused as stale.
#[test]
fn n_a_declaration_over_a_row_that_does_not_overlap_is_refused() {
    let mut declarations = SERVER_INFO_SHADOWS.to_vec();
    declarations.push(ShadowingDecl {
        winner: SERVER_INFO,
        shadowed: "PutObject",
        reason: "a GET row cannot hide a PUT row",
        evidence: &["https://github.com/rustfs/backlog/issues/1744"],
    });
    let mut shadows = Shadows::DECLARED;
    shadows.server_info = leaked(declarations);
    let refusal = table_refusal(shadows);
    assert!(refusal.contains("StaleShadowing") && refusal.contains("PutObject"), "{refusal}");
}

/// Negative — a path literal does not make an admin row disjoint from the object rows: with no
/// declarations the row is refused. `docs/dialects.md` says a path-literal admin row "overlaps
/// nothing"; the lattice treats path and target as independent dimensions, so it overlaps every
/// standard row in its method-and-target cell.
#[test]
fn n_a_path_literal_alone_does_not_make_an_admin_row_disjoint() {
    let mut shadows = Shadows::DECLARED;
    shadows.server_info = &[];
    let refusal = table_refusal(shadows);
    assert!(refusal.contains("UndeclaredShadowing") && refusal.contains(SERVER_INFO), "{refusal}");
}

static SERVICE_TARGET_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::GET),
    Predicate::Target(TargetKind::Service),
    Predicate::PathLiteral(SERVER_INFO_PATH),
];

static SERVICE_TARGET_OVERLAY: DialectOverlay = DialectOverlay {
    name: "rustfs-admin-service-target",
    vendor: "rustfs",
    operations: &[OverlayRow {
        name: SERVER_INFO,
        precedence: 60,
        selector: "Method(GET) ∧ Target(Service) ∧ PathLiteral(\"/rustfs/admin/v3/info\")",
        action: SERVER_INFO_ACTION,
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: &["https://github.com/rustfs/backlog/issues/1744"],
    }],
};

static SERVICE_TARGET_SHADOWS: &[ShadowingDecl] = &[
    ShadowingDecl {
        winner: SERVER_INFO,
        shadowed: "ListDirectoryBuckets",
        reason: "the service-target spelling this test measures",
        evidence: &["https://github.com/rustfs/backlog/issues/1744"],
    },
    ShadowingDecl {
        winner: SERVER_INFO,
        shadowed: "ListBuckets",
        reason: "the service-target spelling this test measures",
        evidence: &["https://github.com/rustfs/backlog/issues/1744"],
    },
];

/// Negative — the spelling that escapes the object-row declarations is a dead row: the host
/// resolver says a multi-segment path addresses an object, so a service-target row never matches
/// the admin path and the request is served as `GetObject`.
#[test]
fn n_the_service_target_spelling_that_owes_fewer_declarations_routes_nothing() {
    let dialect = Dialect::assemble(&SERVICE_TARGET_OVERLAY)
        .declare::<ServerInfo>(DialectRoute {
            precedence: 60,
            selector: SERVICE_TARGET_SELECTOR,
            path_shape: SERVER_INFO_PATH,
            shadows: SERVICE_TARGET_SHADOWS,
        })
        .build()
        .expect("the record and the declaration agree");
    assert_eq!(routed(Some(&dialect), "GET", SERVER_INFO_PATH), Some("GetObject"));
}

// ── authentication and authorisation through the assembled service ────────────────────────────

/// Positive — a signed admin read is authenticated, then authorised once at the route stage with
/// its admin action and the signer's identity, and only then handled.
#[test]
fn a_signed_admin_read_is_authorised_with_its_admin_action() {
    let assembled = assemble(NO_HAND_OFF, only(SERVER_INFO_ACTION));
    let answer = send(&assembled, &server_info().signed(REGION));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.content_type.as_deref(), Some("application/json"));
    assert!(answer.text().contains("\"online\""), "{}", answer.text());

    let calls = assembled.calls();
    let routes = route_calls(&calls);
    assert_eq!(routes.len(), 1, "{calls:?}");
    assert_eq!(routes[0].operation, SERVER_INFO);
    assert_eq!(routes[0].action, SERVER_INFO_ACTION);
    assert_eq!(routes[0].caller.as_deref(), Some(ACCESS_KEY));
    assert!(calls.iter().all(|call| call.caller.as_deref() == Some(ACCESS_KEY)), "{calls:?}");
    // Measured, and owed by the ring-2 authorizer: a path-style admin path still parses as bucket
    // `rustfs`, so a service-shaped admin action is asked about with that bucket beside it. The
    // authorizer must decide admin actions without consulting a bucket policy for it.
    assert_eq!(routes[0].bucket.as_deref(), Some("rustfs"));

    let seen = assembled.backend.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].operation, SERVER_INFO);
    assert_eq!(seen[0].caller.as_deref(), Some(ACCESS_KEY));
    assert_eq!(seen[0].raw_path, SERVER_INFO_PATH);
    assert!(!seen[0].holds_secret);
}

/// Negative — an unsigned admin request is refused before the authorizer, even when anonymous
/// admission is delegated to an authorizer that allows everything (ADR-0021): a third-party
/// operation is privileged, and delegation does not reach it.
#[test]
fn n_an_anonymous_admin_request_is_refused_before_the_authorizer() {
    let assembled = assemble(
        Options {
            secret_hand_off: true,
            delegate_anonymous: true,
        },
        |_| true,
    );
    for request in [
        server_info(),
        add_service_account(SECRET_KEY.as_bytes()),
        metrics("replication-metrics=2"),
    ] {
        let answer = send(&assembled, &request);
        assert_refused_before_the_handler(&assembled, &answer, 403);
        assert!(answer.text().contains("<Code>AccessDenied</Code>"), "{}", answer.text());
    }
    assert!(assembled.calls().is_empty(), "{:?}", assembled.calls());
}

/// Negative — a caller whose policy grants another admin action is refused at the route stage,
/// asked about the operation's own action, before the body is opened.
#[test]
fn n_a_caller_without_the_operations_admin_action_is_refused() {
    let assembled = assemble(HAND_OFF, only(SERVER_INFO_ACTION));
    let answer = send(&assembled, &add_service_account(SECRET_KEY.as_bytes()).signed(REGION));
    assert_refused_before_the_handler(&assembled, &answer, 403);
    assert!(answer.text().contains("<Code>AccessDenied</Code>"), "{}", answer.text());
    let calls = assembled.calls();
    let routes = route_calls(&calls);
    assert_eq!(routes.len(), 1, "{calls:?}");
    assert_eq!(routes[0].action, ADD_SERVICE_ACCOUNT_ACTION);
}

/// Negative — an S3-only policy reaches S3 and never an admin operation in the same assembly.
#[test]
fn n_an_s3_only_caller_reaches_s3_but_no_admin_operation() {
    let assembled = assemble(NO_HAND_OFF, |request| {
        request.action.starts_with("s3:") && request.operation != REPLICATION_METRICS_V2
    });
    let refused = send(&assembled, &server_info().signed(REGION));
    assert_refused_before_the_handler(&assembled, &refused, 403);
    let served = send(&assembled, &ContextRequest::get(PATH_HOST, "/photos/a.png", "").signed(REGION));
    assert_eq!(served.status, 200, "{}", served.text());
    assert_eq!(
        assembled.backend.seen().iter().map(|seen| seen.operation).collect::<Vec<_>>(),
        ["GetObject"]
    );
}

/// Negative — an authorizer that denies everything refuses all three before any handler.
#[test]
fn n_a_deny_everything_authorizer_refuses_every_admin_operation() {
    let assembled = assemble(HAND_OFF, |_| false);
    for request in [
        server_info(),
        add_service_account(SECRET_KEY.as_bytes()),
        metrics("replication-metrics=2"),
    ] {
        let answer = send(&assembled, &request.signed(REGION));
        assert_refused_before_the_handler(&assembled, &answer, 403);
    }
    let operations = route_calls(&assembled.calls())
        .iter()
        .map(|call| call.operation.clone())
        .collect::<Vec<_>>();
    assert_eq!(operations, [SERVER_INFO, ADD_SERVICE_ACCOUNT, REPLICATION_METRICS_V2]);
}

/// Negative — a signature that does not verify never reaches the authorizer or a handler.
#[test]
fn n_a_tampered_signature_never_reaches_the_authorizer() {
    let assembled = assemble(HAND_OFF, |_| true);
    let answer = send_with(&assembled, &server_info().signed(REGION), |headers| {
        let value = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .expect("a signed request")
            .to_owned();
        let flipped = if value.ends_with('0') { "1" } else { "0" };
        let tampered = format!("{}{flipped}", &value[..value.len() - 1]);
        headers.insert(http::header::AUTHORIZATION, HeaderValue::from_str(&tampered).expect("ASCII"));
    });
    assert_refused_before_the_handler(&assembled, &answer, 403);
    assert!(assembled.calls().is_empty(), "{:?}", assembled.calls());
}

// ── the caller's secret ───────────────────────────────────────────────────────────────────────

/// Positive — with the hand-off, the sealed write opens under the caller's secret, is answered
/// sealed under the same key, and the secret never prints through the context.
#[test]
fn with_the_hand_off_the_sealed_write_opens_under_the_callers_secret() {
    let assembled = assemble(HAND_OFF, only(ADD_SERVICE_ACCOUNT_ACTION));
    let answer = send(&assembled, &add_service_account(SECRET_KEY.as_bytes()).signed(REGION));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.content_type.as_deref(), Some("application/octet-stream"));
    let opened = open(SECRET_KEY.as_bytes(), &answer.body).expect("the answer is sealed under the caller's key");
    assert!(String::from_utf8_lossy(&opened).contains(CREATED));
    assert!(open(b"another-key", &answer.body).is_none());
    assert_eq!(assembled.backend.created(), [CREATED]);
    let seen = assembled.backend.seen();
    assert!(seen[0].holds_secret && seen[0].secret_is_the_callers);
    assert!(!seen[0].context_debug_shows_secret);
}

/// Negative — without the hand-off the handler holds no secret and fails closed: nothing is
/// created from a body nobody could open.
#[test]
fn n_without_the_hand_off_the_sealed_write_fails_closed() {
    let assembled = assemble(NO_HAND_OFF, |_| true);
    let answer = send(&assembled, &add_service_account(SECRET_KEY.as_bytes()).signed(REGION));
    assert_eq!(answer.status, 500, "{}", answer.text());
    assert!(!answer.text().contains(SECRET_KEY));
    assert!(assembled.backend.created().is_empty());
    let seen = assembled.backend.seen();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].holds_secret);
}

/// Negative — a body sealed under another key is refused, and nothing is created.
#[test]
fn n_a_body_sealed_under_another_key_is_refused() {
    let assembled = assemble(HAND_OFF, |_| true);
    let answer = send(&assembled, &add_service_account(b"not-the-callers-key").signed(REGION));
    assert_eq!(answer.status, 400, "{}", answer.text());
    assert!(answer.text().contains("<Code>InvalidRequest</Code>"), "{}", answer.text());
    assert!(assembled.backend.created().is_empty());
}

/// Positive, and a measured limit — the hand-off is the authenticator's, not the operation's: once
/// on, every handler in the assembly holds the caller's secret, including a read that never needs
/// it. It still never prints through the context.
#[test]
fn a_handed_off_secret_reaches_every_handler_of_the_assembly() {
    let assembled = assemble(HAND_OFF, |_| true);
    let answer = send(&assembled, &server_info().signed(REGION));
    assert_eq!(answer.status, 200, "{}", answer.text());
    let seen = assembled.backend.seen();
    assert!(seen[0].holds_secret && seen[0].secret_is_the_callers);
    assert!(!seen[0].context_debug_shows_secret);
}

// ── the query-discriminated read and its S3 neighbours ────────────────────────────────────────

/// Positive — the query-discriminated read is authorised on its bucket with the S3 action RustFS
/// checks for it.
#[test]
fn the_query_discriminated_read_is_authorised_on_its_bucket() {
    let assembled = assemble(NO_HAND_OFF, only(REPLICATION_METRICS_ACTION));
    let answer = send(&assembled, &metrics("replication-metrics=2").signed(REGION));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert!(answer.text().contains("\"photos\""), "{}", answer.text());
    let calls = assembled.calls();
    let routes = route_calls(&calls);
    assert_eq!(routes.len(), 1, "{calls:?}");
    assert_eq!(routes[0].action, REPLICATION_METRICS_ACTION);
    assert_eq!(routes[0].bucket.as_deref(), Some("photos"));
}

/// Negative — another value of the same key is an ordinary listing, authorised as one.
#[test]
fn n_another_value_of_the_key_is_an_ordinary_listing() {
    let assembled = assemble(NO_HAND_OFF, |_| true);
    let answer = send(&assembled, &metrics("replication-metrics=1").signed(REGION));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(assembled.backend.seen()[0].operation, "ListObjects");
    assert_eq!(route_calls(&assembled.calls())[0].action, "s3:ListBucket");
}

/// Negative — S3 requests in the same assembly are routed and authorised as S3, including a key
/// in a bucket named like the admin prefix.
#[test]
fn n_s3_requests_beside_the_admin_rows_are_authorised_as_s3() {
    let assembled = assemble(NO_HAND_OFF, |_| true);
    for (path, bucket) in [("/photos/a.png", "photos"), ("/rustfs/other.txt", "rustfs")] {
        let answer = send(&assembled, &ContextRequest::get(PATH_HOST, path, "").signed(REGION));
        assert_eq!(answer.status, 200, "{path}: {}", answer.text());
        let seen = assembled.backend.seen();
        let last = seen.last().expect("a handler ran");
        assert_eq!((last.operation, last.bucket.as_deref()), ("GetObject", Some(bucket)));
    }
    let actions = route_calls(&assembled.calls())
        .iter()
        .map(|call| call.action.clone())
        .collect::<Vec<_>>();
    assert_eq!(actions, ["s3:GetObject", "s3:GetObject"]);
}
