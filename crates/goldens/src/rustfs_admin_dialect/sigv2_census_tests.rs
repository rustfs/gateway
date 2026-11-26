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

//! The SigV2 census of the RustFS dialect (rustfs/gateway#1582): a SigV2 header signature on
//! every claimed admin row (OIDC bootstrap rows included), every admin-router extension and both
//! admin fallbacks is `403 AccessDenied` before the authorizer, on the default floor and on the
//! RustFS profile's.
//!
//! Responsible for: that census across all 670 claimed rows, the zip download's rows and the four
//! OIDC bootstrap operations included; verifying that anonymous OIDC requests are still admitted;
//! and the positive and ADR-0044 virtual-host controls on a local exempt claimed operation, so a
//! fixture refused for its own reasons fails the control rather than passing the census.
//! The metadata listings are extension routes on the standard listing floor and are covered by
//! `super::metadata_listing_tests`.
//! NOT responsible for: SigV2 presigned URLs (refused by every privileged floor already) or the
//! object lambda's own lanes (`super::lambda_tests`).
//! Upstream: `super`, `super::tests`, `super::extension_tests`, `super::lambda_tests`.
//! Downstream: nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rustfs_gateway::{Handler, HandlerResult, LegacyRustfsVirtualHosts, Observer, Req, RequestEvent, Resp, SecurityFloor};
use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::dialect::{ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, OverlayRow};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::OperationSpec;
use rustfs_gateway_core::route::{PathClaim, Predicate};
use rustfs_gateway_dialect_rustfs_admin::{RouteRecord, admin};
use rustfs_gateway_sig::{OperationFloor, SigService};

use super::extension_tests::{admin_router_records, unsigned as unsigned_extension, unsigned_at};
use super::lambda_tests::{sigv2_header_signed, sigv2_header_signed_over};
use super::tests::rows;
use super::{ACCESS_KEY, Exchange, assemble_installing, assemble_on, in_lanes_on, rustfs_profile_floor, unsigned};
use crate::operation_diff::s3s_0_17_0::context::BASE_DOMAIN;

/// The two floors the census runs on.
fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default floor", SecurityFloor::new()),
        ("RustFS profile floor", rustfs_profile_floor()),
    ]
}

/// Every claimed row the census covers: all 670 rows, including the eight OIDC bootstrap rows.
fn census() -> Vec<(&'static RouteRecord, String)> {
    rows().collect()
}

/// Why `exchange` is not the floor's refusal: `403 AccessDenied` (a `HEAD` answer carries no
/// body to read the code from), with no authorizer question and no handler reached.
fn not_refused(exchange: &Exchange, method: &str) -> Option<String> {
    let coded = method == "HEAD" || exchange.body.contains("<Code>AccessDenied</Code>");
    if exchange.status == 403 && coded && exchange.asked.is_empty() && exchange.reached.is_empty() {
        return None;
    }
    Some(format!(
        "status {}, asked {:?}, reached {:?}, body {}",
        exchange.status, exchange.asked, exchange.reached, exchange.body
    ))
}

/// Runs `send` over `items` on both floors and fails once, naming every item that was not
/// refused on each floor, so a broken half never hides behind the other.
fn refused_on_both_floors<T: Sync>(items: &[T], send: impl Fn(&super::Assembled, &T) -> Option<String> + Sync) {
    let failures = Mutex::new(Vec::new());
    for (at, floor) in floors() {
        in_lanes_on(
            &floor,
            |_, _| true,
            items,
            |assembled, item| {
                if let Some(failure) = send(assembled, item) {
                    failures.lock().expect("an unpoisoned list").push(format!("{at}: {failure}"));
                }
            },
        );
    }
    let failures = failures.into_inner().expect("an unpoisoned list");
    assert!(failures.is_empty(), "{} not refused:\n{}", failures.len(), failures.join("\n"));
}

/// Negative — a SigV2 header signature on every claimed admin row is `403 AccessDenied` before
/// the authorizer, on the default floor and on the RustFS profile's: RustFS refuses SigV2 on every
/// authenticated custom route because SigV2 binds neither its query arguments nor its payload.
#[test]
fn n_a_sigv2_header_signature_on_every_claimed_admin_row_is_refused_without_asking() {
    let rows = census();
    assert_eq!(rows.len(), 670, "every claimed row including the eight OIDC rows");
    refused_on_both_floors(&rows, |assembled, (record, path)| {
        let exchange = assembled.exchange(sigv2_header_signed(unsigned(record, path)));
        not_refused(&exchange, record.method).map(|why| format!("{} {path}: {why}", record.method))
    });
}

/// Every error code the observer saw, in request order.
#[derive(Clone, Default)]
struct Codes(Arc<Mutex<Vec<Option<String>>>>);

impl Observer for Codes {
    fn on_response(&self, event: &RequestEvent<'_>) {
        let code = event.error.map(|code| code.as_str().to_owned());
        self.0.lock().expect("an unpoisoned list").push(code);
    }
}

/// Negative — the `HEAD` rows, whose answer carries no body for the census to read a code from,
/// are refused as `AccessDenied` as the observer reports it, on both floors. A `HEAD` refused for
/// another reason, `SignatureDoesNotMatch` from a fixture the floor let through, say, carries
/// the same status and also asks no authorizer, so only the code separates the two.
#[test]
fn n_a_sigv2_header_signature_on_every_head_row_is_refused_as_access_denied() {
    let heads: Vec<_> = census().into_iter().filter(|(record, _)| record.method == "HEAD").collect();
    assert!(!heads.is_empty(), "the census has HEAD rows");
    for (at, floor) in floors() {
        let codes = Codes::default();
        let observed = codes.clone();
        let assembled = assemble_installing(floor, |_, _| true, false, None, |builder| builder.observer(observed));
        for (record, path) in &heads {
            let exchange = assembled.exchange(sigv2_header_signed(unsigned(record, path)));
            assert_eq!(not_refused(&exchange, "HEAD"), None, "{at}: HEAD {path}");
            let code = codes.0.lock().expect("an unpoisoned list").pop().flatten();
            assert_eq!(code.as_deref(), Some("AccessDenied"), "{at}: HEAD {path}");
        }
    }
}

/// Negative — a SigV2 header signature on every admin-router extension is `403 AccessDenied`
/// before the authorizer, on the default floor and on the RustFS profile's.
#[test]
fn n_a_sigv2_header_signature_on_every_admin_router_extension_is_refused_without_asking() {
    refused_on_both_floors(&admin_router_records(), |assembled, record| {
        let exchange = assembled.exchange(sigv2_header_signed(unsigned_extension(record)));
        not_refused(&exchange, record.method).map(|why| format!("{}: {why}", record.operation))
    });
}

/// Negative — a SigV2 header signature on a path no claimed row names, which the two admin
/// fallbacks answer (`v3` with `501`, `v4` with its downgrade `426`), is `403 AccessDenied`
/// before the authorizer under both admin prefixes, on both floors: the fallbacks share
/// `admin::floor`, and they are not rows of `ROUTES`, so the claimed-row census never reaches them.
#[test]
fn n_a_sigv2_header_signature_on_either_admin_fallback_is_refused_without_asking() {
    let paths: Vec<String> = ["/rustfs/admin", "/minio/admin"]
        .iter()
        .flat_map(|prefix| [format!("{prefix}/v3/no-such-route"), format!("{prefix}/v4/x")])
        .collect();
    refused_on_both_floors(&paths, |assembled, path| {
        let exchange = assembled.exchange(sigv2_header_signed(unsigned_at("GET", path)));
        not_refused(&exchange, "GET").map(|why| format!("GET {path}: {why}"))
    });
}

/// Positive — refusing SigV2 on `admin::anonymous_floor` leaves anonymous OIDC bootstrap access
/// intact on both floors.
#[test]
fn an_anonymous_oidc_bootstrap_request_is_still_admitted() {
    let (record, path) = rows()
        .find(|(record, _)| record.anonymous && record.method == "GET")
        .expect("the inventory has a GET OIDC bootstrap row");
    for (at, floor) in floors() {
        let assembled = assemble_on(floor, |_, _| true);
        let exchange = assembled.exchange(unsigned(record, &path));
        assert_eq!(exchange.status, 200, "{at}: anonymous GET {path}: {}", exchange.body);
        assert_eq!(exchange.reached, [record.operation], "{at}: {path}");
    }
}

pub(super) const CONTROL_PATH: &str = "/_test/sigv2-control/ping";

pub(super) struct SigV2ControlOp;

static CONTROL_SPEC: OperationSpec = admin::spec(
    "test:SigV2Control",
    AuthRequirement::new("test:SigV2Control", ResourceShape::Service),
    false,
);

static CONTROL_FLOOR: OperationFloor =
    OperationFloor::custom("test:SigV2Control", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

static CONTROL_GET: &[Predicate] = &[Predicate::Method(http::Method::GET)];

static CONTROL_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: CONTROL_PATH,
    selector: CONTROL_GET,
}];

static CONTROL_OVERLAY: DialectOverlay = DialectOverlay {
    name: "sigv2-control",
    vendor: "test",
    claims: &[PathClaim {
        prefix: "/_test/sigv2-control",
        reason: "Local test prefix verifying SigV2 header signature verification on a claimed route.",
        evidence: &["https://github.com/rustfs/gateway/issues/1632"],
    }],
    operations: &[OverlayRow {
        name: "test:SigV2Control",
        precedence: 1,
        selector: "PathTemplate(\"/_test/sigv2-control/ping\") ∧ Method(GET)",
        action: "test:SigV2Control",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/1632"],
    }],
};

impl Operation for SigV2ControlOp {
    const NAME: &'static str = "test:SigV2Control";
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &CONTROL_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &CONTROL_FLOOR
    }
}

impl OperationCodec for SigV2ControlOp {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<(), CodecError> {
        Ok(())
    }

    fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

pub(super) struct ControlHandler(pub(super) Arc<AtomicUsize>);

impl Handler<SigV2ControlOp> for ControlHandler {
    async fn call(&self, _request: Req<SigV2ControlOp>) -> HandlerResult<SigV2ControlOp> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(()))
    }
}

pub(super) fn control_dialect() -> Dialect {
    Dialect::assemble(&CONTROL_OVERLAY)
        .declare_claimed::<SigV2ControlOp>(ClaimedRoute {
            precedence: 1,
            rows: CONTROL_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .build()
        .expect("the local SigV2 control dialect builds")
}

/// Positive — the control: the same SigV2 header fixture on a local exempt claimed row is verified
/// as the shared caller and reaches its handler, on both floors. A fixture refused for its own
/// reasons would fail here instead of passing the census as a refusal. Every RustFS admin dialect
/// row (including the four OIDC bootstrap operations) now refuses SigV2 under every policy.
#[test]
fn a_sigv2_header_signature_on_an_exempt_row_is_verified_and_reaches_its_handler() {
    let dialect = control_dialect();
    for (at, floor) in floors() {
        let hits = Arc::new(AtomicUsize::new(0));
        let handler_hits = Arc::clone(&hits);
        let assembled = assemble_installing(
            floor,
            |_, _| true,
            false,
            None,
            |builder| {
                builder
                    .dialect(&dialect)
                    .register::<SigV2ControlOp, _>(Arc::new(ControlHandler(handler_hits)))
            },
        );
        let exchange = assembled.exchange(sigv2_header_signed(unsigned_at("GET", CONTROL_PATH)));
        assert_eq!(exchange.status, 200, "{at}: GET {CONTROL_PATH}: {}", exchange.body);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "{at}: control handler not reached");
        assert!(!exchange.asked.is_empty(), "{at}: {CONTROL_PATH}: the authorizer was not asked");
        assert!(
            exchange.asked.iter().all(|asked| asked.caller.as_deref() == Some(ACCESS_KEY)),
            "{at}: {CONTROL_PATH}: the SigV2 signature was not verified as the caller: {:?}",
            exchange.asked
        );
    }
}

/// Positive and negative — ADR-0044's claimed-route SigV2 canonical resource on a claimed route
/// that admits SigV2: under RustFS's addressing, which claims a prefix on any host, a claimed row
/// requested on a virtual host is verified over its declared service-level path. A SigV2 header
/// signed over that path is the caller's and reaches the handler; the same request signed over the
/// host-derived bucket is refused `SignatureDoesNotMatch` without asking.
#[test]
fn a_claimed_row_on_a_virtual_host_is_signed_over_its_service_level_path() {
    let dialect = control_dialect();
    let hits = Arc::new(AtomicUsize::new(0));
    let handler_hits = Arc::clone(&hits);
    let host = format!("photos.{BASE_DOMAIN}");
    let resolver = LegacyRustfsVirtualHosts::new([BASE_DOMAIN]).expect("the base domain");
    let assembled = assemble_installing(
        SecurityFloor::new(),
        |_, _| true,
        true,
        None,
        |builder| {
            builder
                .host_resolver(resolver)
                .dialect(&dialect)
                .register::<SigV2ControlOp, _>(Arc::new(ControlHandler(handler_hits)))
        },
    );
    let on_virtual_host = || {
        let mut request = unsigned_at("GET", CONTROL_PATH);
        request
            .headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_str(&host).expect("a host"));
        request
    };
    let exchange = assembled.exchange(sigv2_header_signed_over(on_virtual_host(), None));
    assert_eq!(exchange.status, 200, "service-level path: {}", exchange.body);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(
        !exchange.asked.is_empty() && exchange.asked.iter().all(|asked| asked.caller.as_deref() == Some(ACCESS_KEY)),
        "{:?}",
        exchange.asked
    );
    let exchange = assembled.exchange(sigv2_header_signed_over(on_virtual_host(), Some("photos")));
    assert_eq!(exchange.status, 403, "host bucket: {}", exchange.body);
    assert!(exchange.body.contains("<Code>SignatureDoesNotMatch</Code>"), "{}", exchange.body);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(exchange.asked.is_empty() && exchange.reached.is_empty(), "{exchange:?}");
}
