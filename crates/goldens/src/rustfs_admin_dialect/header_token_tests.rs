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

//! The host-verified header token claim against the RustFS admin dialect (ADR-0053,
//! rustfs/gateway#1586).
//!
//! Responsible for: with the claim and a spy verifier installed, every admin row and every
//! S3-shaped extension row refusing a request whose only credential is the header token, on the
//! default floor and on the RustFS profile's, with no authorizer question, no handler and the
//! verifier never asked; the anonymous bootstrap rows refusing the token they would serve
//! without; the zip download refusing the token beside its own query bearer token and alone, with
//! neither verifier asked; the object lambda route, which requires SigV4 under every policy,
//! refusing it; and the bearer and presigned paths of those two routes unchanged beside the claim.
//! NOT responsible for: the floor's rules themselves (`rustfs-gateway-sig`'s
//! `tests/header_token.rs`), the standard operations that do admit the scheme (`rustfs-gateway`'s
//! `tests/header_token.rs`), the STS form, which this harness does not serve
//! (`operation_diff::sts_parity`), or the harness (`super`).
//! Upstream: `super`, `super::zip_token_tests`, `super::extension_tests`. Downstream: nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{HeaderValue, Request};
use rustfs_gateway::{
    HeaderTokenClaim, HeaderTokenRefused, HeaderTokenVerifier, Identity, RequestNow, SecurityFloor, ServiceBuilder,
};
use rustfs_gateway_dialect_rustfs_admin::{EXTENSION_ROUTES, ExtensionRouteRecord, ROUTES};

use super::extension_tests::{KEY, LAMBDA, LAMBDA_ARN, presigned_lambda, unsigned as unsigned_extension, unsigned_at};
use super::zip_token_tests::{FixtureVerifier, GOOD, ZIP_GET, asked_of};
use super::{Assembled, BUCKET, Exchange, assemble_installing, in_lanes_installing, paths, rustfs_profile_floor, unsigned};
use crate::operation_diff::s3s_0_17_0::context::ACCESS_KEY;

const HEADER: &str = "x-auth-token";
const TOKEN: &str = "gAAAAABheader-token-sentinel";

/// A host verifier that would report the shared credential's principal for anything, and counts
/// how often it is asked. Every case here asserts that count stays zero: were the floor to admit
/// one of these routes by header token, the request would be served and the count would say so.
#[derive(Clone, Default)]
struct Spy(Arc<AtomicUsize>);

/// What a host's outer layer leaves in a request it authenticated. Every request these cases
/// send with the token carries one, so the spy would be asked the moment a floor admitted it.
#[derive(Clone)]
struct Outer;

impl HeaderTokenVerifier for Spy {
    type Established = Outer;

    fn identity(&self, _established: &Outer, _now: RequestNow) -> Result<Identity, HeaderTokenRefused> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Identity::new(ACCESS_KEY).map_err(|_| HeaderTokenRefused)
    }
}

fn install(spy: &Spy) -> impl Fn(ServiceBuilder) -> ServiceBuilder + Sync + '_ {
    move |builder| builder.host_verified_header_token(HeaderTokenClaim::new(HEADER).expect("a legal claim"), spy.clone())
}

fn assemble_with(floor: SecurityFloor, spy: &Spy, also: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> Assembled {
    assemble_installing(floor, |_, _| true, false, None, |builder| also(install(spy)(builder)))
}

/// The default floor, and the RustFS profile's with its reading of which requests are signed.
fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default", SecurityFloor::new()),
        ("rustfs-profile", rustfs_profile_floor().recognize_signatures_as_legacy_rustfs()),
    ]
}

fn with_token(mut request: Request<Bytes>) -> Request<Bytes> {
    request.headers_mut().insert(HEADER, HeaderValue::from_static(TOKEN));
    request.extensions_mut().insert(Outer);
    request
}

/// `403`, no handler, no authorizer question, and no token in the answer.
fn refused_without_asking(exchange: &Exchange, at: &str) {
    assert_eq!(exchange.status, 403, "{at}: {}", exchange.body);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran: {:?}", exchange.reached);
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
    assert!(
        !exchange.body.to_ascii_lowercase().contains("sentinel"),
        "{at}: the refusal holds the token"
    );
}

/// Negative — no row of the admin dialect, and no S3-shaped extension row outside the reviewed
/// list, admits a header token: with an allow-everything policy and a verifier that would vouch
/// for anyone, every one of them is refused before the authorizer and the handler, and the
/// verifier is never asked.
#[test]
fn n_no_admin_or_extension_row_admits_a_header_token() {
    // Each row's own unsigned request, kept as its method and target so every lane can rebuild it.
    let target = |request: Request<Bytes>| (request.method().to_string(), request.uri().to_string());
    let admin: Vec<(String, String)> = ROUTES
        .iter()
        .flat_map(|record| paths(record).into_iter().map(move |path| target(unsigned(record, &path))))
        .collect();
    let refusing = |record: &&ExtensionRouteRecord| !DIALECT_OPERATIONS_ADMITTING_A_HEADER_TOKEN.contains(&record.operation);
    let extensions: Vec<(String, String)> = EXTENSION_ROUTES
        .iter()
        .filter(refusing)
        .map(|record| target(unsigned_extension(record)))
        .collect();
    assert_eq!(EXTENSION_ROUTES.len() - extensions.len(), 2, "the two reviewed metadata listings");
    assert_eq!((admin.len(), extensions.len()), (670, 8), "every other row of both tables");
    let requests: Vec<(String, String)> = admin.into_iter().chain(extensions).collect();
    for (floor_name, floor) in floors() {
        let spy = Spy::default();
        in_lanes_installing(
            &floor,
            |_, _| true,
            install(&spy),
            &requests,
            |assembled, (method, uri)| {
                let at = format!("{floor_name}: {method} {uri}");
                refused_without_asking(&assembled.exchange(with_token(unsigned_at(method, uri))), &at);
            },
        );
        assert_eq!(spy.0.load(Ordering::SeqCst), 0, "{floor_name}: the verifier was asked");
    }
}

/// Negative — the rows that admit an anonymous request refuse the same request once it carries
/// the token: a presented credential is never served as anonymous, and these privileged
/// operations do not admit the scheme. The request without the header is the control.
#[test]
fn n_an_anonymous_bootstrap_row_refuses_the_token_it_would_serve_without() {
    let bootstrap: Vec<_> = ROUTES
        .iter()
        .filter(|record| record.anonymous)
        .flat_map(|record| paths(record).into_iter().map(move |path| (record, path)))
        .collect();
    assert_eq!(bootstrap.len(), 8, "the eight rows of RustFS's four bootstrap operations");
    for (floor_name, floor) in floors() {
        let spy = Spy::default();
        let assembled = assemble_with(floor, &spy, |builder| builder);
        for (record, path) in &bootstrap {
            let at = format!("{floor_name}: {} {path}", record.method);
            let anonymous = assembled.exchange(unsigned(record, path));
            assert_eq!(anonymous.status, 200, "{at}: {}", anonymous.body);
            assert_eq!(anonymous.reached, [record.operation], "{at}");
            refused_without_asking(&assembled.exchange(with_token(unsigned(record, path))), &at);
        }
        assert_eq!(spy.0.load(Ordering::SeqCst), 0, "{floor_name}: the verifier was asked");
    }
}

/// Negative — the zip download refuses the header token beside its own query bearer token and
/// alone, and neither verifier is asked: the two credentials have no precedence, and a
/// bearer-claimed route does not admit the scheme. The minted URL without the header still
/// reaches the download through its bearer verifier, with the claim installed beside it.
#[test]
fn n_the_zip_download_refuses_the_token_beside_its_bearer_token_and_alone() {
    for (floor_name, floor) in floors() {
        let spy = Spy::default();
        let bearer = FixtureVerifier::default();
        let assembled = assemble_with(floor, &spy, |builder| builder.bearer_token_verifier(bearer.clone()));
        for prefix in ["/rustfs/admin", "/minio/admin"] {
            for query in [format!("?token={GOOD}"), String::new(), "?note=a".to_owned()] {
                let uri = format!("{prefix}/v3/object-zip-downloads/abc.zip{query}");
                let at = format!("{floor_name}: {uri}");
                refused_without_asking(&assembled.exchange(with_token(unsigned_at("GET", &uri))), &at);
                assert!(asked_of(&bearer).is_empty(), "{at}: the bearer verifier was asked");
            }
            let uri = format!("{prefix}/v3/object-zip-downloads/abc.zip?token={GOOD}");
            let minted = assembled.exchange(unsigned_at("GET", &uri));
            assert_eq!(minted.status, 200, "{floor_name}: {uri}: {}", minted.body);
            assert_eq!(minted.reached, [ZIP_GET], "{floor_name}: {uri}");
            assert_eq!(asked_of(&bearer), ["abc"], "{floor_name}: {uri}: the bearer path is unchanged");
        }
        assert_eq!(spy.0.load(Ordering::SeqCst), 0, "{floor_name}: the header verifier was asked");
    }
}

/// Negative — the object lambda route requires SigV4 under every policy and refuses the header
/// token, alone and beside its own presigned URL; the presigned URL without the header still
/// reaches the handler, with the claim installed beside it.
#[test]
fn n_the_object_lambda_route_refuses_the_token_alone_and_beside_its_presigned_url() {
    for (floor_name, floor) in floors() {
        let spy = Spy::default();
        let assembled = assemble_with(floor, &spy, |builder| builder);
        let unsigned_lambda = unsigned_at("GET", &format!("/{BUCKET}/{KEY}?lambdaArn={LAMBDA_ARN}"));
        refused_without_asking(&assembled.exchange(with_token(unsigned_lambda)), floor_name);
        refused_without_asking(&assembled.exchange(with_token(presigned_lambda())), floor_name);
        let presigned = assembled.exchange(presigned_lambda());
        assert_eq!(presigned.status, 200, "{floor_name}: {}", presigned.body);
        assert_eq!(presigned.reached, [LAMBDA], "{floor_name}");
        assert_eq!(spy.0.load(Ordering::SeqCst), 0, "{floor_name}: the verifier was asked");
    }
}

/// The operations of the `rustfs` dialect that admit a header token: the reviewed list. RustFS's
/// two metadata listings stand on the standard listing floor (ADR-0050) and answer what
/// `ListObjectsV2` and `ListObjectVersions` answer plus each object's user metadata; a token's
/// user reaches the standard listings, the authorizer decides both, and refusing the scheme here
/// would only make the same caller sign for the same bucket. Nothing else of the dialect admits
/// the scheme.
const DIALECT_OPERATIONS_ADMITTING_A_HEADER_TOKEN: [&str; 2] =
    ["rustfs:ListObjectVersionsWithMetadata", "rustfs:ListObjectsV2WithMetadata"];

/// The dialect's operations that admit a header token are the reviewed list, on both floors, and
/// one of them is served as the principal the host established while a privileged neighbour is
/// not. An operation added to the dialect on a non-privileged floor admits the scheme the moment
/// it is declared: this is where that is seen and decided.
#[test]
fn the_dialect_operations_that_admit_a_header_token_are_the_reviewed_list() {
    for (floor_name, floor) in floors() {
        let spy = Spy::default();
        let assembled = assemble_with(floor, &spy, |builder| builder);
        let report = assembled.service.startup_posture();
        let line = report
            .lines()
            .find(|line| line.starts_with("HEADER_TOKEN_POSTURE "))
            .expect("a claimed service reports the line");
        assert!(
            line.ends_with(&format!("header_token_ops=[{}]", DIALECT_OPERATIONS_ADMITTING_A_HEADER_TOKEN.join(","))),
            "{floor_name}: the set of dialect operations that admit a header token changed; review each one: {line}"
        );

        let listing = with_token(unsigned_at("GET", &format!("/{BUCKET}?list-type=2&metadata=true")));
        let served = assembled.exchange(listing);
        assert_eq!(served.status, 200, "{floor_name}: {}", served.body);
        assert_eq!(served.reached, ["rustfs:ListObjectsV2WithMetadata"], "{floor_name}");
        assert_eq!(
            spy.0.load(Ordering::SeqCst),
            1,
            "{floor_name}: the verifier answers for an admitting operation"
        );
    }
}
