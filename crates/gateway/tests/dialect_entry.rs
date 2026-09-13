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

//! Proves that vendor codecs cannot enter the public service through an unverified route.
//!
//! Responsible for: the facade-level dialect registration boundary.
//! NOT responsible for: dialect extension fields or vendor wire semantics.
//! Upstream: the public service builder and a real test codec.
//! Downstream: the assembled service result.

use std::sync::Arc;

use crate::support::{self, Backend, Ping, ping_route, wired};
use http::Method;
use rustfs_gateway_core::{
    Dialect, DialectOverlay, DialectRoute, HostClass, OverlayRow, Predicate, ResourceShape, RouteEntry, RouteSelector, TargetKind,
};

static PING_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example",
    vendor: "example",
    claims: &[],
    operations: &[OverlayRow {
        name: "example:Ping",
        precedence: 50,
        selector: "Method(POST) ∧ Target(Service)",
        action: "example:Ping",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

static RESERVED_PING_PREDICATES: &[Predicate] = &[
    Predicate::Method(Method::POST),
    Predicate::Target(TargetKind::Service),
    Predicate::HostClass(HostClass::S3Express),
];

fn ping_dialect() -> Dialect {
    Dialect::assemble(&PING_OVERLAY)
        .declare::<Ping>(DialectRoute {
            precedence: 50,
            selector: support::PING_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .expect("the test dialect repeats the codec's exact reviewed facts")
}

fn assert_unverified(result: Result<rustfs_gateway::S3Service, rustfs_gateway::AssemblyError>) {
    let error = result.expect_err("the unverified wire route must fail closed");
    assert!(
        format!("{error:?}").contains("UnverifiedCodecRoute"),
        "the refusal must identify the missing dialect proof: {error:?}"
    );
}

#[test]
fn raw_route_and_handler_cannot_bypass_dialect_proof() {
    let result = wired().route(ping_route()).register::<Ping, _>(Arc::new(Backend)).build();

    assert_unverified(result);
}

#[test]
fn raw_reserved_host_route_cannot_bypass_dialect_proof() {
    let result = wired()
        .route(RouteEntry {
            precedence: 50,
            selector: RouteSelector::new(RESERVED_PING_PREDICATES),
            op_name: "example:Ping",
            path_shape: "/",
        })
        .register::<Ping, _>(Arc::new(Backend))
        .build();

    assert_unverified(result);
}

#[test]
fn a_dialect_proof_does_not_cover_a_different_raw_row() {
    let dialect = ping_dialect();
    let mut different = ping_route();
    different.precedence += 1;
    let result = wired()
        .dialect(&dialect)
        .route(different)
        .register::<Ping, _>(Arc::new(Backend))
        .build();

    assert_unverified(result);
}

#[test]
fn validated_dialect_and_real_codec_install_together() {
    let dialect = ping_dialect();
    let result = wired().dialect(&dialect).register::<Ping, _>(Arc::new(Backend)).build();

    assert!(result.is_ok(), "the exact validated dialect row must install: {result:?}");
}
