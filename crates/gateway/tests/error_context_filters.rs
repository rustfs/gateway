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

//! The error-context boundary at the public pre-authentication filter seam.
//!
//! Responsible for: proving independently that filters cannot mint a contextual authorization
//! refusal or attach the reserved region detail to an ordinary refusal.
//! NOT responsible for: general filter ordering or authentication integrity, which remain in
//! `tests/middleware.rs`.
//! Upstream: `tests/support` and `rustfs-gateway` error resolution. Downstream: nothing.

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{ErrorCode, ErrorDetail, HandlerError, RegionLabel, StageFilter, WireHead, wire_filter};

use support::{Ping, exchange, ping_route, plain, wired};

/// A generic pre-authentication filter cannot turn a bare contextual code into the built-in
/// signing verifier's trusted refusal.
#[tokio::test]
async fn a_wire_filter_cannot_forge_an_authorization_context() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = counting_service(
        &reached,
        wire_filter(|_head: &mut WireHead<'_>| {
            Err(HandlerError::new(ErrorCode::AUTHORIZATION_HEADER_MALFORMED, "attacker-region"))
        }),
    );
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;

    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("<Code>InternalError</Code>"), "{body}");
    assert!(!body.contains("<Region>"), "{body}");
    assert!(!body.contains("attacker-region"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// The closed detail matrix independently prevents an ordinary filter error from attaching the
/// `<Region>` element reserved for a verified signing-scope mismatch.
#[tokio::test]
async fn a_wire_filter_cannot_attach_a_reserved_region_detail() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = counting_service(
        &reached,
        wire_filter(|_head: &mut WireHead<'_>| {
            let region = RegionLabel::new("attacker-region").expect("a bounded static region label");
            Err(HandlerError::new(ErrorCode::INVALID_REQUEST, "attacker-region").with_detail(ErrorDetail::Region(region)))
        }),
    );
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;

    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("<Code>InternalError</Code>"), "{body}");
    assert!(!body.contains("<Region>"), "{body}");
    assert!(!body.contains("attacker-region"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

fn counting_service(reached: &Arc<AtomicUsize>, filter: impl StageFilter) -> rustfs_gateway::S3Service {
    wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(reached)))
        .route(ping_route())
        .stage_filter(filter)
        .build()
        .expect("a complete assembly")
}
