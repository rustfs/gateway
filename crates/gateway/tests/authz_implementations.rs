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

//! Shipped authorization implementations and closure adapters.
//!
//! Responsible for: proving the concrete authorizers decide in both directions and work through
//! the public contract. NOT responsible for: service-pipeline ordering or wire responses, covered
//! by `authz_contract.rs`. Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used)]

use futures_util::FutureExt;
use rustfs_gateway::{
    Authorizer, AuthzRequest, Decision, DenyAllAuthorizer, Identity, PolicySnapshot, RequestContext, ResourceShape, TargetOrigin,
    allow_when, decide_with,
};

fn request<'a>(caller: Option<&'a Identity>, shape: ResourceShape) -> AuthzRequest<'a> {
    AuthzRequest {
        operation: "example:Ping",
        action: "example:Ping",
        resource: shape,
        bucket: None,
        key: None,
        copy_source_identity: None,
        version_id: None,
        route_action: "example:Ping",
        route_bucket: None,
        route_key: None,
        identity: caller,
        target_origin: TargetOrigin::Path,
        subject: None,
    }
}

/// Negative — the shipped deny-all authorizer refuses every principal and resource shape.
#[tokio::test]
async fn n_deny_all_denies_every_shape() {
    let identity = Identity::new("AKIDEXAMPLE").expect("a valid access key id");
    let snapshot = PolicySnapshot::empty();
    let context = RequestContext::new(rustfs_gateway::RequestNow::from_unix_seconds(0), &snapshot);
    for caller in [None, Some(&identity)] {
        for shape in [ResourceShape::Service, ResourceShape::Bucket, ResourceShape::Object] {
            assert_eq!(DenyAllAuthorizer.authorize_route(&context, &request(caller, shape)).await, Decision::Deny);
        }
    }
}

/// c-azc-0007. Positive — closure adapters preserve the same decisions as a named implementation.
#[tokio::test]
async fn n_the_closure_adapters_are_not_one_directional() {
    let identity = Identity::new("AKIDEXAMPLE").expect("a valid access key id");
    let snapshot = PolicySnapshot::empty();
    let context = RequestContext::new(rustfs_gateway::RequestNow::from_unix_seconds(0), &snapshot);
    let predicate = allow_when(|request| !request.is_anonymous());
    assert_eq!(
        predicate
            .authorize_route(&context, &request(Some(&identity), ResourceShape::Service))
            .await,
        Decision::Allow
    );
    assert_eq!(
        predicate
            .authorize_route(&context, &request(None, ResourceShape::Service))
            .await,
        Decision::Deny
    );
    let three = decide_with(|request| match request.identity {
        Some(_) => Decision::Allow,
        None => Decision::Indeterminate,
    });
    assert_eq!(
        three
            .authorize_route(&context, &request(Some(&identity), ResourceShape::Service))
            .await,
        Decision::Allow
    );
    assert_eq!(
        three.authorize_route(&context, &request(None, ResourceShape::Service)).await,
        Decision::Indeterminate
    );
}

/// A fallible closure route keeps the legacy allocation cost for all three decisions.
#[test]
fn n_fallible_closure_routes_add_no_allocation() {
    const ENV: &str = "RUSTFS_GATEWAY_AUTHORIZER_ALLOCATION_PROBE";
    const SENTINEL: &str = "rustfs-gateway authorizer allocation probe: ";
    const TEST: &str = "authz_implementations::n_fallible_closure_routes_add_no_allocation";
    const SHORT: usize = 16;
    const LONG: usize = 144;
    if let Some(counts) = crate::support::allocations::requested_sizes(ENV) {
        let authorizer = decide_with(|request| match request.resource {
            ResourceShape::Service => Decision::Allow,
            ResourceShape::Bucket => Decision::Deny,
            ResourceShape::Object => Decision::Indeterminate,
        });
        let snapshot = PolicySnapshot::empty();
        let context = RequestContext::new(rustfs_gateway::RequestNow::from_unix_seconds(0), &snapshot);
        for count in counts {
            let mut blocks = [0; 2];
            for (fallible, total) in [false, true].into_iter().zip(&mut blocks) {
                let profiler = dhat::Profiler::builder().testing().build();
                for _ in 0..count {
                    for (shape, expected) in [
                        (ResourceShape::Service, Decision::Allow),
                        (ResourceShape::Bucket, Decision::Deny),
                        (ResourceShape::Object, Decision::Indeterminate),
                    ] {
                        let question = request(None, shape);
                        let decision = if fallible {
                            authorizer
                                .authorize_route_result(&context, &question)
                                .now_or_never()
                                .expect("a synchronous decision")
                                .expect("a closure decision succeeds")
                        } else {
                            authorizer
                                .authorize_route(&context, &question)
                                .now_or_never()
                                .expect("a synchronous decision")
                        };
                        assert_eq!(decision, expected);
                    }
                }
                *total = dhat::HeapStats::get().total_blocks;
                drop(profiler);
            }
            crate::support::allocations::report(SENTINEL, &blocks);
        }
        return;
    }
    let rows = crate::support::allocations::measure(TEST, ENV, SENTINEL, &[SHORT, LONG], 2);
    let legacy = rows[1][0] - rows[0][0];
    let fallible = rows[1][1] - rows[0][1];
    assert!(legacy >= (LONG - SHORT) as u64, "the allocator must observe the legacy route futures");
    assert_eq!(fallible, legacy, "fallible closure routes must keep one future per decision");
}
