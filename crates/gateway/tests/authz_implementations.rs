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
