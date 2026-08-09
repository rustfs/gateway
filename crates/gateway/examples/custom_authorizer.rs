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

//! c-azc-0008: an `Authorizer` that reads a policy snapshot, and an audit sink that watches it.
//!
//! Responsible for: showing the three things the extension point's contract is about — the third
//! verdict state, the per-request policy snapshot, and the audit hook — in code that is meant to be
//! copied.
//! NOT responsible for: being a policy language. `Grants` below is a set of `(principal, action)`
//! pairs, deliberately trivial: this framework does not evaluate IAM policy and never will, and an
//! example that pretended otherwise would be a specification nobody wrote.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! Run it with `cargo run -p rustfs-gateway --example custom_authorizer`.
//!
//! # The one thing to copy carefully
//!
//! `Grants::lookup` returns `Option<bool>`, and the `None` arm becomes [`Decision::Indeterminate`]
//! rather than [`Decision::Deny`]. That is the whole discipline: when your store cannot answer, say
//! so. The framework refuses the request either way, so nothing is lost on the wire — but the audit
//! trail can tell an operator "your policy store is down" instead of "this caller keeps being
//! refused", and those are different pages.
//!
//! **There is no allow-all in this file, and there must never be one.**
//! `scripts/check_authz_fail_closed.sh` fails the build if one appears in `examples/`: a
//! copy-pasteable `|_| true` is the single most effective way to ship a gateway with no
//! authorisation at all.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustfs_gateway::{
    AuthRequirement, Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, BoxFuture, CodecError, Credentials, Decision,
    DerivedResourceError, EncodedResponse, Handler, HandlerResult, Identity, InputAuthzRequest, InputDecisions, MetaView,
    NoDerived, Operation, OperationCodec, OperationFloor, OperationSpec, PolicyError, PolicySnapshot, PolicySource, Predicate,
    RegionSet, Req, RequestBody, RequestContext, ResourceShape, Resp, ResponseBody, RouteEntry, RouteSelector, ServiceBuilder,
    SigService, SigV4Authenticator, StaticCredentials, TargetKind,
};

// ── a vendor operation, so the example reaches authorisation without signing anything ──────────
//
// Every AWS operation is header-signatures-only and this crate cannot mint a signature in an
// example yet, so an anonymous `GET /` never reaches the authorizer at all — it is refused one
// stage earlier. The operation below declares itself anonymously reachable, in the one method whose
// name says what that costs, so that the three properties this file is about are visible.

/// A vendor operation with no input and no body.
struct Ping;

/// What `example:Ping` decodes to.
struct PingInput;

/// What `example:Ping` answers with.
struct PingOutput;

static PING_SPEC: OperationSpec = OperationSpec {
    name: "example:Ping",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:Ping", ResourceShape::Service)),
};

static PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:Ping", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

static PING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::POST), Predicate::Target(TargetKind::Service)];

impl Operation for Ping {
    const NAME: &'static str = "example:Ping";

    type Input = PingInput;
    type Output = PingOutput;
    type DerivedResources = NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &PING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &PING_FLOOR
    }
}

impl OperationCodec for Ping {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<PingInput, CodecError> {
        Ok(PingInput)
    }

    fn encode(_output: PingOutput, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.set_header("content-type", "application/xml");
        encoded.body = ResponseBody::Complete(b"<Ping>pong</Ping>".to_vec());
        Ok(encoded)
    }
}

/// The deployment's own policy type. The framework never looks inside it.
#[derive(Debug, Default)]
struct Grants {
    allowed: BTreeSet<(String, String)>,
    /// Whether this reading is complete. A partial reading answers `None` for everything it does
    /// not know about, which is the difference between "denied" and "could not tell".
    complete: bool,
}

impl Grants {
    /// `Some(true)` allowed, `Some(false)` refused, **`None` could not be determined**.
    fn lookup(&self, principal: &str, action: &str) -> Option<bool> {
        let hit = self.allowed.contains(&(principal.to_owned(), action.to_owned()));
        if hit {
            return Some(true);
        }
        // A miss against an incomplete reading is not a refusal — it is a question this reading
        // cannot answer.
        if self.complete { Some(false) } else { None }
    }
}

/// Reads policy once per request. The framework calls this exactly once, before the authorizer.
struct GrantStore {
    /// A real deployment reaches a store here. This one holds the answer and a switch that makes
    /// the store "unavailable", so both directions are visible when the example runs.
    reachable: bool,
}

impl PolicySource for GrantStore {
    fn snapshot<'a>(&'a self, identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        let reachable = self.reachable;
        let principal = identity.map(|identity| identity.access_key_id().to_owned());
        Box::pin(async move {
            if !reachable {
                // Becomes `Decision::Indeterminate`, which the framework renders as `403`. Never a
                // `500`: a `5xx` is the status a front end retries, and some of them fail open.
                return Err(PolicyError::unavailable());
            }
            let mut grants = Grants {
                complete: true,
                ..Grants::default()
            };
            // Anonymous is a principal, and this deployment grants it exactly one action.
            grants
                .allowed
                .insert((principal.unwrap_or_else(|| "anonymous".to_owned()), "example:Ping".to_owned()));
            Ok(PolicySnapshot::of(Arc::new(grants)))
        })
    }
}

/// The extension point itself: one decision, three possible answers.
struct GrantAuthorizer;

impl Authorizer for GrantAuthorizer {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        // Anonymous is a principal like any other. It is not a reason to skip the check — rustfs's
        // GHSA-5qfg-mf7r-jp3w is what skipping looks like — it is simply a principal that is
        // granted almost nothing.
        let principal = request.identity.map_or("anonymous", Identity::access_key_id);
        let decision = match context.policy().get::<Grants>() {
            Some(grants) => match grants.lookup(principal, request.action) {
                Some(true) => Decision::Allow,
                Some(false) => Decision::Deny,
                // The store answered, and the answer was "I do not know". Say so.
                None => Decision::Indeterminate,
            },
            // No `Grants` in the snapshot means this service was assembled with a policy source
            // this authorizer does not understand. That is a misassembly, and a misassembly must
            // not be read as permission.
            None => Decision::Indeterminate,
        };
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = decide(context.policy(), request.route());
        let decisions = request.decide_all(stage, |resource| decide(context.policy(), resource));
        Box::pin(async move { decisions })
    }
}

fn decide(policy: &PolicySnapshot, request: &AuthzRequest<'_>) -> Decision {
    let principal = request.identity.map_or("anonymous", Identity::access_key_id);
    match policy.get::<Grants>() {
        Some(grants) => match grants.lookup(principal, request.action) {
            Some(true) => Decision::Allow,
            Some(false) => Decision::Deny,
            None => Decision::Indeterminate,
        },
        None => Decision::Indeterminate,
    }
}

/// The audit hook. It observes and returns nothing; it cannot change what was decided.
struct PrintingAudit;

impl AuthzAuditSink for PrintingAudit {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        println!(
            "authz request_id={} principal={} operation={} stage={:?} resources={} target_origin={} snapshot={:?} decision={}",
            event.request_id,
            event.identity.map_or("anonymous", Identity::access_key_id),
            event.operation,
            event.stage,
            event.resources.len(),
            event.target_origin.as_str(),
            event.policy_snapshot.map(rustfs_gateway::SnapshotId::get),
            event.decision.as_str(),
        );
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Both directions, asserted rather than printed: the store that answers allows the one action
    // it grants, and the store that cannot answer refuses. An example whose output nobody reads is
    // an example that stops being true.
    for (reachable, expected) in [(true, http::StatusCode::OK), (false, http::StatusCode::FORBIDDEN)] {
        let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret")?));
        let service = ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"])?))
            .authorizer(GrantAuthorizer)
            .policy_source(GrantStore { reachable })
            .authz_audit(PrintingAudit)
            .register::<Ping, _>(Arc::new(Pong))
            .route(RouteEntry {
                precedence: 50,
                selector: RouteSelector::new(PING_PREDICATES),
                op_name: "example:Ping",
                path_shape: "/",
            })
            .build()?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/")
            .header("host", "s3.example.com")
            .body(bytes::Bytes::new())?;
        let response = service.call_bytes(request).await;
        println!("policy store reachable={reachable} -> {}\n", response.status());
        assert_eq!(response.status(), expected, "policy store reachable={reachable}");
    }
    Ok(())
}

/// A backend, so that an allowed request has somewhere to go.
struct Pong;

impl Handler<Ping> for Pong {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Ok(Resp::new(PingOutput))
    }
}
