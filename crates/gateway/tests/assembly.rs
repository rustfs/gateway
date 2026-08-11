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

//! What `ServiceBuilder::build` refuses, and what it accepts.
//!
//! Responsible for: every assembly-time rule, asserted through the public facade only — a missing
//! extension point, an empty registry, a refused registration, a refused route, and the rule
//! reference each of them carries.
//! NOT responsible for: request behaviour, which is `tests/pipeline.rs`.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! Negative cases outnumber positive ones, and deliberately: every refusal here is a mistake that
//! a service which started anyway would turn into a silent run-time behaviour.

use crate::support;

use std::sync::Arc;

use rustfs_gateway::dto::ListBuckets;
use rustfs_gateway::{AssemblyError, OperationSet, RouteEntry, RouteSelector, RuleRef, ServiceBuilder};
use support::{Backend, Impostor, Ping, Unnamespaced, ping_route, wired};

/// a-asm-0016. Negative — an assembly with no operation is refused. A service that answers every request with
/// `501` is a configuration mistake, and starting it hides the mistake until traffic arrives.
#[test]
fn an_empty_registry_is_refused() {
    let error = wired().build().expect_err("nothing is registered");
    assert!(matches!(error, AssemblyError::EmptyRegistry { .. }), "{error}");
    assert_eq!(error.rule(), RuleRef::EMPTY_REGISTRY);
}

/// c-azc-0019 and a-asm-0009/a-asm-0010. Negative — this implementation chooses the design's
/// fallible-build alternative to typestate: no authorizer means no service, with no default allow
/// or default deny.
#[test]
fn a_asm_0009_and_0010_missing_authorizer_is_refused_at_build() {
    let credentials = Arc::new(
        rustfs_gateway::StaticCredentials::new().with(rustfs_gateway::Credentials::new("AKIDEXAMPLE", b"secret").expect("valid")),
    );
    let error = ServiceBuilder::new()
        .register::<ListBuckets, _>(Arc::new(Backend))
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .build()
        .expect_err("no authorizer");
    assert!(matches!(error, AssemblyError::MissingAuthorizer { .. }), "{error}");
    assert_eq!(error.rule(), RuleRef::MISSING_AUTHORIZER);
}

/// Negative — no authenticator, no service. The same asymmetry, one stage earlier.
#[test]
fn a_missing_authenticator_is_refused() {
    let error = ServiceBuilder::new()
        .register::<ListBuckets, _>(Arc::new(Backend))
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .build()
        .expect_err("no authenticator");
    assert!(matches!(error, AssemblyError::MissingAuthenticator { .. }), "{error}");
    assert_eq!(error.rule(), RuleRef::MISSING_AUTHENTICATOR);
}

/// Negative — the empty-registry check runs before the missing-extension-point checks, so an
/// assembly that got everything wrong is told about the registry first rather than about whichever
/// check happens to be written first.
#[test]
fn an_entirely_unconfigured_builder_reports_the_registry() {
    let error = ServiceBuilder::new().build().expect_err("nothing at all");
    assert_eq!(error.rule(), RuleRef::EMPTY_REGISTRY);
}

/// Negative — registering one operation twice is refused rather than silently taking the second
/// backend. A last-write-wins registry would let an ordering change move traffic between backends.
#[test]
fn a_duplicate_registration_is_refused() {
    let backend = Arc::new(Backend);
    let error = wired()
        .register::<ListBuckets, _>(Arc::clone(&backend))
        .register::<ListBuckets, _>(backend)
        .build()
        .expect_err("registered twice");
    assert_eq!(error.rule(), RuleRef::REGISTRATION);
    assert!(error.to_string().contains("ListBuckets"), "{error}");
}

/// a-asm-0014. Negative — a third-party operation whose name has no namespace is refused. Without the rule,
/// a vendor operation can occupy a name AWS has not defined yet.
#[test]
fn a_third_party_name_without_a_namespace_is_refused() {
    let error = wired()
        .register::<Unnamespaced, _>(Arc::new(Backend))
        .build()
        .expect_err("not namespaced");
    assert_eq!(error.rule(), RuleRef::REGISTRATION);
}

/// a-asm-0013. Negative — a third-party operation wearing an AWS name is refused, so requests AWS defines
/// cannot be answered by a handler nobody reviewed.
#[test]
fn a_third_party_name_colliding_with_an_aws_one_is_refused() {
    let error = wired()
        .register::<Impostor, _>(Arc::new(Backend))
        .build()
        .expect_err("collides");
    assert_eq!(error.rule(), RuleRef::REGISTRATION);
}

/// Negative — a route entry claiming an AWS operation name is refused even when nothing is
/// registered under that name: the entry alone would send AWS-defined requests elsewhere.
#[test]
fn a_route_entry_claiming_an_aws_name_is_refused() {
    let error = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(RouteEntry {
            precedence: 50,
            selector: RouteSelector::new(support::PING_PREDICATES),
            op_name: "GetObject",
            path_shape: "/",
        })
        .build()
        .expect_err("claims an AWS name");
    assert_eq!(error.rule(), RuleRef::ROUTE);
    assert!(error.to_string().contains("GetObject"), "{error}");
}

/// a-asm-0015. Negative — a third-party entry that stands in front of a standard operation is refused unless
/// the shadowing is declared. This is the check that stops a vendor route from quietly taking over
/// `ListBuckets`.
#[test]
fn an_undeclared_shadowing_route_is_refused() {
    static SHADOWS_LIST_BUCKETS: &[rustfs_gateway::Predicate] = &[
        rustfs_gateway::Predicate::Method(http::Method::GET),
        rustfs_gateway::Predicate::Target(rustfs_gateway::TargetKind::Service),
    ];
    let error = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(RouteEntry {
            precedence: 10,
            selector: RouteSelector::new(SHADOWS_LIST_BUCKETS),
            op_name: "example:Ping",
            path_shape: "/",
        })
        .build()
        .expect_err("shadows ListBuckets");
    assert_eq!(error.rule(), RuleRef::ROUTE);
    assert!(error.to_string().contains("ListBuckets"), "{error}");
}

/// Negative — `require` names what is missing, and it refuses before `build` is even reached.
#[test]
fn requiring_an_unregistered_operation_is_refused() {
    let missing = wired()
        .register::<ListBuckets, _>(Arc::new(Backend))
        .require(&OperationSet::of(["ListBuckets", "GetObject"]))
        .expect_err("GetObject is not registered");
    assert!(missing.to_string().contains("GetObject"), "{missing}");
}

/// a-asm-0017. Negative — every refusal carries a rule reference in the `asm-` namespace, and the rendered
/// message leads with it. A refusal a reader cannot look up is a refusal they cannot act on.
#[test]
fn every_refusal_is_greppable_by_its_rule() {
    let refusals: Vec<AssemblyError> = vec![
        ServiceBuilder::new().build().expect_err("empty"),
        wired().build().expect_err("empty"),
        wired()
            .register::<Unnamespaced, _>(Arc::new(Backend))
            .build()
            .expect_err("not namespaced"),
    ];
    for refusal in refusals {
        let rule = refusal.rule();
        assert!(rule.as_str().starts_with("asm-"), "{rule}");
        assert!(refusal.to_string().starts_with(&format!("[{rule}]")), "{refusal}");
    }
}

/// a-asm-0001. Positive — the smallest complete assembly builds, and the service reports what it answers.
#[test]
fn a_complete_assembly_builds() {
    let service = support::service();
    let operations: Vec<&str> = service.operations().collect();
    assert_eq!(operations, ["ListBuckets", "example:ContentPing", "example:HeadPing", "example:Ping"]);
}

/// a-asm-0001. Positive — cloning a service is one pointer's worth of work, which is what makes cloning it per
/// connection the right thing for a server to do.
#[test]
fn the_service_is_one_arc_wide_and_cheap_to_clone() {
    assert_eq!(core::mem::size_of::<rustfs_gateway::S3Service>(), core::mem::size_of::<usize>());
    let service = support::service();
    let clones: Vec<_> = (0..1_000).map(|_| service.clone()).collect();
    assert_eq!(clones.len(), 1_000);
}

/// Positive — a vendor operation with a namespaced name, its own floor and a non-overlapping route
/// assembles alongside the AWS operations.
#[test]
fn a_vendor_operation_assembles_beside_the_aws_ones() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    assert_eq!(service.operations().collect::<Vec<_>>(), ["example:Ping"]);
}

/// Negative — a fixed wall clock far from the system clock cannot silently reach production.
#[test]
fn a_large_custom_clock_skew_is_refused_at_assembly() {
    let error = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .clock(rustfs_gateway::FixedClock::at_unix_seconds(1))
        .build()
        .expect_err("the clock is decades away from the system clock");
    assert_eq!(error.rule(), RuleRef::CLOCK_SKEW);
}

/// Negative — the escape hatch is explicit and remains visible in the assembled posture.
#[test]
fn an_acknowledged_custom_clock_is_named_in_the_posture() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .clock_with_skew_ack(
            rustfs_gateway::FixedClock::at_unix_seconds(1),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("the skew was explicitly acknowledged");
    assert_eq!(service.clock_posture(), rustfs_gateway::ClockPosture::CustomAcknowledged);
}

/// Negative — even a custom source within the allowed skew remains visible in the posture.
#[test]
fn a_checked_custom_clock_is_named_in_the_posture() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .clock(rustfs_gateway::system_clock())
        .build()
        .expect("the custom source agrees with system time");
    assert_eq!(service.clock_posture(), rustfs_gateway::ClockPosture::CustomChecked);
}
