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

//! What the deployment is told about an authorisation decision it did not make.
//!
//! Responsible for: [`AuthzAuditEvent`] — the record the *framework* builds, so that no field can
//! be left out by an implementation that did not think of it — the [`AuthzAuditSink`] that receives
//! one, and the default [`NoAuthzAudit`].
//! NOT responsible for: making the decision (`crate::ext::authorizer`), rendering the refusal
//! (`crate::render`), or persisting anything. Where an event goes is the sink's whole job and this
//! module has no opinion about it.
//! Upstream: `crate::ext::authorizer`, `crate::ext::policy`, `crate::trace`. Downstream:
//! `crate::service`, which is the only producer of an event.
//!
//! # Why a sink cannot change the decision, and how that is kept true
//!
//! [`AuthzAuditSink::on_decision`] takes `&self` and a shared reference, and returns `()`. There is
//! nothing to hand back, so an implementation that wanted to overturn a refusal would have nothing
//! to overturn it with. That is the type-level half. The other half is positional: `crate::service`
//! settles the verdict into an outcome **before** the sink is called, so even a future change that
//! gave the sink something to say would be saying it after the answer was chosen.
//!
//! `scripts/check_authz_fail_closed.sh` asserts the signature, because a returning `on_decision` is
//! a one-line change and the reason it must not happen is three paragraphs long. The runtime half
//! is `crates/gateway/tests/authz_contract.rs`, which compares a service with a sink installed
//! against one without and requires the two responses to be the same bytes.
//!
//! # Why the event is built here and not by the sink
//!
//! An audit trail assembled by whoever happens to be logging is an audit trail with a different
//! field set per deployment, and the fields that go missing are the ones nobody needed until an
//! incident. The framework therefore constructs the whole record: who, what operation, what action,
//! which target, **where the target's name came from**, which reading of policy, and what was
//! decided. A sink chooses what to do with it and not what is in it.
//!
//! `target_origin` is the field that is easy to leave out and expensive to lack. `bucket` in an
//! access log is ambiguous between `Host: bucket.example.com` and `GET /bucket/…`, and a routing
//! dispute is precisely an argument about which of the two happened.
//!
//! # Why the event carries no policy text and no signature
//!
//! It carries [`crate::SnapshotId`], not the snapshot: an identifier joins two events to one
//! reading without putting a policy document into a log aggregator. It carries the caller's access
//! key id, which is the public half of a credential and the only value an operator can look a
//! caller up by; it carries no secret, no session token and no signature. `crates/gateway`'s
//! `n_an_audit_event_carries_no_secret_and_no_policy_text` is the assertion.

use core::time::Duration;

use rustfs_gateway_core::ResourceShape;
use rustfs_gateway_sig::Identity;
use rustfs_gateway_types::{BucketName, ObjectKey};

use crate::ext::authorizer::Decision;
use crate::ext::host::TargetOrigin;
use crate::ext::policy::SnapshotId;
use crate::trace::RequestId;

use super::{AuthSchemeRef, AuthzRequest};

/// Which authorization boundary produced an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthzStage {
    /// The action and primary route resource, before the body is read.
    Route,
    /// The decoded input and all resources derived from it.
    Input,
}

/// One authorisation decision, as the framework saw it.
///
/// Borrowed throughout for the reason [`crate::AuthzRequest`] is: the value lives for one call, and
/// a sink that needs to keep something copies the field it needs rather than paying for every
/// field it does not.
#[derive(Debug)]
pub struct AuthzAuditEvent<'a> {
    /// The identifier the response went out with, and the one the caller received. This is what
    /// joins an audit line to a support ticket.
    pub request_id: &'a RequestId,
    /// Which of the two mandatory authorization stages produced this event.
    pub stage: AuthzStage,
    /// The operation routing chose, by its `Operation::NAME`.
    pub operation: &'a str,
    /// The IAM action the operation declares, in its wire spelling.
    pub action: &'a str,
    /// What the action is about.
    pub resource: ResourceShape,
    /// The bucket the request addressed, when it addressed one.
    pub bucket: Option<&'a BucketName>,
    /// The object key the request addressed, when it addressed one.
    pub key: Option<&'a ObjectKey>,
    /// Every resource relevant to this stage. Input-stage events include the route target followed
    /// by every normalized derived resource.
    pub resources: &'a [AuthzRequest<'a>],
    /// Whether authentication was verified, or [`AuthSchemeRef::Anonymous`].
    pub auth_scheme: AuthSchemeRef,
    /// Who the request ran as. `None` is an anonymous caller — a request that presented nothing and
    /// was confirmed to have presented nothing, never one whose verification failed.
    pub identity: Option<&'a Identity>,
    /// Whether the bucket name came out of the `Host` header or out of the path.
    pub target_origin: TargetOrigin,
    /// Which reading of policy the decision was made against.
    ///
    /// `None` means there was no reading: the [`crate::PolicySource`] could not answer, which is
    /// the case that produced [`Decision::Indeterminate`] without the authorizer ever being asked.
    /// That distinction is invisible on the wire — both are one `403` — and this field is where an
    /// operator finds it.
    pub policy_snapshot: Option<SnapshotId>,
    /// What was decided. All three states are reported, including the two the caller cannot tell
    /// apart: `Deny` and `Indeterminate` are one `403` on the wire, and an operator investigating a
    /// refusal needs to know which of the two it was.
    pub decision: Decision,
    /// Time spent obtaining and applying the decision for this stage.
    pub elapsed: Duration,
}

/// Receives every authorisation decision, and changes none of them.
///
/// **If you need to change an answer, write an [`crate::Authorizer`].** `on_decision` takes shared
/// references and returns nothing; it is called after the outcome has been settled; and the
/// framework reads nothing back from it. See the module documentation for why that is three
/// separate mechanisms rather than one.
///
/// Synchronous, on the same reasoning as [`crate::Observer`]: it runs on the path of every request,
/// it cannot influence the request, and the natural implementation hands the event to a channel and
/// returns. An implementation that must do I/O does it in its own task, visibly.
///
/// Held as `Arc<dyn AuthzAuditSink>` so the service stays non-generic over it.
pub trait AuthzAuditSink: Send + Sync + 'static {
    /// Records one decision.
    ///
    /// **Must not panic.** The framework isolates a panic so it cannot change the response, but the
    /// event is lost. Keep the implementation to a `push` onto a queue.
    fn on_decision(&self, event: &AuthzAuditEvent<'_>);
}

pub(crate) fn emit_safely(sink: &dyn AuthzAuditSink, event: &AuthzAuditEvent<'_>) {
    crate::panic_boundary::contain_report("authorization audit sink", || sink.on_decision(event));
}

pub(crate) fn emit_input_safely(
    sink: &dyn AuthzAuditSink,
    event: &AuthzAuditEvent<'_>,
    visibility: Option<(&AuthzRequest<'_>, Decision)>,
) {
    emit_safely(sink, event);
    if let Some((request, decision)) = visibility {
        emit_safely(
            sink,
            &AuthzAuditEvent {
                request_id: event.request_id,
                stage: AuthzStage::Input,
                operation: event.operation,
                action: request.action,
                resource: request.resource,
                bucket: request.bucket,
                key: request.key,
                resources: std::slice::from_ref(request),
                auth_scheme: event.auth_scheme,
                identity: event.identity,
                target_origin: event.target_origin,
                policy_snapshot: event.policy_snapshot,
                decision,
                elapsed: event.elapsed,
            },
        );
    }
}

impl<T: AuthzAuditSink + ?Sized> AuthzAuditSink for std::sync::Arc<T> {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        (**self).on_decision(event);
    }
}

/// The default: no authorisation decision is recorded anywhere.
///
/// It cannot widen access — it removes a defence rather than opening a door — but a deployment
/// running with it has no answer to "who was refused, and against which policy". `crate::ext`'s
/// table of defaults says the same thing about [`crate::NoObserver`].
pub struct NoAuthzAudit;

impl AuthzAuditSink for NoAuthzAudit {
    fn on_decision(&self, _event: &AuthzAuditEvent<'_>) {}
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::ext::policy::PolicySnapshot;
    use crate::trace::MintedTraces;
    use crate::trace::TraceSource;

    fn event_with(decision: Decision, snapshot: Option<SnapshotId>, request_id: &RequestId) -> AuthzAuditEvent<'_> {
        AuthzAuditEvent {
            request_id,
            stage: AuthzStage::Route,
            operation: "example:Ping",
            action: "example:Ping",
            resource: ResourceShape::Service,
            bucket: None,
            key: None,
            resources: &[],
            auth_scheme: AuthSchemeRef::Anonymous,
            identity: None,
            target_origin: TargetOrigin::Path,
            policy_snapshot: snapshot,
            decision,
            elapsed: Duration::ZERO,
        }
    }

    /// Negative — the default sink records nothing and answers nothing. The assertion is that it
    /// is reachable and inert, which is the only claim it makes.
    #[test]
    fn n_the_default_sink_is_inert() {
        let trace = MintedTraces::new().mint();
        let snapshot = PolicySnapshot::empty();
        let sink: Box<dyn AuthzAuditSink> = Box::new(NoAuthzAudit);
        // Returns `()`: there is nothing to bind, which is the property this test is about.
        sink.on_decision(&event_with(Decision::Deny, Some(snapshot.id()), trace.request_id()));
    }

    /// Negative — a sink sees every state, and the two states the wire collapses into one `403`
    /// arrive here distinguishable. A sink stuck on one answer would satisfy nothing below.
    #[test]
    fn n_a_sink_sees_all_three_states_apart() {
        #[derive(Default)]
        struct Seen(Mutex<Vec<Decision>>, AtomicUsize);
        impl AuthzAuditSink for Seen {
            fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
                self.1.fetch_add(1, Ordering::SeqCst);
                self.0.lock().expect("not poisoned").push(event.decision);
            }
        }
        let trace = MintedTraces::new().mint();
        let snapshot = PolicySnapshot::empty();
        let sink = Seen::default();
        for decision in [Decision::Allow, Decision::Deny, Decision::Indeterminate] {
            sink.on_decision(&event_with(decision, Some(snapshot.id()), trace.request_id()));
        }
        assert_eq!(sink.1.load(Ordering::SeqCst), 3);
        assert_eq!(
            sink.0.lock().expect("not poisoned").as_slice(),
            [Decision::Allow, Decision::Deny, Decision::Indeterminate]
        );
    }

    /// Negative — the whole event renders without a policy document in it, because the only thing
    /// it holds about policy is an identifier.
    #[test]
    fn n_the_event_renders_no_policy_text() {
        let trace = MintedTraces::new().mint();
        let snapshot = PolicySnapshot::of(std::sync::Arc::new(String::from("Allow s3:* on everything")));
        let rendered = format!("{:?}", event_with(Decision::Deny, Some(snapshot.id()), trace.request_id()));
        assert!(!rendered.contains("Allow s3:*"), "{rendered}");
        assert!(rendered.contains(&snapshot.id().to_string()), "{rendered}");
    }

    /// Negative — the auxiliary visibility verdict is audited as its own ListBucket decision, not
    /// hidden inside the admitted GetObject event or omitted because it does not gate the handler.
    #[test]
    fn n_a_missing_object_visibility_decision_is_a_separate_audit_event() {
        #[derive(Default)]
        struct Seen(Mutex<Vec<(String, Decision, Option<String>)>>);
        impl AuthzAuditSink for Seen {
            fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
                self.0.lock().expect("not poisoned").push((
                    event.action.to_owned(),
                    event.decision,
                    event.key.map(|key| key.as_str().to_owned()),
                ));
            }
        }

        let trace = MintedTraces::new().mint();
        let snapshot = PolicySnapshot::empty();
        let bucket = crate::BucketName::new("example-bucket").expect("a valid bucket name");
        let key = crate::ObjectKey::new("private/report.txt").expect("a valid object key");
        let request = AuthzRequest {
            operation: "GetObject",
            action: "s3:ListBucket",
            resource: ResourceShape::Bucket,
            bucket: Some(&bucket),
            key: Some(&key),
            copy_source_identity: None,
            version_id: None,
            route_action: "s3:GetObject",
            route_bucket: Some(&bucket),
            route_key: Some(&key),
            identity: None,
            target_origin: TargetOrigin::Path,
            subject: None,
        };
        let mut event = event_with(Decision::Allow, Some(snapshot.id()), trace.request_id());
        event.stage = AuthzStage::Input;
        event.operation = "GetObject";
        event.action = "s3:GetObject";

        let sink = Seen::default();
        emit_input_safely(&sink, &event, Some((&request, Decision::Deny)));
        assert_eq!(
            sink.0.lock().expect("not poisoned").as_slice(),
            [
                ("s3:GetObject".to_owned(), Decision::Allow, None),
                ("s3:ListBucket".to_owned(), Decision::Deny, Some("private/report.txt".to_owned())),
            ]
        );
    }
}
