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

//! Authorization request builders, audit emission, and handler context assembly.
//!
//! Responsible for: constructing route-stage and input-stage [`AuthzRequest`] sets, collecting
//! profile-required extra permissions, emitting route and input authorization audit events, and
//! assembling the handler [`RequestContextView`].
//! NOT responsible for: taking policy snapshots, calling the authorizer, checking bucket owners,
//! holding the failure floor, or advancing `RequestConfig` stages (all owned by `super::S3Service`).
//! Upstream: `super::S3Service::run`. Downstream: `crate::ext::authz_audit` and `rustfs_gateway_core`.

use std::time::Duration;

use http::HeaderMap;
use rustfs_gateway_core::authz::ExtraPermission;
use rustfs_gateway_core::{
    Addressed, AuthRequirement, Decision, HandlerError, MetaView, OwnedResource, PathParams, PostObjectSuccessCheck,
    RequestContextView, ResourceShape, ResponseKind, Subject, Subjects,
};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_sig::post_policy::PostKeyConstraints;
use rustfs_gateway_sig::{Identity, SecretBytes, Verdict};
use rustfs_gateway_types::ObjectKey;

use crate::builder::view_policy::ViewPolicy;
use crate::close::ConnectionIntent;
use crate::ext::{AuthSchemeRef, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, AuthzStage, InputAuthzRequest, emit_safely};
use crate::render::{S3Error, from_handler};
use crate::{RequestId, SnapshotId, TargetOrigin};

/// The route-stage authorization question(s): a stack-allocated primary request plus optional extras.
pub(super) struct RouteQuestions<'a> {
    pub(super) primary: AuthzRequest<'a>,
    expanded: Vec<AuthzRequest<'a>>,
}

impl<'a> RouteQuestions<'a> {
    /// Builds the route-stage authorization questions for one operation and subject list.
    #[allow(clippy::too_many_arguments)] // All inputs are borrowed request facts from the pipeline.
    pub(super) fn build(
        operation: &'static str,
        requirement: AuthRequirement,
        meta: &'a MetaView<'a>,
        effective_key: Option<&'a ObjectKey>,
        asked_version: Option<&'a str>,
        identity: Option<&'a Identity>,
        target_origin: TargetOrigin,
        subjects: Option<&'a Subjects>,
    ) -> Self {
        let first = requirement.question(subjects, 0);
        let first_action = first.map_or(requirement.action, |question| question.action);
        let primary = AuthzRequest {
            operation,
            action: first_action,
            resource: requirement.resource,
            bucket: meta.bucket(),
            key: effective_key,
            copy_source_identity: None,
            version_id: asked_version,
            route_action: first_action,
            route_bucket: meta.bucket(),
            route_key: effective_key,
            identity,
            target_origin,
            subject: first.and_then(|question| question.subject),
        };
        let question_count = requirement.question_count(subjects);
        let expanded = if question_count > 1 {
            (0..question_count)
                .filter_map(|index| requirement.question(subjects, index))
                .map(|question| AuthzRequest {
                    action: question.action,
                    route_action: question.action,
                    subject: question.subject,
                    ..primary
                })
                .collect()
        } else {
            Vec::new()
        };
        Self { primary, expanded }
    }

    /// The slice of route questions to ask (zero-allocation for single-question operations).
    pub(super) fn as_slice(&self) -> &[AuthzRequest<'a>] {
        if self.expanded.is_empty() {
            std::slice::from_ref(&self.primary)
        } else {
            self.expanded.as_slice()
        }
    }

    /// Whether more than one route question must be evaluated.
    pub(super) fn is_multi(&self) -> bool {
        !self.expanded.is_empty()
    }
}

/// Collects the profile-required extra permission questions triggered by headers or form fields.
pub(super) fn collect_route_extras<'a>(
    extra_permissions: &[ExtraPermission],
    view_policy: ViewPolicy,
    post_fields: Option<&[(String, String)]>,
    headers: &HeaderMap,
    base: &AuthzRequest<'a>,
) -> Vec<AuthzRequest<'a>> {
    let mut extras = Vec::new();
    for extra in extra_permissions {
        if !view_policy.requires_extra_permission(*extra) {
            continue;
        }
        if !crate::post_object::permission_applies(post_fields, headers, extra) {
            continue;
        }
        extras.push(AuthzRequest {
            action: extra.action(),
            route_action: extra.action(),
            copy_source_identity: None,
            subject: None,
            ..*base
        });
    }
    extras
}

/// Emits one route-stage authorization audit event.
#[allow(clippy::too_many_arguments)] // Mirrors `AuthzAuditEvent` fields directly.
pub(super) fn emit_route_audit(
    sink: &dyn AuthzAuditSink,
    request_id: &RequestId,
    operation: &'static str,
    requirement: AuthRequirement,
    meta: &MetaView<'_>,
    effective_key: Option<&ObjectKey>,
    asked: &[AuthzRequest<'_>],
    extras: &[AuthzRequest<'_>],
    auth_scheme: AuthSchemeRef,
    identity: Option<&Identity>,
    target_origin: TargetOrigin,
    policy_snapshot: Option<SnapshotId>,
    decision: Decision,
    elapsed: Duration,
) {
    let combined;
    let audited: &[AuthzRequest<'_>] = if extras.is_empty() {
        asked
    } else {
        let mut merged = Vec::with_capacity(asked.len().saturating_add(extras.len()));
        merged.extend_from_slice(asked);
        merged.extend_from_slice(extras);
        combined = merged;
        &combined
    };
    emit_safely(
        sink,
        &AuthzAuditEvent {
            request_id,
            stage: AuthzStage::Route,
            operation,
            action: requirement.action,
            resource: requirement.resource,
            bucket: meta.bucket(),
            key: effective_key,
            resources: audited,
            auth_scheme,
            identity,
            target_origin,
            policy_snapshot,
            decision,
            elapsed,
        },
    );
}

/// Builds the input-stage authorization requests for derived resources.
#[allow(clippy::too_many_arguments)] // Borrowed pipeline facts for zero-copy `AuthzRequest` construction.
pub(super) fn build_input_authz_requests<'a>(
    operation: &'static str,
    requirement: AuthRequirement,
    deciding_action: &'static str,
    input_subject: Option<&'a Subject>,
    meta: &'a MetaView<'a>,
    effective_key: Option<&'a ObjectKey>,
    asked_version: Option<&'a str>,
    identity: Option<&'a Identity>,
    target_origin: TargetOrigin,
    resources: &'a [OwnedResource],
) -> (AuthzRequest<'a>, Vec<AuthzRequest<'a>>) {
    let route_request = AuthzRequest {
        operation,
        action: deciding_action,
        resource: requirement.resource,
        bucket: meta.bucket(),
        key: effective_key,
        copy_source_identity: None,
        version_id: asked_version,
        route_action: deciding_action,
        route_bucket: meta.bucket(),
        route_key: effective_key,
        identity,
        target_origin,
        subject: input_subject,
    };
    let mut input_resources = Vec::with_capacity(resources.len());
    for resource in resources {
        let shape = if resource.key().is_some() {
            ResourceShape::Object
        } else if resource.bucket().is_some() {
            ResourceShape::Bucket
        } else {
            ResourceShape::Service
        };
        input_resources.push(AuthzRequest {
            operation,
            action: resource.action(),
            resource: shape,
            bucket: resource.resolved_bucket(meta.bucket()),
            key: resource.key(),
            copy_source_identity: resource.identity(),
            version_id: resource.version_id(),
            route_action: deciding_action,
            route_bucket: meta.bucket(),
            route_key: effective_key,
            identity,
            target_origin,
            subject: input_subject,
        });
    }
    (route_request, input_resources)
}

/// Emits one input-stage authorization audit event including any missing-object visibility query.
#[allow(clippy::too_many_arguments)] // Mirrors `AuthzAuditEvent` fields directly.
pub(super) fn emit_input_audit(
    sink: &dyn AuthzAuditSink,
    request_id: &RequestId,
    operation: &'static str,
    requirement: AuthRequirement,
    meta: &MetaView<'_>,
    effective_key: Option<&ObjectKey>,
    route_request: AuthzRequest<'_>,
    input_resources: &[AuthzRequest<'_>],
    input_request: &InputAuthzRequest<'_>,
    auth_scheme: AuthSchemeRef,
    identity: Option<&Identity>,
    target_origin: TargetOrigin,
    policy_snapshot: SnapshotId,
    stage: Decision,
    decisions: &[Decision],
    visibility: Option<Decision>,
    elapsed: Duration,
) {
    let input_decision = if stage != Decision::Allow {
        stage
    } else {
        decisions
            .iter()
            .copied()
            .find(|decision| *decision != Decision::Allow)
            .unwrap_or(Decision::Allow)
    };
    let mut audited_resources = Vec::with_capacity(input_resources.len().saturating_add(1));
    audited_resources.push(route_request);
    audited_resources.extend(input_resources.iter().copied());
    crate::ext::emit_input_safely(
        sink,
        &AuthzAuditEvent {
            request_id,
            stage: AuthzStage::Input,
            operation,
            action: requirement.action,
            resource: requirement.resource,
            bucket: meta.bucket(),
            key: effective_key,
            resources: &audited_resources,
            auth_scheme,
            identity,
            target_origin,
            policy_snapshot: Some(policy_snapshot),
            decision: input_decision,
            elapsed,
        },
        input_request.visibility().zip(visibility),
    );
}

/// Assembles the [`RequestContextView`] handed to the operation handler.
#[allow(clippy::too_many_arguments)] // All request-context components come from verified pipeline stages.
pub(super) fn build_handler_context(
    operation: &'static str,
    wire: &WireRequest<()>,
    addressed: Addressed,
    verdict: &Verdict,
    caller_secret: Option<SecretBytes>,
    post_success_check: Option<PostObjectSuccessCheck>,
    post_key_constraints: Option<PostKeyConstraints>,
    post_date_offset: Option<i32>,
    path_params: PathParams,
    subjects: Option<Subjects>,
    response_kind: ResponseKind,
) -> Result<RequestContextView, S3Error> {
    let context = RequestContextView::from_pipeline(operation, wire, addressed, verdict, caller_secret)
        .map(|context| context.with_post_object_success_check(post_success_check))
        .map(|context| context.with_post_object_key_constraints(post_key_constraints))
        .map(|context| context.with_post_object_retain_until_offset_seconds(post_date_offset))
        .map(|context| context.with_path_params(path_params).with_subjects(subjects));
    context.ok_or_else(|| {
        from_handler(
            HandlerError::internal_error("a rejected request reached its handler"),
            response_kind,
            ConnectionIntent::MayKeepAlive,
        )
    })
}
