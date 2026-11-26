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

//! Panic-containment wrappers for pipeline extension callbacks outside handler dispatch.
//!
//! Responsible for: isolating panics in `StageFilter`, `HostResolver`, `Authenticator`,
//! `CustomSignatureVerifier`, and the optional replaced AWS signature verifier so every extension
//! panic becomes a fail-closed `500 InternalError` with a throttled `gateway_extension_panicked`
//! event and never unwinds out of `S3Service::call`.
//! NOT responsible for: handler/authorizer dispatch containment (`service.rs`) or report callbacks
//! (`panic_boundary::contain_report`).
//! Upstream: `crate::service`, `crate::classify`. Downstream: `crate::panic_boundary`, `crate::logging`.

use std::sync::Arc;

use http::Response;
use http::request::Parts;
use rustfs_gateway_core::{CodecError, HandlerError, Router};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_sig::{CustomAuthRequest, SignatureVerifier, Verdict};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::NamePolicy;

use crate::ext::{
    Authentication, AuthenticationOutcome, Authenticator, HostResolver, ResolvedHost, ResponseView, RoutedView,
    SigV2Authentication, StageFilter, Unavailable, WireHead,
};
use crate::logging::{Extension, extension_panicked};
use crate::panic_boundary::{catch_boxed_future, contain_decision};
use crate::trace::RequestTrace;

pub(crate) fn run_wire_filters(
    filters: &[Arc<dyn StageFilter>],
    parts: &mut Parts,
    trace: Option<&RequestTrace>,
) -> Result<(), HandlerError> {
    if filters.is_empty() {
        return Ok(());
    }
    let mut head = WireHead::new(parts);
    for filter in filters {
        match contain_decision(|| filter.on_wire(&mut head)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(()) => {
                if let Some(trace) = trace {
                    extension_panicked(Extension::Handler, trace.request_id(), "unknown");
                }
                return Err(HandlerError::internal_error("the stage filter failed"));
            }
        }
    }
    Ok(())
}

pub(crate) fn run_routed_filters(
    filters: &[Arc<dyn StageFilter>],
    view: &RoutedView<'_>,
    trace: &RequestTrace,
) -> Result<(), HandlerError> {
    for filter in filters {
        match contain_decision(|| filter.on_routed(view)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(()) => {
                extension_panicked(Extension::Handler, trace.request_id(), view.operation);
                return Err(HandlerError::internal_error("the stage filter failed"));
            }
        }
    }
    Ok(())
}

pub(crate) fn run_response_filters(
    filters: &[Arc<dyn StageFilter>],
    view: &ResponseView<'_>,
    response: &mut Response<Body>,
    trace: &RequestTrace,
) -> Result<(), HandlerError> {
    for filter in filters {
        match contain_decision(|| filter.on_response(view, response)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(()) => {
                extension_panicked(Extension::Handler, trace.request_id(), view.operation.unwrap_or("unknown"));
                return Err(HandlerError::internal_error("the stage filter failed"));
            }
        }
    }
    Ok(())
}

pub(crate) fn resolve_host_safely<B>(
    resolver: &dyn HostResolver,
    wire: &WireRequest<B>,
    trace: Option<&RequestTrace>,
) -> Result<(ResolvedHost, Option<String>), HandlerError> {
    contain_decision(|| crate::ext::resolve_host(resolver, wire)).map_err(|()| {
        if let Some(trace) = trace {
            extension_panicked(Extension::Handler, trace.request_id(), "unknown");
        }
        HandlerError::internal_error("the host resolver failed")
    })
}

pub(crate) fn classify_addressing_safely<B>(
    names: &NamePolicy,
    resolver: &dyn HostResolver,
    router: &Router,
    wire: &WireRequest<B>,
    resolved: ResolvedHost,
    trace: Option<&RequestTrace>,
) -> Result<Result<ResolvedHost, CodecError>, HandlerError> {
    contain_decision(|| crate::legacy_addressing::classify(names, resolver, router, wire, resolved)).map_err(|()| {
        if let Some(trace) = trace {
            extension_panicked(Extension::Handler, trace.request_id(), "unknown");
        }
        HandlerError::internal_error("the host resolver failed")
    })
}

pub(crate) async fn authenticate_safely<'a>(
    authenticator: &'a dyn Authenticator,
    question: &'a Authentication<'a>,
    trace: &RequestTrace,
    operation: &'static str,
) -> Result<Result<AuthenticationOutcome, Unavailable>, HandlerError> {
    catch_boxed_future(|| authenticator.authenticate(question))
        .await
        .map_err(|()| {
            extension_panicked(Extension::Handler, trace.request_id(), operation);
            HandlerError::internal_error("the authenticator failed")
        })
}

pub(crate) async fn authenticate_sigv2_safely<'a>(
    authenticator: &'a dyn Authenticator,
    question: &'a SigV2Authentication<'a>,
    trace: &RequestTrace,
    operation: &'static str,
) -> Result<Result<AuthenticationOutcome, Unavailable>, HandlerError> {
    catch_boxed_future(|| authenticator.authenticate_sigv2(question))
        .await
        .map_err(|()| {
            extension_panicked(Extension::Handler, trace.request_id(), operation);
            HandlerError::internal_error("the authenticator failed")
        })
}

pub(crate) fn verify_custom_signature_safely(
    verifier: &dyn SignatureVerifier,
    request: &CustomAuthRequest<'_>,
    trace: &RequestTrace,
    operation: &'static str,
) -> Result<Verdict, HandlerError> {
    contain_decision(|| verifier.verify(request)).map_err(|()| {
        extension_panicked(Extension::Handler, trace.request_id(), operation);
        HandlerError::internal_error("the custom signature verifier failed")
    })
}

#[cfg(feature = "dangerous-replace-signature-verifier")]
pub(crate) fn replaced_verifier_panicked(trace: &RequestTrace, operation: &'static str) -> HandlerError {
    extension_panicked(Extension::Handler, trace.request_id(), operation);
    HandlerError::internal_error("the signature verifier failed")
}

pub(crate) struct PolicyLoadContext<'a> {
    pub(crate) service: &'a super::S3Service,
    pub(crate) runtime: &'a crate::routing::RuntimeAssembly,
    pub(crate) request_id: &'a crate::trace::RequestId,
    pub(crate) operation: &'static str,
    pub(crate) requirement: rustfs_gateway_core::AuthRequirement,
    pub(crate) bucket: Option<&'a rustfs_gateway_types::BucketName>,
    pub(crate) key: Option<&'a rustfs_gateway_types::ObjectKey>,
    pub(crate) asked: &'a [crate::ext::AuthzRequest<'a>],
    pub(crate) auth_scheme: crate::ext::AuthSchemeRef,
    pub(crate) identity: Option<&'a rustfs_gateway_sig::Identity>,
    pub(crate) target_origin: crate::ext::TargetOrigin,
    pub(crate) authz_started: crate::clock::MonotonicNow,
    pub(crate) response_kind: rustfs_gateway_core::ResponseKind,
}

pub(crate) async fn handle_policy_snapshot_failure(panicked: bool, ctx: PolicyLoadContext<'_>) -> crate::render::S3Error {
    use crate::close::ConnectionIntent;
    use crate::ext::{AuthzAuditEvent, AuthzStage, emit_safely};
    use crate::render::{from_denial, from_handler};
    use crate::request_deadline::{elapsed_since, hold_failure_floor};
    use rustfs_gateway_core::Decision;

    if panicked {
        extension_panicked(Extension::Handler, ctx.request_id, ctx.operation);
    }
    emit_safely(
        ctx.runtime.authz_audit.as_ref(),
        &AuthzAuditEvent {
            request_id: ctx.request_id,
            stage: AuthzStage::Route,
            operation: ctx.operation,
            action: ctx.requirement.action,
            resource: ctx.requirement.resource,
            bucket: ctx.bucket,
            key: ctx.key,
            resources: ctx.asked,
            auth_scheme: ctx.auth_scheme,
            identity: ctx.identity,
            target_origin: ctx.target_origin,
            policy_snapshot: None,
            decision: Decision::Indeterminate,
            elapsed: elapsed_since(ctx.service.inner.authz_clock.as_ref(), ctx.authz_started),
        },
    );
    hold_failure_floor(
        ctx.service.inner.floor.failure_floor(),
        ctx.service.inner.authz_clock.as_ref(),
        ctx.authz_started,
    )
    .await;
    if panicked {
        from_handler(
            HandlerError::internal_error("the policy source failed"),
            ctx.response_kind,
            ConnectionIntent::MayKeepAlive,
        )
    } else {
        from_denial(
            rustfs_gateway_core::Denied::indeterminate(),
            ctx.response_kind,
            ctx.service.inner.view_policy.denial_sentences(),
        )
    }
}

pub(crate) async fn evaluate_route_questions<'a>(
    authorizer: &'a dyn crate::ext::Authorizer,
    authz_context: &'a crate::ext::RequestContext<'a>,
    asked: &'a [crate::ext::AuthzRequest<'a>],
    anonymous_about_a_subject: bool,
    request_id: &crate::trace::RequestId,
    operation: &'static str,
    response_kind: rustfs_gateway_core::ResponseKind,
) -> Result<(Vec<rustfs_gateway_core::Decision>, Option<HandlerError>), crate::render::S3Error> {
    let mut decisions = Vec::with_capacity(asked.len());
    let mut route_error = None;
    for question in asked {
        if anonymous_about_a_subject {
            break;
        }
        match catch_boxed_future(|| authorizer.authorize_route_result(authz_context, question)).await {
            Ok(Ok(decision)) => decisions.push(decision),
            Ok(Err(error)) => {
                route_error = Some(error);
                break;
            }
            Err(()) => {
                extension_panicked(Extension::Authorizer, request_id, operation);
                return Err(crate::render::from_handler(
                    HandlerError::internal_error("the authorizer failed"),
                    response_kind,
                    crate::close::ConnectionIntent::MayKeepAlive,
                ));
            }
        }
    }
    Ok((decisions, route_error))
}

pub(crate) async fn evaluate_route_extras<'a>(
    authorizer: &'a dyn crate::ext::Authorizer,
    authz_context: &'a crate::ext::RequestContext<'a>,
    route_extras: &'a [crate::ext::AuthzRequest<'a>],
    request_id: &crate::trace::RequestId,
    operation: &'static str,
    response_kind: rustfs_gateway_core::ResponseKind,
) -> Result<(rustfs_gateway_core::Decision, Option<HandlerError>), crate::render::S3Error> {
    for extra_request in route_extras {
        match catch_boxed_future(|| authorizer.authorize_route_result(authz_context, extra_request)).await {
            Ok(Err(error)) => return Ok((rustfs_gateway_core::Decision::Indeterminate, Some(error))),
            Ok(Ok(decision)) => {
                if decision != rustfs_gateway_core::Decision::Allow {
                    return Ok((decision, None));
                }
            }
            Err(()) => {
                extension_panicked(Extension::Authorizer, request_id, operation);
                return Err(crate::render::from_handler(
                    HandlerError::internal_error("the authorizer failed"),
                    response_kind,
                    crate::close::ConnectionIntent::MayKeepAlive,
                ));
            }
        }
    }
    Ok((rustfs_gateway_core::Decision::Allow, None))
}
