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

//! Response decoration, committed-work observation, and dispatch outcome rendering.
//!
//! Responsible for: applying `304`, CORS, and `on_response` filter decoration, attaching the
//! detached-work observer callback, and turning `StaticDispatchError` / `StaticDispatchOutcome`
//! into final `Response<Body>` values.
//! NOT responsible for: `finish_response` invariant validation or non-committed request observation
//! (both remain directly in `super::S3Service` for redirect-authority and handler-deadline guards).
//! Upstream: `super::S3Service::call_with_mode` and `super::S3Service::run`.
//! Downstream: `crate::commit`, `crate::response::into_response`, and `crate::ext::observe_safely`.

use std::sync::Arc;

use http::{Method, Response};
use rustfs_gateway_core::{
    EncodedResponse, HandlerError, ResponseBody, StaticDispatchError, StaticDispatchOutcome, TargetKind, TransportSecurity,
};
use rustfs_gateway_http::WireRequest;
use rustfs_gateway_sig::RequestNow;
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::BucketName;

use super::cors::LegacyCorsRequest;
use super::outcome::{LegacyCorsDisposition, Outcome};
use super::{Refused, RequestEvent, ResponseView, RuntimeAssembly, S3Service};
use crate::TargetOrigin;
use crate::clock::MonotonicNow;
use crate::close::ConnectionIntent;
use crate::ext::ResolvedHost;
use crate::post_object::PostObjectResponsePlan;
use crate::render::{from_codec, from_denial, from_handler};
use crate::request_config::HandlerDeadlineReport;
use crate::request_deadline::hold_failure_floor;
use crate::response::into_response;

impl S3Service {
    /// Applies `304`, standard/legacy CORS headers, and `on_response` filters before invariants.
    #[allow(clippy::too_many_arguments)] // Explicit stage values from `call_with_mode`.
    pub(super) async fn decorate_and_filter_response(
        &self,
        mut response: Response<Body>,
        outcome: &mut Outcome<'_>,
        legacy_cors: Option<&LegacyCorsRequest>,
        runtime: &RuntimeAssembly,
        method: &Method,
        now: RequestNow,
        non_s3: bool,
    ) -> Response<Body> {
        let status = response.status();
        if !non_s3 {
            self.inner
                .view_policy
                .not_modified_headers
                .apply(outcome.operation, status, response.headers_mut());
        }
        outcome.decorate_response_cors(&mut response);
        // Legacy RustFS decorates answers that reach its CORS layer, including authentication
        // refusals, but its earlier cleartext customer-key gate is outside that layer.
        if outcome.legacy_cors_disposition == LegacyCorsDisposition::Decorate
            && let Some(legacy_cors) = legacy_cors
        {
            self.decorate_legacy_cors(legacy_cors, &mut response, now).await;
        }
        // Filters see the browser's CORS headers on success and refusal. The body invariants
        // and final stamp apply to their result.
        if !runtime.filters.is_empty() {
            let view = ResponseView {
                request_id: outcome.trace.request_id(),
                operation: outcome.operation,
                method,
            };
            if let Err(error) =
                super::extension_guards::run_response_filters(&runtime.filters, &view, &mut response, outcome.trace)
            {
                response = outcome.refuse_handler(error);
            }
        }
        response
    }

    /// Starts detached committed-work tracking and registers the post-commit observer callback.
    pub(super) fn start_committed_observation(
        &self,
        response: &mut Response<Body>,
        outcome: &Outcome<'_>,
        runtime: &RuntimeAssembly,
        method: &Method,
        handler_deadline: Option<HandlerDeadlineReport>,
    ) -> bool {
        let event_request_id = *outcome.trace.request_id();
        let event_operation = outcome.operation;
        let event_method = method.clone();
        let event_status = response.status().as_u16();
        let event_identity = outcome.identity.clone();
        let committed_observer = Arc::clone(&runtime.observer);
        self.inner.detached_work.start(
            response,
            Box::new(move |error| {
                let event = RequestEvent {
                    request_id: &event_request_id,
                    operation: event_operation,
                    method: &event_method,
                    status: event_status,
                    handler_deadline,
                    identity: event_identity.as_ref(),
                    error: error.as_ref(),
                };
                crate::ext::observe_safely(committed_observer.as_ref(), &event);
            }),
        )
    }

    /// Renders a [`StaticDispatchError`] into an S3 refusal response.
    pub(super) async fn render_dispatch_error(
        &self,
        error: StaticDispatchError<crate::render::S3Error>,
        outcome: &mut Outcome<'_>,
        auth_started: MonotonicNow,
        authz_started: MonotonicNow,
    ) -> Response<Body> {
        let response_kind = outcome.response_kind;
        match error {
            StaticDispatchError::OperationMismatch { .. } => outcome.refuse_handler(HandlerError::internal_error(
                "the static operation set did not match the routed operation",
            )),
            StaticDispatchError::Route(error) | StaticDispatchError::Input(error) => outcome.refuse(error),
            StaticDispatchError::Body(error) => {
                let refused = Refused::reading_the_body(&error);
                if refused == Some(Refused::Authentication) {
                    self.hold_auth_failure_floor(auth_started).await;
                }
                outcome.refuse_as(refused, self.inner.view_policy.body_refusal(error))
            }
            StaticDispatchError::Codec(error) => {
                let refusal = from_codec(error, response_kind);
                outcome.refuse_as(Refused::reading_the_input(&refusal), refusal)
            }
            StaticDispatchError::Denied(denial) => {
                hold_failure_floor(self.inner.floor.failure_floor(), self.inner.authz_clock.as_ref(), authz_started).await;
                outcome.refuse(from_denial(denial, response_kind, self.inner.view_policy.denial_sentences()))
            }
            StaticDispatchError::Handler(error) => {
                outcome.refuse(from_handler(error, response_kind, ConnectionIntent::MayKeepAlive))
            }
        }
    }

    /// Converts a successful [`StaticDispatchOutcome`] into an HTTP response.
    #[allow(clippy::too_many_arguments)] // Explicit stage values from `run` for settled/committed/event-stream paths.
    pub(super) fn render_dispatch_outcome(
        &self,
        dispatched: StaticDispatchOutcome,
        operation: &'static str,
        post_response: Option<PostObjectResponsePlan>,
        connection: TransportSecurity,
        target_origin: TargetOrigin,
        bound_bucket: Option<BucketName>,
        service_level: bool,
        resolved: &ResolvedHost,
        target: TargetKind,
        wire: WireRequest<()>,
        outcome: &mut Outcome<'_>,
    ) -> Response<Body> {
        let response_kind = outcome.response_kind;
        match dispatched {
            StaticDispatchOutcome::Settled(mut encoded) => {
                if let Some(response) = post_response
                    && let Err(error) = response.apply(&mut encoded, connection, wire.host().as_str(), target_origin)
                {
                    return outcome.refuse_handler(error);
                }
                self.inner.view_policy.settle(operation, &mut encoded);
                into_response(encoded)
            }
            StaticDispatchOutcome::Committed { status, response } => {
                let host_bucket = match bound_bucket {
                    Some(bucket) => Some(bucket),
                    None if service_level => None,
                    None => resolved.bucket().cloned(),
                };
                let names = self.inner.names.clone();
                let trace = *outcome.trace;
                let context = crate::commit::CommitContext::new(wire, target, host_bucket, names, response_kind, trace);
                match crate::commit::prepare_response(response, status, context) {
                    Ok(response) => response,
                    Err(error) => outcome.refuse_handler(error),
                }
            }
            StaticDispatchOutcome::EventStream { status, stream } => {
                let mut encoded = EncodedResponse::of(status);
                encoded.set_header("content-type", crate::EVENT_STREAM_CONTENT_TYPE);
                encoded.body = ResponseBody::Stream(stream);
                encoded.enforce_http_invariants(wire.method());
                into_response(encoded)
            }
        }
    }
}
