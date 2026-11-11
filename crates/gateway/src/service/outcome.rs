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

//! Response refusals and the observer outcome accumulated by the request pipeline.
//!
//! Responsible for: constructing an outcome and rendering its ordinary, contextual,
//! preflight and governor refusals, and reporting the terminal response to the entry observer.
//! NOT responsible for: running pipeline stages, choosing a trace, or decorating responses.
//! Upstream: `super::S3Service`, which owns the request walk.
//! Downstream: `super::S3Service`, which consumes the rendered response and recorded outcome.

use http::{Method, Response};
use rustfs_gateway_core::cors::{PreflightRefusalCause, VARY, VARY_ORIGIN, preflight_refusal_for};
use rustfs_gateway_core::{ErrorContext, HandlerError, ResponseKind, resolve};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::ErrorCode;
use std::sync::Arc;

use super::cors::CorsDecoration;
use crate::builder::credential_sentences::CredentialSentences;
use crate::close::ConnectionIntent;
use crate::ext::{Observer, RequestEvent};
use crate::logging::Refused;
use crate::render::{S3Error, from_handler, from_pre_auth, render};
use crate::request_config::HandlerDeadlineReport;
use crate::trace::RequestTrace;

/// Whether an answer reached legacy RustFS's CORS layer.
#[derive(PartialEq, Eq)]
pub(super) enum LegacyCorsDisposition {
    Decorate,
    PlaintextCustomerKeyRefusal,
}

/// What the observer is told, accumulated as the pipeline learns it.
///
/// Borrows the request's [`RequestTrace`] rather than owning a source, which is what makes the one
/// identifier per request a property of the type: every refusal below renders through
/// [`Outcome::refuse`], and `refuse` has exactly one trace it can render with.
pub(super) struct Outcome<'a> {
    pub(super) trace: &'a RequestTrace,
    pub(super) operation: Option<&'static str>,
    pub(super) identity: Option<rustfs_gateway_sig::Identity>,
    pub(super) error: Option<ErrorCode>,
    /// The CORS decoration for an ordinary response, set once authorisation has been granted and
    /// applied by [`super::S3Service::call`] to whatever the pipeline produced afterwards. `None` for
    /// every request that never got that far, which is what keeps a pre-authentication refusal
    /// from costing a configuration read.
    pub(super) cors: Option<CorsDecoration>,
    pub(super) legacy_cors_disposition: LegacyCorsDisposition,
    pub(super) response_kind: ResponseKind,
    pub(super) credential_sentences: CredentialSentences,
    /// The stage that refused the request, when the gateway refused it; reported once, at the end
    /// (`crate::logging::request_refused`).
    pub(super) refused: Option<Refused>,
}

impl<'a> Outcome<'a> {
    /// An outcome that knows nothing yet, except which request it is about.
    pub(super) fn new(trace: &'a RequestTrace, method: &Method, credential_sentences: CredentialSentences) -> Self {
        Self {
            trace,
            operation: None,
            identity: None,
            error: None,
            cors: None,
            legacy_cors_disposition: LegacyCorsDisposition::Decorate,
            credential_sentences,
            refused: None,
            response_kind: if *method == Method::HEAD {
                ResponseKind::Head
            } else {
                ResponseKind::Other
            },
        }
    }

    /// Consume the outcome once the response and any external transfer have settled.
    pub(super) fn report(
        self,
        detached_work: &crate::DetachedWork,
        observer: &Arc<dyn Observer>,
        method: &Method,
        response: &mut Response<Body>,
        handler_deadline: Option<HandlerDeadlineReport>,
    ) {
        let event_request_id = *self.trace.request_id();
        let event_operation = self.operation;
        let event_method = method.clone();
        let event_status = response.status().as_u16();
        let event_identity = self.identity.clone();
        // Both reports below go to the observer this request's entry snapshot holds, and both go
        // through one panic boundary. The committed one runs before the terminal document is sent,
        // so a panic there would otherwise replace that document with the stopped-work fallback.
        let committed_observer = Arc::clone(observer);
        let started_committed_work = detached_work.start(
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
        );
        if let Some(refused) = self.refused {
            crate::logging::request_refused(refused, self.trace.request_id(), self.operation, event_status, self.error.as_ref());
        }
        if !started_committed_work {
            let event = RequestEvent {
                request_id: self.trace.request_id(),
                operation: self.operation,
                method,
                status: response.status().as_u16(),
                handler_deadline,
                identity: self.identity.as_ref(),
                error: self.error.as_ref(),
            };
            crate::ext::observe_safely(observer.as_ref(), &event);
        }
    }

    /// Renders a refusal and records its code, so every early return goes through one place.
    pub(super) fn refuse(&mut self, error: S3Error) -> Response<Body> {
        let error = self.credential_sentences.restyle(error);
        self.error = error.code().cloned();
        render(&error, self.trace)
    }

    pub(super) fn refuse_handler(&mut self, error: HandlerError) -> Response<Body> {
        self.refuse(from_handler(error, self.response_kind, ConnectionIntent::MayKeepAlive))
    }

    /// [`Outcome::refuse`], remembering which stage refused, for the request's refusal event.
    pub(super) fn refuse_at(&mut self, refused: Refused, error: S3Error) -> Response<Body> {
        self.refuse_as(Some(refused), error)
    }

    /// [`Outcome::refuse_at`] for a refusal whose stage is read off the refusal itself, and which
    /// may be no refusal of the gateway's at all (`None`).
    pub(super) fn refuse_as(&mut self, refused: Option<Refused>, error: S3Error) -> Response<Body> {
        self.refused = refused;
        self.refuse(error)
    }

    /// [`Outcome::refuse_handler`], remembering which stage refused.
    pub(super) fn refuse_handler_at(&mut self, refused: Refused, error: HandlerError) -> Response<Body> {
        self.refused = Some(refused);
        self.refuse_handler(error)
    }

    /// The one refusal a preflight can receive.
    ///
    /// `preflight_refusal_for` erases the typed cause before rendering. The closed contextual
    /// resolver remains the only authority for `AccessForbidden`; the non-contextual branch makes
    /// the refusal-profile mutation observable without opening another public construction seam.
    /// `Vary: Origin` rides along because the refusal is still
    /// an answer that depends on the `Origin` header: a shared cache that stored it under the URL
    /// alone would serve it to an origin that would have been allowed.
    ///
    /// A malformed preflight is a head the gateway could not read, and is reported as one; a
    /// preflight the bucket's CORS configuration does not allow is that configuration's answer.
    pub(super) fn refuse_preflight(&mut self, cause: PreflightRefusalCause) -> Response<Body> {
        if cause == PreflightRefusalCause::Malformed {
            self.refused = Some(Refused::Wire);
        }
        let refusal = preflight_refusal_for(cause);
        let error = if refusal.code() == &ErrorCode::ACCESS_FORBIDDEN {
            S3Error::from(resolve(ErrorContext::cors_forbidden(), self.response_kind))
        } else {
            from_pre_auth(refusal, self.response_kind)
        };
        self.error = error.code().cloned();
        let mut response = render(&error, self.trace);
        response.headers_mut().insert(VARY, VARY_ORIGIN);
        response
    }

    /// The one refusal a governor can cause.
    ///
    /// Takes no argument, and there is deliberately nowhere to put one. Every reason a limiter
    /// can have — the aggregate ceiling, one client, one class, a deployment's own
    /// quota — renders the same bytes, because a refusal that named its reason would answer "which
    /// of my buckets is nearly full" for anybody willing to send traffic and read the difference.
    /// Nothing here is derived from the request, and no `Retry-After` is written: the exact time
    /// the limiter recovers is the recovery rate, told to whoever asked.
    pub(super) fn refuse_for_load(&mut self) -> Response<Body> {
        self.refuse_handler_at(
            Refused::Governor,
            HandlerError::new(ErrorCode::SLOW_DOWN, "the service is not accepting this request right now"),
        )
    }
}
