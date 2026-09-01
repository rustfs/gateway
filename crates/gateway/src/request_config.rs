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

//! The request-local configuration carrier through the eight assembly stages.
//!
//! Responsible for: carrying the one configuration snapshot loaded at request entry, the admitted
//! Governor lease, and request-local cancellation monitors through the pipeline.
//! NOT responsible for: loading or replacing configuration, or implementing a pipeline stage.
//! Upstream: [`crate::S3Service`]. Downstream: the ordered pipeline in `service.rs`.

use crate::{ConfigSnapshot, Decision, Lease};
use rustfs_gateway_core::SseEnforced;
use std::sync::atomic::{AtomicU8, Ordering};

pub(crate) struct Entered;
pub(crate) struct Wire;
pub(crate) struct Targeted;
pub(crate) struct Routed;
pub(crate) struct Governed;
pub(crate) struct MetaAuth;
pub(crate) struct RouteAuthorized;
pub(crate) struct Guarded;
pub(crate) struct Decoded;
pub(crate) struct Authorized;

pub(crate) trait CarriesSse {}

impl CarriesSse for Authorized {}

/// How a handler completed cleanup after its deadline won the response race.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerDeadlineReport {
    /// The handler observed cancellation and returned before the cleanup grace expired.
    Acknowledged,
    /// The cleanup grace expired before the handler returned.
    Unacknowledged,
}

#[derive(Clone)]
pub(crate) struct HandlerDeadlineReportSlot(std::sync::Arc<AtomicU8>);

impl HandlerDeadlineReportSlot {
    fn new() -> Self {
        Self(std::sync::Arc::new(AtomicU8::new(0)))
    }

    pub(crate) fn record(&self, cleanup_completed: bool) {
        self.0.store(if cleanup_completed { 1 } else { 2 }, Ordering::Release);
    }

    pub(crate) fn outcome(&self) -> Option<HandlerDeadlineReport> {
        match self.0.load(Ordering::Acquire) {
            0 => None,
            1 => Some(HandlerDeadlineReport::Acknowledged),
            _ => Some(HandlerDeadlineReport::Unacknowledged),
        }
    }
}

/// The one snapshot carried by a request, with its current real pipeline stage in the type.
pub(crate) struct RequestConfig<S> {
    snapshot: ConfigSnapshot,
    handler_deadline_report: HandlerDeadlineReportSlot,
    request_cancellation: Option<tokio::sync::watch::Receiver<bool>>,
    body_monitor: Option<crate::request_body::BodyMonitor>,
    governor_lease: Option<Lease>,
    sse: Option<SseEnforced>,
    hide_missing_object: bool,
    stage: core::marker::PhantomData<fn() -> S>,
}

impl RequestConfig<Entered> {
    pub(crate) fn enter(snapshot: ConfigSnapshot) -> Self {
        Self {
            snapshot,
            handler_deadline_report: HandlerDeadlineReportSlot::new(),
            request_cancellation: None,
            body_monitor: None,
            governor_lease: None,
            sse: None,
            hide_missing_object: false,
            stage: core::marker::PhantomData,
        }
    }

    pub(crate) fn with_request_cancellation(mut self, request_cancellation: Option<tokio::sync::watch::Receiver<bool>>) -> Self {
        self.request_cancellation = request_cancellation;
        self
    }

    pub(crate) fn wire(self) -> RequestConfig<Wire> {
        self.advance()
    }
}

impl RequestConfig<Wire> {
    pub(crate) fn targeted(self) -> RequestConfig<Targeted> {
        self.advance()
    }
}

impl RequestConfig<Targeted> {
    pub(crate) fn routed(self) -> RequestConfig<Routed> {
        self.advance()
    }
}

impl RequestConfig<Routed> {
    pub(crate) fn governed(mut self, lease: Lease) -> RequestConfig<Governed> {
        self.governor_lease = Some(lease);
        self.advance()
    }
}

impl RequestConfig<Governed> {
    pub(crate) fn meta_auth(self) -> RequestConfig<MetaAuth> {
        self.advance()
    }
}

impl RequestConfig<MetaAuth> {
    pub(crate) fn route_authorized(self) -> RequestConfig<RouteAuthorized> {
        self.advance()
    }
}

impl RequestConfig<RouteAuthorized> {
    pub(crate) fn guarded(mut self, sse: SseEnforced) -> RequestConfig<Guarded> {
        self.sse = Some(sse);
        self.advance()
    }
}

impl RequestConfig<Guarded> {
    pub(crate) fn with_body_monitor(mut self, body_monitor: Option<crate::request_body::BodyMonitor>) -> Self {
        self.body_monitor = body_monitor;
        self
    }

    pub(crate) fn decoded(self) -> RequestConfig<Decoded> {
        self.advance()
    }
}

impl RequestConfig<Decoded> {
    pub(crate) fn with_missing_object_visibility(mut self, decision: Option<Decision>) -> Self {
        self.hide_missing_object = decision.is_some_and(|decision| decision != Decision::Allow);
        self
    }

    pub(crate) fn authorized(self) -> RequestConfig<Authorized> {
        self.advance()
    }
}

impl<S> RequestConfig<S> {
    pub(crate) fn sse(&self) -> Result<&SseEnforced, rustfs_gateway_core::HandlerError>
    where
        S: CarriesSse,
    {
        self.sse
            .as_ref()
            .ok_or_else(|| rustfs_gateway_core::HandlerError::internal_error("the guarded pipeline stage lost its SSE proof"))
    }

    pub(crate) fn config(&self) -> &ConfigSnapshot {
        &self.snapshot
    }

    pub(crate) fn handler_deadline_report(&self) -> HandlerDeadlineReportSlot {
        self.handler_deadline_report.clone()
    }

    pub(crate) fn record_handler_deadline(&self, cleanup_completed: bool) {
        self.handler_deadline_report.record(cleanup_completed);
    }

    pub(crate) fn request_cancellation(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.request_cancellation.clone()
    }

    pub(crate) fn take_body_monitor(&mut self) -> Option<crate::request_body::BodyMonitor> {
        self.body_monitor.take()
    }

    pub(crate) fn body_quota(&self) -> Option<std::sync::Arc<dyn crate::BodyQuota>> {
        self.governor_lease.as_ref().and_then(Lease::body_quota)
    }

    pub(crate) fn hide_missing_object(&self) -> bool {
        self.hide_missing_object
    }

    fn advance<N>(self) -> RequestConfig<N> {
        RequestConfig {
            snapshot: self.snapshot,
            handler_deadline_report: self.handler_deadline_report,
            request_cancellation: self.request_cancellation,
            body_monitor: self.body_monitor,
            governor_lease: self.governor_lease,
            sse: self.sse,
            hide_missing_object: self.hide_missing_object,
            stage: core::marker::PhantomData,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Fixed, in-memory test input; no external failure reaches this helper.
pub(crate) fn sse_proof_for_test() -> SseEnforced {
    use bytes::Bytes;
    use rustfs_gateway_core::{MetaView, TargetKind, TransportSecurity};
    use rustfs_gateway_http::{Limits, WireRequest};

    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("valid proof fixture");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted proof fixture");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("service proof fixture");
    rustfs_gateway_core::sse::enforce(&meta, TransportSecurity::Encrypted, &rustfs_gateway_core::SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}
