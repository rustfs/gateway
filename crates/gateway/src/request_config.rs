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
//! Responsible for: making every stage consume the one [`crate::ConfigSnapshot`] loaded at entry.
//! NOT responsible for: loading or replacing configuration, or for implementing a pipeline stage.
//! Upstream: [`crate::S3Service`]. Downstream: the ordered pipeline in `service.rs`.

use core::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::ConfigSnapshot;

pub(crate) struct Entered;
pub(crate) struct Accepted;
pub(crate) struct Routed;
pub(crate) struct Governed;
pub(crate) struct Authenticated;
pub(crate) struct RouteAuthorized;
pub(crate) struct BodyRead;
pub(crate) struct Decoded;
pub(crate) struct InputAuthorized;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandlerDeadlineReport {
    Acknowledged,
    Unacknowledged,
}

#[derive(Clone)]
pub(crate) struct HandlerDeadlineReportSlot(Arc<AtomicU8>);

impl HandlerDeadlineReportSlot {
    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
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
    stage: PhantomData<fn() -> S>,
}

impl RequestConfig<Entered> {
    pub(crate) fn enter(snapshot: ConfigSnapshot) -> Self {
        Self {
            snapshot,
            handler_deadline_report: HandlerDeadlineReportSlot::new(),
            stage: PhantomData,
        }
    }

    pub(crate) fn accepted(self) -> RequestConfig<Accepted> {
        self.advance()
    }
}

impl RequestConfig<Accepted> {
    pub(crate) fn routed(self) -> RequestConfig<Routed> {
        self.advance()
    }
}

impl RequestConfig<Routed> {
    pub(crate) fn governed(self) -> RequestConfig<Governed> {
        self.advance()
    }
}

impl RequestConfig<Governed> {
    pub(crate) fn authenticated(self) -> RequestConfig<Authenticated> {
        self.advance()
    }
}

impl RequestConfig<Authenticated> {
    pub(crate) fn route_authorized(self) -> RequestConfig<RouteAuthorized> {
        self.advance()
    }
}

impl RequestConfig<RouteAuthorized> {
    pub(crate) fn body_read(self) -> RequestConfig<BodyRead> {
        self.advance()
    }
}

impl RequestConfig<BodyRead> {
    pub(crate) fn decoded(self) -> RequestConfig<Decoded> {
        self.advance()
    }
}

impl RequestConfig<Decoded> {
    pub(crate) fn input_authorized(self) -> RequestConfig<InputAuthorized> {
        self.advance()
    }
}

impl<S> RequestConfig<S> {
    pub(crate) fn config(&self) -> &ConfigSnapshot {
        &self.snapshot
    }

    pub(crate) fn handler_deadline_report(&self) -> HandlerDeadlineReportSlot {
        self.handler_deadline_report.clone()
    }

    pub(crate) fn record_handler_deadline(&self, cleanup_completed: bool) {
        self.handler_deadline_report.record(cleanup_completed);
    }

    fn advance<N>(self) -> RequestConfig<N> {
        RequestConfig {
            snapshot: self.snapshot,
            handler_deadline_report: self.handler_deadline_report,
            stage: PhantomData,
        }
    }
}
