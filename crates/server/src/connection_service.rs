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

//! Transport-independent request lifecycle enforcement for accepted connections.
//!
//! Responsible for: connection metadata, request capacity, cancellation, panic isolation and
//! shutdown accounting around every transport-dispatched request. NOT responsible for: parsing
//! HTTP or writing response frames. Upstream: accepted connection drivers. Downstream: services.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};
use tower::Service;
use tower_http::body::UnsyncBoxBody;
use tower_http::catch_panic::{CatchPanic, DefaultResponseForPanic};

use crate::driver::ConnectionInfo;
use crate::request_capacity::{RequestCancellationFuture, RequestCancellationSource, RequestCapacity, RequestPermit};

/// The erased error returned to a connection driver.
pub type ConnectionError = Box<dyn std::error::Error + Send + Sync>;

/// Response body that holds request capacity and shutdown accounting until transport completion.
pub struct ConnectionBody {
    body: UnsyncBoxBody<Bytes, ConnectionError>,
    permit: Option<RequestPermit>,
    guard: Option<RequestGuard>,
}

impl Body for ConnectionBody {
    type Data = Bytes;
    type Error = ConnectionError;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = ready!(Pin::new(&mut this.body).poll_frame(context));
        if frame.is_none() || this.body.is_end_stream() {
            this.permit.take();
            if let Some(mut guard) = this.guard.take() {
                guard.complete();
            }
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Per-connection service boundary shared by Hyper and self-held transport drivers.
///
/// Drivers cannot obtain the raw inner service. Calling this value is the only supported path from
/// a parsed request to the configured application service.
#[derive(Clone)]
pub struct ConnectionService<S> {
    inner: CatchPanic<S, DefaultResponseForPanic>,
    connection: ConnectionInfo,
    request_seen: Arc<AtomicBool>,
    request_capacity: Arc<RequestCapacity>,
    request_stats: Arc<RequestStats>,
    connection_in_flight: Arc<AtomicUsize>,
}

impl<S> ConnectionService<S> {
    pub(crate) fn new(
        inner: S,
        connection: ConnectionInfo,
        request_seen: Arc<AtomicBool>,
        request_capacity: Arc<RequestCapacity>,
        request_stats: Arc<RequestStats>,
        connection_in_flight: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner: CatchPanic::new(inner),
            connection,
            request_seen,
            request_capacity,
            request_stats,
            connection_in_flight,
        }
    }
}

impl<S, RequestBody, ResponseBody> Service<Request<RequestBody>> for ConnectionService<S>
where
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<ConnectionError> + Send + 'static,
    RequestBody: Send + 'static,
    ResponseBody: Body<Data = Bytes> + Send + 'static,
    ResponseBody::Error: Into<ConnectionError>,
{
    type Response = Response<ConnectionBody>;
    type Error = ConnectionError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ConnectionBody>, ConnectionError>> + Send + 'static>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: Request<RequestBody>) -> Self::Future {
        self.request_seen.store(true, Ordering::Release);
        request.extensions_mut().insert(self.connection);
        let (cancellation_source, cancellation) = RequestCancellationSource::pair();
        request.extensions_mut().insert(cancellation);
        let mut service = self.inner.clone();
        let request_capacity = Arc::clone(&self.request_capacity);
        let force_abort = Arc::clone(&self.request_stats.force_abort);
        let request_stats = Arc::clone(&self.request_stats);
        let connection_in_flight = Arc::clone(&self.connection_in_flight);
        Box::pin(async move {
            let permit = request_capacity
                .acquire()
                .await
                .map_err(|error| Box::new(error) as ConnectionError)?;
            poll_fn(|context| service.poll_ready(context)).await.map_err(Into::into)?;
            let mut guard = RequestGuard::new(request_stats, connection_in_flight);
            let response = match RequestCancellationFuture::new(service.call(request), cancellation_source, force_abort).await {
                Ok(response) => response,
                Err(error) => {
                    guard.complete();
                    return Err(error.into());
                }
            };
            Ok(response.map(|body| ConnectionBody {
                body,
                permit: Some(permit),
                guard: Some(guard),
            }))
        })
    }
}

impl<S, RequestBody, ResponseBody> hyper::service::Service<Request<RequestBody>> for ConnectionService<S>
where
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<ConnectionError> + Send + 'static,
    RequestBody: Send + 'static,
    ResponseBody: Body<Data = Bytes> + Send + 'static,
    ResponseBody::Error: Into<ConnectionError>,
{
    type Response = Response<ConnectionBody>;
    type Error = ConnectionError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ConnectionBody>, ConnectionError>> + Send + 'static>>;

    fn call(&self, request: Request<RequestBody>) -> Self::Future {
        let mut service = self.clone();
        Service::call(&mut service, request)
    }
}

#[derive(Default)]
pub(crate) struct RequestStats {
    shutting_down: AtomicBool,
    pub(crate) force_abort: Arc<AtomicBool>,
    drained: AtomicUsize,
    aborted: AtomicUsize,
}

impl RequestStats {
    pub(crate) fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
    }

    pub(crate) fn force_abort(&self) {
        self.force_abort.store(true, Ordering::Release);
    }

    pub(crate) fn drained(&self) -> usize {
        self.drained.load(Ordering::Relaxed)
    }

    pub(crate) fn aborted(&self) -> usize {
        self.aborted.load(Ordering::Relaxed)
    }
}

struct RequestGuard {
    stats: Arc<RequestStats>,
    connection_in_flight: Arc<AtomicUsize>,
    completed: bool,
}

impl RequestGuard {
    fn new(stats: Arc<RequestStats>, connection_in_flight: Arc<AtomicUsize>) -> Self {
        connection_in_flight.fetch_add(1, Ordering::Relaxed);
        Self {
            stats,
            connection_in_flight,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
        self.connection_in_flight.fetch_sub(1, Ordering::Relaxed);
        if self.stats.shutting_down.load(Ordering::Acquire) {
            self.stats.drained.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.connection_in_flight.fetch_sub(1, Ordering::Relaxed);
        if self.stats.force_abort.load(Ordering::Acquire) {
            self.stats.aborted.fetch_add(1, Ordering::Relaxed);
        }
    }
}
