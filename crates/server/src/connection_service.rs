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

use std::any::Any;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_util::FutureExt;
use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use tower::Service;
use tower_http::catch_panic::{DefaultResponseForPanic, ResponseForPanic};

use crate::driver::ConnectionInfo;
use crate::request_capacity::{RequestCancellationFuture, RequestCancellationSource, RequestCapacity, RequestPermit};
use crate::write_receipt::WriteReceipts;

/// The erased error returned to a connection driver.
pub type ConnectionError = Box<dyn std::error::Error + Send + Sync>;

/// Response extension proving that the application stopped before the request body reached its end.
///
/// A service inserts this zero-sized marker into the response only when it independently knows
/// that request-body octets may still arrive after the response starts. The server then gives an
/// initially empty socket the existing per-block linger grace instead of abandoning the drain on
/// its first `Pending` read.
///
/// This is deliberately not inferred from `Connection: close`, a status code, or any other close
/// verdict: ordinary closes include bodyless requests and requests whose bodies were completely
/// consumed. Inserting the marker is an explicit application assertion, not a transport guess.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnfinishedRequestBody;

pin_project! {
    /// Response body that holds request capacity and shutdown accounting until transport completion.
    pub struct ConnectionBody<B> {
        #[pin]
        body: B,
        completion: ResponseCompletion,
    }
}

pin_project! {
    #[project = ConnectionResponseBodyProj]
    #[allow(missing_docs)] // pin-project-lite cannot carry rustdoc on projected enum fields.
    /// Preserves an application's concrete response body while representing an isolated panic.
    pub enum ConnectionResponseBody<B> {
        /// The response returned by the configured application service.
        Application {
            #[pin]
            body: B,
        },
        /// The framework-generated body for an isolated application panic.
        Panic {
            #[pin]
            body: tower_http::body::Full,
        },
    }
}

impl<B> ConnectionResponseBody<B> {
    /// Returns the application body, or the panic body when the application did not produce one.
    pub fn into_result(self) -> Result<B, tower_http::body::Full> {
        match self {
            Self::Application { body } => Ok(body),
            Self::Panic { body } => Err(body),
        }
    }
}

impl<B> Body for ConnectionResponseBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<ConnectionError>,
{
    type Data = Bytes;
    type Error = ConnectionError;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            ConnectionResponseBodyProj::Application { body } => body
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(Into::into))),
            ConnectionResponseBodyProj::Panic { body } => body
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(Into::into))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Application { body } => body.is_end_stream(),
            Self::Panic { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Application { body } => body.size_hint(),
            Self::Panic { body } => body.size_hint(),
        }
    }
}

impl<B> ConnectionBody<B> {
    /// Separates the concrete response body from its lifecycle token.
    ///
    /// A self-held transport uses this method so payload capabilities remain available while the
    /// request permit and shutdown guard stay alive until the transport reports completion.
    #[must_use]
    pub fn into_parts(self) -> (B, ResponseCompletion) {
        let Self { body, completion } = self;
        (body, completion)
    }
}

/// Holds generic request lifecycle state until a self-held transport finishes the response.
pub struct ResponseCompletion {
    permit: Option<RequestPermit>,
    guard: Option<RequestGuard>,
    receipts: Arc<WriteReceipts>,
    http2: bool,
}

impl ResponseCompletion {
    fn complete_inner(&mut self) {
        self.permit.take();
        if let Some(mut guard) = self.guard.take() {
            guard.complete();
        }
    }

    /// The final frame was handed to a Hyper transport: capacity is released now, and whether the
    /// response drained is left to the transport's write receipt (`crate::write_receipt`).
    fn hand_over(&mut self) {
        self.permit.take();
        if let Some(mut guard) = self.guard.take() {
            guard.hand_over();
            self.receipts.handed_over(self.http2);
        }
    }

    /// Marks the response body as completely written and releases its request capacity.
    pub fn complete(mut self) {
        self.complete_inner();
    }
}

impl<B> Body for ConnectionBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<ConnectionError>,
{
    type Data = B::Data;
    type Error = ConnectionError;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let frame = ready!(this.body.as_mut().poll_frame(context)).map(|result| result.map_err(Into::into));
        if frame.is_none() || this.body.as_ref().is_end_stream() {
            this.completion.hand_over();
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
    inner: S,
    connection: ConnectionInfo,
    request_seen: Arc<AtomicBool>,
    request_capacity: Arc<RequestCapacity>,
    request_stats: Arc<RequestStats>,
    connection_in_flight: Arc<AtomicUsize>,
    request_body_unfinished: Arc<AtomicBool>,
    receipts: Arc<WriteReceipts>,
}

impl<S> ConnectionService<S> {
    pub(crate) fn new(
        inner: S,
        connection: ConnectionInfo,
        request_seen: Arc<AtomicBool>,
        request_capacity: Arc<RequestCapacity>,
        request_stats: Arc<RequestStats>,
        connection_in_flight: Arc<AtomicUsize>,
        request_body_unfinished: Arc<AtomicBool>,
    ) -> Self {
        let receipts = WriteReceipts::new(Arc::clone(&request_stats));
        Self {
            inner,
            connection,
            request_seen,
            request_capacity,
            request_stats,
            connection_in_flight,
            request_body_unfinished,
            receipts,
        }
    }

    /// Shares write receipts with the transport that confirms this connection's writes.
    pub(crate) fn confirm_writes_into(mut self, receipts: Arc<WriteReceipts>) -> Self {
        self.receipts = receipts;
        self
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
    type Response = Response<ConnectionBody<ConnectionResponseBody<ResponseBody>>>;
    type Error = ConnectionError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, ConnectionError>> + Send + 'static>>;

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
        // Counted from here rather than from the permit: a request queued for a permit is not an
        // idle connection (rustfs/gateway#1209).
        let in_flight = InFlight::new(Arc::clone(&self.connection_in_flight), Arc::clone(&self.request_seen));
        let request_body_unfinished = Arc::clone(&self.request_body_unfinished);
        let receipts = Arc::clone(&self.receipts);
        let http2 = request.version() == http::Version::HTTP_2;
        Box::pin(async move {
            let permit = request_capacity
                .acquire()
                .await
                .map_err(|error| Box::new(error) as ConnectionError)?;
            poll_fn(|context| service.poll_ready(context)).await.map_err(Into::into)?;
            let mut guard = RequestGuard::new(request_stats, in_flight);
            let response = match catch_unwind(AssertUnwindSafe(|| service.call(request))) {
                Ok(future) => match RequestCancellationFuture::new(
                    AssertUnwindSafe(future).catch_unwind(),
                    cancellation_source,
                    force_abort,
                )
                .await
                {
                    Ok(Ok(response)) => response.map(|body| ConnectionResponseBody::Application { body }),
                    Ok(Err(error)) => {
                        guard.complete();
                        return Err(error.into());
                    }
                    Err(panic) => panic_response(panic),
                },
                Err(panic) => panic_response(panic),
            };
            if response.extensions().get::<UnfinishedRequestBody>().is_some() {
                request_body_unfinished.store(true, Ordering::Release);
            }
            Ok(response.map(|body| ConnectionBody {
                body,
                completion: ResponseCompletion {
                    permit: Some(permit),
                    guard: Some(guard),
                    receipts,
                    http2,
                },
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
    type Response = Response<ConnectionBody<ConnectionResponseBody<ResponseBody>>>;
    type Error = ConnectionError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, ConnectionError>> + Send + 'static>>;

    fn call(&self, request: Request<RequestBody>) -> Self::Future {
        let mut service = self.clone();
        Service::call(&mut service, request)
    }
}

fn panic_response<B>(panic: Box<dyn Any + Send + 'static>) -> Response<ConnectionResponseBody<B>> {
    let mut handler = DefaultResponseForPanic::default();
    handler
        .response_for_panic(panic)
        .map(|body| ConnectionResponseBody::Panic { body })
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

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    pub(crate) fn add_drained(&self, count: usize) {
        self.drained.fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn add_aborted(&self, count: usize) {
        self.aborted.fetch_add(count, Ordering::Relaxed);
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

/// One request's share of its connection's in-flight count, which is what keeps the connection
/// from idling: taken when the transport hands the request over and given back once. Giving it
/// back is request activity too, so it raises `activity` for the transport's idle check.
struct InFlight {
    counter: Arc<AtomicUsize>,
    activity: Arc<AtomicBool>,
    counted: bool,
}

impl InFlight {
    fn new(counter: Arc<AtomicUsize>, activity: Arc<AtomicBool>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self {
            counter,
            activity,
            counted: true,
        }
    }

    fn end(&mut self) {
        if std::mem::take(&mut self.counted) {
            self.counter.fetch_sub(1, Ordering::Relaxed);
            self.activity.store(true, Ordering::Release);
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.end();
    }
}

struct RequestGuard {
    stats: Arc<RequestStats>,
    in_flight: InFlight,
    completed: bool,
}

impl RequestGuard {
    fn new(stats: Arc<RequestStats>, in_flight: InFlight) -> Self {
        Self {
            stats,
            in_flight,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.hand_over();
        if self.stats.is_shutting_down() {
            self.stats.add_drained(1);
        }
    }

    /// Ends the request's share of the connection without deciding whether it drained.
    fn hand_over(&mut self) {
        self.completed = true;
        self.in_flight.end();
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.in_flight.end();
        if self.stats.force_abort.load(Ordering::Acquire) {
            self.stats.aborted.fetch_add(1, Ordering::Relaxed);
        }
    }
}
