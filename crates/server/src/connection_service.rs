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
use crate::send_deadline::SendProgress;
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
    /// The HTTP/2 stream's send progress, when this response is served on one. Only a frame the
    /// body has not ended with is charged: once the body ends, the permit is already released.
    progress: Option<SendProgress>,
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
        // Asked for the next frame, so the transport sent what it held: from here until a frame is
        // handed over, any wait is the body's own and is not charged to the peer.
        if let Some(progress) = &this.completion.progress {
            progress.producing();
        }
        let frame = ready!(this.body.as_mut().poll_frame(context)).map(|result| result.map_err(Into::into));
        if frame.is_none() || this.body.as_ref().is_end_stream() {
            this.completion.hand_over();
        } else if let Some(progress) = &this.completion.progress {
            progress.wait_for_peer();
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
            // Present only when an HTTP/2 stream task is polling this future (`send_deadline`).
            let progress = SendProgress::current();
            let permit = request_capacity
                .acquire()
                .await
                .map_err(|error| Box::new(error) as ConnectionError)?;
            poll_fn(|context| service.poll_ready(context)).await.map_err(Into::into)?;
            let mut guard = RequestGuard::new(request_stats, in_flight);
            let (response, permit, guard) = RequestCancellationFuture::new(
                async move {
                    // Detached peer-loss cleanup owns the same permit and lifecycle guard as the
                    // handler. Transport-only completion state stays with the caller.
                    let response = match catch_unwind(AssertUnwindSafe(|| service.call(request))) {
                        Ok(future) => match AssertUnwindSafe(future).catch_unwind().await {
                            Ok(Ok(response)) => response.map(|body| ConnectionResponseBody::Application { body }),
                            Ok(Err(error)) => {
                                guard.complete();
                                return Err(error.into());
                            }
                            Err(panic) => panic_response(panic),
                        },
                        Err(panic) => panic_response(panic),
                    };
                    Ok::<_, ConnectionError>((response, permit, guard))
                },
                cancellation_source,
                force_abort,
            )
            .await?;
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
                    progress,
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

#[cfg(test)]
#[allow(clippy::expect_used)] // Test-only fixtures and synchronization terminate the scenario on failure.
mod cancellation_capacity_tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::task::noop_waker_ref;
    use http::{Request, Response, Version};
    use http_body::Body;
    use http_body_util::{BodyExt, Full};
    use tokio::sync::{Notify, watch};
    use tower::{Service, service_fn};

    use super::{ConnectionService, RequestStats};
    use crate::driver::{ConnectionInfo, TransportKind};
    use crate::request_capacity::{RequestCancellation, RequestCapacity};

    #[derive(Clone, Copy)]
    enum CleanupOutcome {
        Response,
        Error,
        Panic,
    }

    pub(super) fn managed_service<S>(
        inner: S,
        stats: Arc<RequestStats>,
        in_flight: Arc<AtomicUsize>,
    ) -> (ConnectionService<S>, watch::Receiver<usize>) {
        let (capacity, available) = RequestCapacity::new(1);
        (
            ConnectionService::new(
                inner,
                ConnectionInfo {
                    peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                    transport: TransportKind::Plaintext,
                    tcp_nodelay: true,
                },
                Arc::new(AtomicBool::new(false)),
                capacity,
                stats,
                in_flight,
                Arc::new(AtomicBool::new(false)),
            ),
            available,
        )
    }

    #[allow(clippy::panic)] // Deliberate handler panics verify detached cleanup and capacity release.
    async fn detached_cleanup_holds_capacity(version: Version, outcome: CleanupOutcome) {
        let cleanup_started = Arc::new(Notify::new());
        let cleanup_release = Arc::new(Notify::new());
        let cleanup_finished = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let cleanup_started = Arc::clone(&cleanup_started);
            let cleanup_release = Arc::clone(&cleanup_release);
            let cleanup_finished = Arc::clone(&cleanup_finished);
            let calls = Arc::clone(&calls);
            move |request: Request<()>| {
                let cleanup_started = Arc::clone(&cleanup_started);
                let cleanup_release = Arc::clone(&cleanup_release);
                let cleanup_finished = Arc::clone(&cleanup_finished);
                let calls = Arc::clone(&calls);
                async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        let mut cancellation = request
                            .extensions()
                            .get::<RequestCancellation>()
                            .cloned()
                            .expect("the managed service inserts cancellation");
                        while !*cancellation.borrow() {
                            cancellation
                                .changed()
                                .await
                                .expect("the cancellation source stays alive until peer loss");
                        }
                        cleanup_started.notify_one();
                        cleanup_release.notified().await;
                        cleanup_finished.notify_one();
                        match outcome {
                            CleanupOutcome::Response => {}
                            CleanupOutcome::Error => return Err(io::Error::other("cleanup completed with a handler error")),
                            CleanupOutcome::Panic => panic!("cleanup completed with a handler panic"),
                        }
                    }
                    Ok::<_, io::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                }
            }
        });
        let in_flight = Arc::new(AtomicUsize::new(0));
        let (mut service, _) = managed_service(inner, Arc::new(RequestStats::default()), Arc::clone(&in_flight));
        let request = || Request::builder().version(version).body(()).expect("fixture request");
        let mut first = Service::call(&mut service, request());
        let mut context = Context::from_waker(noop_waker_ref());
        assert!(
            first.as_mut().poll(&mut context).is_pending(),
            "the first handler is waiting for peer loss"
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), cleanup_started.notified())
            .await
            .expect("peer loss reaches asynchronous cleanup");

        let mut second = Service::call(&mut service, request());
        let initial_poll = second.as_mut().poll(&mut context);
        let entered_while_cleaning = calls.load(Ordering::SeqCst) != 1;
        let in_flight_while_cleaning = in_flight.load(Ordering::Relaxed);
        cleanup_release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), cleanup_finished.notified())
            .await
            .expect("the detached handler finishes cleanup");
        let response = match initial_poll {
            Poll::Ready(response) => response,
            Poll::Pending => tokio::time::timeout(Duration::from_secs(1), second)
                .await
                .expect("finished cleanup releases capacity"),
        }
        .expect("the next handler responds");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("the response body completes")
            .to_bytes();
        assert_eq!(body, b"ok"[..], "capacity is reusable after cleanup");
        assert!(
            !entered_while_cleaning,
            "a detached handler still owns the global request permit until cleanup ends"
        );
        assert_eq!(
            in_flight_while_cleaning, 2,
            "the detached handler and queued request both remain in flight"
        );
        assert_eq!(
            in_flight.load(Ordering::Relaxed),
            0,
            "cleanup and the next response release their lifecycle guards"
        );
    }

    #[derive(Clone, Copy)]
    enum HandlerOutcome {
        Response,
        CallPanic,
        FuturePanic,
    }

    #[allow(clippy::panic)] // Deliberate construction and poll panics verify error-response ownership.
    async fn response_holds_capacity(outcome: HandlerOutcome) {
        let inner = service_fn(move |_request: Request<()>| {
            if matches!(outcome, HandlerOutcome::CallPanic) {
                panic!("the service panics before returning its future");
            }
            async move {
                if matches!(outcome, HandlerOutcome::FuturePanic) {
                    panic!("the service future panics");
                }
                Ok::<_, io::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        });
        let in_flight = Arc::new(AtomicUsize::new(0));
        let (mut service, available) = managed_service(inner, Arc::new(RequestStats::default()), Arc::clone(&in_flight));
        let first = Service::call(&mut service, Request::new(()))
            .await
            .expect("panic isolation returns a response");
        let expected_status = match outcome {
            HandlerOutcome::Response => http::StatusCode::OK,
            HandlerOutcome::CallPanic | HandlerOutcome::FuturePanic => http::StatusCode::INTERNAL_SERVER_ERROR,
        };
        assert_eq!(first.status(), expected_status);
        assert_eq!(*available.borrow(), 0, "the response owns its request permit");
        let mut second = Service::call(&mut service, Request::new(()));
        let mut context = Context::from_waker(noop_waker_ref());
        assert!(
            second.as_mut().poll(&mut context).is_pending(),
            "the undrained response keeps the next handler queued"
        );
        assert_eq!(
            in_flight.load(Ordering::Relaxed),
            2,
            "the response and queued request retain their guards"
        );

        let mut first_body = first.into_body();
        let _ = first_body
            .frame()
            .await
            .expect("the first response has a data frame")
            .expect("the first response frame succeeds");
        assert!(first_body.is_end_stream(), "the frame ends the first response");
        assert_eq!(
            in_flight.load(Ordering::Relaxed),
            1,
            "handing over the final frame ends the response guard"
        );
        let second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("the final frame releases capacity while the first body remains alive")
            .expect("the next request is isolated too");
        let _ = second.into_body().collect().await.expect("the next response body completes");
        drop(first_body);
        assert_eq!(*available.borrow(), 1, "completed response bodies leave no permit behind");
        assert_eq!(in_flight.load(Ordering::Relaxed), 0, "completed response bodies leave no guard behind");
    }

    #[tokio::test]
    async fn http1_peer_loss_keeps_request_capacity_through_detached_cleanup() {
        detached_cleanup_holds_capacity(Version::HTTP_11, CleanupOutcome::Response).await;
    }

    #[tokio::test]
    async fn http2_peer_loss_keeps_request_capacity_through_detached_cleanup() {
        detached_cleanup_holds_capacity(Version::HTTP_2, CleanupOutcome::Response).await;
    }

    #[tokio::test]
    async fn a_detached_handler_error_releases_capacity_after_cleanup() {
        detached_cleanup_holds_capacity(Version::HTTP_11, CleanupOutcome::Error).await;
    }

    #[tokio::test]
    async fn a_detached_handler_panic_releases_capacity_after_cleanup() {
        detached_cleanup_holds_capacity(Version::HTTP_2, CleanupOutcome::Panic).await;
    }

    #[tokio::test]
    async fn a_successful_handler_transfers_capacity_into_its_response_body() {
        response_holds_capacity(HandlerOutcome::Response).await;
    }

    #[tokio::test]
    async fn a_synchronous_panic_transfers_capacity_into_its_error_response_body() {
        response_holds_capacity(HandlerOutcome::CallPanic).await;
    }

    #[tokio::test]
    async fn an_async_panic_transfers_capacity_into_its_error_response_body() {
        response_holds_capacity(HandlerOutcome::FuturePanic).await;
    }

    #[tokio::test]
    async fn a_handler_error_releases_capacity_and_completes_its_guard() {
        let inner =
            service_fn(|_request: Request<()>| async { Err::<Response<Full<Bytes>>, _>(io::Error::other("the handler failed")) });
        let stats = Arc::new(RequestStats::default());
        stats.begin_shutdown();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let (mut service, available) = managed_service(inner, Arc::clone(&stats), Arc::clone(&in_flight));
        assert!(
            Service::call(&mut service, Request::new(())).await.is_err(),
            "handler errors remain errors"
        );
        assert_eq!(*available.borrow(), 1, "handler errors leave no permit behind");
        assert_eq!(in_flight.load(Ordering::Relaxed), 0, "handler errors leave no guard behind");
        assert_eq!(stats.drained(), 1, "handler errors preserve completed shutdown accounting");
    }

    #[tokio::test]
    async fn force_abort_drops_the_handler_without_detaching_cleanup() {
        struct DropMarker(Arc<AtomicBool>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let inner = service_fn({
            let dropped = Arc::clone(&dropped);
            move |_request: Request<()>| {
                let dropped = Arc::clone(&dropped);
                async move {
                    let _marker = DropMarker(dropped);
                    std::future::pending::<Result<Response<Full<Bytes>>, io::Error>>().await
                }
            }
        });
        let stats = Arc::new(RequestStats::default());
        let in_flight = Arc::new(AtomicUsize::new(0));
        let (mut service, available) = managed_service(inner, Arc::clone(&stats), Arc::clone(&in_flight));
        let mut request = Service::call(&mut service, Request::new(()));
        let mut context = Context::from_waker(noop_waker_ref());
        assert!(request.as_mut().poll(&mut context).is_pending(), "the handler is still running");
        stats.force_abort();
        drop(request);
        assert!(dropped.load(Ordering::SeqCst), "force abort drops the handler synchronously");
        assert_eq!(*available.borrow(), 1, "force abort leaves no permit behind");
        assert_eq!(in_flight.load(Ordering::Relaxed), 0, "force abort leaves no guard behind");
        assert_eq!(stats.aborted(), 1, "force abort accounts for the interrupted request");
    }
}

#[cfg(test)]
mod receipt_lifetime_tests;
