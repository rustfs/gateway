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

//! Request cancellation and capacity ownership unit controls for `ConnectionService`.
//!
//! Responsible for: verifying detached peer-loss cleanup, response-body capacity handoff,
//! handler errors, and force-abort permit/guard accounting.
//! NOT responsible for: `poll_ready` / `Body` panic isolation (`panic_isolation_tests`) or
//! transport write receipts (`receipt_lifetime_tests`).
//! Upstream: `ConnectionService`, `RequestCapacity`. Downstream: tests.

#![allow(clippy::expect_used)] // Test-only fixtures and synchronization terminate the scenario on failure.

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
