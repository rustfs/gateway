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

//! Panic isolation controls for `Service::poll_ready` and response `Body` polling.
//!
//! Responsible for: proving panics in `poll_ready`, `Body::poll_frame`, `Body::is_end_stream`,
//! and `Body::size_hint` are contained without unwinding or leaking request capacity permits.
//! NOT responsible for: handler `call`/future panics (`cancellation_capacity_tests`) or transport
//! write receipts (`receipt_lifetime_tests`).
//! Upstream: `ConnectionService`, `ConnectionBody`, `ConnectionResponseBody`. Downstream: tests.

#![allow(clippy::expect_used, clippy::panic)]

use std::convert::Infallible;
use std::future::{Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use tower::Service;

use super::RequestStats;
use super::cancellation_capacity_tests::managed_service;

#[derive(Clone)]
struct PollReadyPanicsOnce {
    polls: Arc<AtomicUsize>,
}

impl Service<Request<()>> for PollReadyPanicsOnce {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("poll_ready panic fixture");
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<()>) -> Self::Future {
        ready(Ok(Response::new(Full::new(Bytes::from_static(b"ok")))))
    }
}

/// Negative — a panic inside `Service::poll_ready` must become a 500 response instead of unwinding
/// out of the connection task, and must not leak the request capacity permit.
#[tokio::test]
async fn n_panicking_poll_ready_returns_500_without_unwinding_or_leaking_capacity() {
    let inner = PollReadyPanicsOnce {
        polls: Arc::new(AtomicUsize::new(0)),
    };
    let stats = Arc::new(RequestStats::default());
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (mut service, available) = managed_service(inner, stats, Arc::clone(&in_flight));

    let first = Service::call(&mut service, Request::new(()))
        .await
        .expect("poll_ready panic must be contained as an HTTP response");
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let _ = first.into_body().collect().await.expect("panic body drains");
    assert_eq!(*available.borrow(), 1, "request capacity permit must be released after poll_ready panic");
    assert_eq!(in_flight.load(Ordering::Relaxed), 0);

    let second = Service::call(&mut service, Request::new(()))
        .await
        .expect("subsequent request succeeds after poll_ready panic");
    assert_eq!(second.status(), StatusCode::OK);
    let body = second.into_body().collect().await.expect("body reads").to_bytes();
    assert_eq!(body, b"ok"[..]);
    assert_eq!(*available.borrow(), 1);
}

struct PanickingFrameBody {
    emitted_first: bool,
    panic_on_end_stream: bool,
    panic_on_size_hint: bool,
}

impl Body for PanickingFrameBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if !this.emitted_first {
            this.emitted_first = true;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"chunk1")))));
        }
        panic!("body poll_frame panic fixture");
    }

    fn is_end_stream(&self) -> bool {
        if self.panic_on_end_stream {
            panic!("body is_end_stream panic fixture");
        }
        false
    }

    fn size_hint(&self) -> SizeHint {
        if self.panic_on_size_hint {
            panic!("body size_hint panic fixture");
        }
        SizeHint::default()
    }
}

/// Negative — a panic in response `Body::poll_frame` must return a stream error instead of
/// unwinding, must release the request capacity permit, and must not mark the request drained.
#[tokio::test]
async fn n_panicking_response_body_poll_frame_returns_stream_error_and_releases_capacity() {
    let inner = tower::service_fn(|_request: Request<()>| async {
        Ok::<_, Infallible>(Response::new(PanickingFrameBody {
            emitted_first: false,
            panic_on_end_stream: false,
            panic_on_size_hint: false,
        }))
    });
    let stats = Arc::new(RequestStats::default());
    stats.begin_shutdown();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (mut service, available) = managed_service(inner, Arc::clone(&stats), Arc::clone(&in_flight));

    let response = Service::call(&mut service, Request::new(()))
        .await
        .expect("handler returns streaming response");
    assert_eq!(*available.borrow(), 0, "permit is held while response body streams");
    let mut body = std::pin::pin!(response.into_body());

    // First frame succeeds.
    let first = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await;
    assert!(matches!(first, Some(Ok(_))), "first frame must succeed");
    assert_eq!(*available.borrow(), 0);

    // Second frame panics inside inner Body::poll_frame — must become Some(Err(_)), not unwind.
    let second = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await;
    assert!(
        matches!(second, Some(Err(_))),
        "body poll_frame panic must be converted to a stream error"
    );
    assert_eq!(*available.borrow(), 1, "body poll_frame panic must immediately release capacity permit");
    assert_eq!(in_flight.load(Ordering::Relaxed), 0);
    assert_eq!(stats.drained(), 0, "a panicked response body must not be counted as drained");
}

/// Negative — panics in `Body::is_end_stream` and `Body::size_hint` must be contained without
/// unwinding or leaking request capacity.
#[tokio::test]
async fn n_panicking_response_body_metadata_methods_do_not_unwind() {
    let inner = tower::service_fn(|_request: Request<()>| async {
        Ok::<_, Infallible>(Response::new(PanickingFrameBody {
            emitted_first: false,
            panic_on_end_stream: true,
            panic_on_size_hint: true,
        }))
    });
    let stats = Arc::new(RequestStats::default());
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (mut service, available) = managed_service(inner, stats, Arc::clone(&in_flight));

    let response = Service::call(&mut service, Request::new(()))
        .await
        .expect("handler returns response");
    let body = response.into_body();
    assert!(!body.is_end_stream(), "panicking is_end_stream must default safely to false");
    assert_eq!(body.size_hint().exact(), None, "panicking size_hint must return default");
    drop(body);
    assert_eq!(*available.borrow(), 1);
    assert_eq!(in_flight.load(Ordering::Relaxed), 0);
}
