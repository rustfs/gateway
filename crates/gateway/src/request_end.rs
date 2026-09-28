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

//! Whether a transport's request body reached its end before the service answered.
//!
//! Responsible for: [`EndObserved`], a pass-through request body that records its own end of
//! stream, and [`RequestEnd`], which marks a response with
//! `rustfs_gateway_server::UnfinishedRequestBody` when the body it watched had not ended.
//! NOT responsible for: reading, draining or refusing the body (the pipeline and the transport's
//! lingering close do that), or inferring anything from a status, error code or close verdict.
//! Upstream: the tower and hyper adapters in `crate::adapt`. Downstream: the server's lingering
//! close, which gives an initially quiet socket its per-block grace only for a marked response.
//!
//! # Why this is observed at the transport entry
//!
//! RFC 9112 §9.6: a server that closes over request octets it never read sends `RST`, and the peer
//! can lose the response it has not finished reading. A refusal decided on the head (a signature
//! mismatch, an unknown bucket) answers before the pipeline touches the body, so no pipeline stage
//! holds a [`crate::wire_read::WireProgress`] that could prove the body unfinished, and the peer's
//! remainder can reach the server only after it has started to close. The self-held driver in
//! `crate::conn` already decides the same thing from its own body state; this gives the Hyper
//! driver the same observation. It is a measurement of what the body reported, never a guess: a
//! body that was empty on arrival, reached its end, or failed is not marked.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};

pin_project_lite::pin_project! {
    /// A request body that records whether it has ended.
    pub(crate) struct EndObserved<B> {
        #[pin]
        inner: B,
        // `None` when the body had already ended on arrival: there is nothing to observe, and the
        // bodyless request pays no allocation for it.
        ended: Option<Arc<AtomicBool>>,
    }
}

impl<B: Body> Body for EndObserved<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let polled = this.inner.poll_frame(context);
        // A body that failed makes no claim that readable octets remain; only a live body does.
        if matches!(polled, Poll::Ready(None | Some(Err(_))))
            && let Some(ended) = this.ended
        {
            ended.store(true, Ordering::Release);
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// What the adapter keeps of an [`EndObserved`] body after handing it to the service.
pub(crate) struct RequestEnd {
    ended: Option<Arc<AtomicBool>>,
}

impl RequestEnd {
    /// Marks `response` when the watched body had not ended by the time it was produced.
    pub(crate) fn mark_unfinished<T>(&self, response: &mut Response<T>) {
        #[cfg(feature = "server")]
        if let Some(ended) = &self.ended
            && !ended.load(Ordering::Acquire)
        {
            response.extensions_mut().insert(rustfs_gateway_server::UnfinishedRequestBody);
        }
        #[cfg(not(feature = "server"))]
        let _ = (&self.ended, response);
    }
}

/// Wraps `request`'s body so its end can be read back after the service answers.
pub(crate) fn observe_end<B: Body>(request: Request<B>) -> (Request<EndObserved<B>>, RequestEnd) {
    let (parts, inner) = request.into_parts();
    let ended = (cfg!(feature = "server") && !inner.is_end_stream()).then(|| Arc::new(AtomicBool::new(false)));
    let end = RequestEnd { ended: ended.clone() };
    (Request::from_parts(parts, EndObserved { inner, ended }), end)
}

#[cfg(all(test, feature = "server"))]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::convert::Infallible;
    use std::future::poll_fn;

    use bytes::Bytes;
    use rustfs_gateway_server::UnfinishedRequestBody;

    use super::*;

    /// A body whose octets have not arrived yet: the socket the peer still owes.
    struct Owed;

    impl Body for Owed {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Pending
        }
    }

    /// A body that fails on its first poll, as a broken transport does.
    struct Broken;

    impl Body for Broken {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            Poll::Ready(Some(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))))
        }
    }

    fn put<B>(body: B) -> Request<B> {
        Request::builder()
            .method(http::Method::PUT)
            .uri("/bucket/key")
            .header(http::header::HOST, "s3.example.com")
            .header(http::header::CONTENT_LENGTH, "24")
            .body(body)
            .expect("a valid request")
    }

    fn marked<T>(response: &Response<T>) -> bool {
        response.extensions().get::<UnfinishedRequestBody>().is_some()
    }

    /// Positive — a refusal decided on the head, over a body the peer still owes, is marked on
    /// the hyper path so the server lingers for the octets instead of resetting over them.
    #[tokio::test]
    async fn a_head_refusal_over_an_owed_body_is_marked_on_the_hyper_path() {
        let service = crate::tests::minimal_service();
        let response = hyper::service::Service::call(&service, put(Owed)).await.expect("infallible");
        assert!(!response.status().is_success(), "the head must be refused: {}", response.status());
        assert!(marked(&response), "the owed body was not reported unfinished");
    }

    /// Positive — the tower path is the same observation.
    #[tokio::test]
    async fn a_head_refusal_over_an_owed_body_is_marked_on_the_tower_path() {
        let mut service = crate::tests::minimal_service();
        let response = tower::Service::call(&mut service, put(Owed)).await.expect("infallible");
        assert!(marked(&response), "the owed body was not reported unfinished");
    }

    /// Negative — a bodyless request has nothing to linger over.
    #[tokio::test]
    async fn a_bodyless_refusal_is_not_marked() {
        let service = crate::tests::minimal_service();
        let request = Request::builder()
            .uri("/bucket/key")
            .header(http::header::HOST, "s3.example.com")
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("a valid request");
        let response = hyper::service::Service::call(&service, request).await.expect("infallible");
        assert!(!marked(&response));
    }

    /// Negative — a body that was empty on arrival is not watched at all.
    #[test]
    fn an_empty_body_is_neither_watched_nor_marked() {
        let (_request, end) = observe_end(put(http_body_util::Empty::<Bytes>::new()));
        assert!(end.ended.is_none(), "an empty body paid for an observer");
        let mut response = Response::new(());
        end.mark_unfinished(&mut response);
        assert!(!marked(&response));
    }

    /// Negative — a body read to its end is finished, however the service answered.
    #[tokio::test]
    async fn a_body_read_to_its_end_is_not_marked() {
        let (request, end) = observe_end(put(http_body_util::Full::new(Bytes::from_static(b"first-slice-second-slice"))));
        let mut body = std::pin::pin!(request.into_body());
        while poll_fn(|context| body.as_mut().poll_frame(context)).await.is_some() {}
        let mut response = Response::new(());
        end.mark_unfinished(&mut response);
        assert!(!marked(&response));
    }

    /// Negative — a body that failed makes no claim that readable octets remain.
    #[tokio::test]
    async fn a_failed_body_is_not_marked() {
        let (request, end) = observe_end(put(Broken));
        let mut body = std::pin::pin!(request.into_body());
        assert!(
            poll_fn(|context| body.as_mut().poll_frame(context))
                .await
                .is_some_and(|frame| frame.is_err())
        );
        let mut response = Response::new(());
        end.mark_unfinished(&mut response);
        assert!(!marked(&response));
    }
}
