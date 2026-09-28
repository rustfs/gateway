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

//! How the assembled service is reached from `tower` and from `hyper`.
//!
//! Responsible for: the `tower::Service` and `hyper::service::Service` implementations for
//! [`S3Service`] and [`crate::MonomorphicService`], and [`ServiceFuture`], the boxed future they
//! return.
//! NOT responsible for: any protocol decision. Both implementations forward to
//! [`S3Service::call`] and add only what a transport entry observes: the connection verdict
//! announcement and whether the request body had ended when the answer was produced
//! (`crate::request_end`). If a behaviour differs between the two paths, it is a defect in one of
//! the two libraries or in this file, and never a policy.
//! Upstream: `crate::service`. Downstream: P7-02's server, and any tower stack.
//!
//! # Why `poll_ready` is always ready
//!
//! Back-pressure in this framework is per bucket and per identity, and `poll_ready` is handed no
//! request at all — so a limit expressed there can only be per service, which is the one dimension
//! an object store does not need. The [`crate::Governor`] runs where the bucket is known.
//! Connection-level admission is the accept loop's, and that is P7-02's.
//!
//! # Why the future is boxed
//!
//! `S3Service::call` is an `async fn` whose future borrows the service for the duration of the
//! call, and `tower::Service::Future` must be `'static`. Boxing it after cloning the service — one
//! `Arc::clone` — is the only shape that satisfies both without an `unsafe` projection, which this
//! crate forbids. It is one allocation per request, on top of the one the erased handler already
//! pays.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response};
use rustfs_gateway_stream::Body;

use crate::service::S3Service;
use crate::{MonomorphicOperationSet, MonomorphicService};

/// The future both adapters return.
pub type ServiceFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

/// Turns the refusal's connection verdict into the hop-by-hop header that carries it.
///
/// **This is the only place in the crate that writes `Connection`,** and it is here because this is
/// the only place a connection exists. `crate::render` publishes the verdict into the response's
/// extensions, which never reach the wire; a transport reads it and announces it.
///
/// RFC 9112 §9.6 is why announcing it matters: a peer that is told stops pipelining, and a peer
/// that is not discovers the close as a failed write on a request it has already sent. It is still
/// only an announcement — hyper closes the connection because it reads this header, and a
/// transport that wrote the header without closing would be lying to its peer in exactly the way
/// the socket observation in `crates/conformance` exists to catch.
pub(crate) fn announce_connection_verdict(response: &mut Response<Body>) {
    if crate::render::connection_intent_of(response).is_some_and(crate::close::ConnectionIntent::must_close) {
        response
            .headers_mut()
            .insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
    }
}

impl<B> tower::Service<Request<B>> for S3Service
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Body>;
    /// Never returned. See the module documentation for why the type is spelled this way rather
    /// than left open.
    type Error = Infallible;
    type Future = ServiceFuture;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let (request, end) = crate::request_end::observe_end(request);
            let mut response = service.call(request).await;
            end.mark_unfinished(&mut response);
            announce_connection_verdict(&mut response);
            Ok(response)
        })
    }
}

impl<B> hyper::service::Service<Request<B>> for S3Service
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Body>;
    /// Never returned, for the same reason as the tower implementation: hyper answers an `Err` by
    /// dropping the connection, so a `400` would reach the client as a reset.
    type Error = Infallible;
    type Future = ServiceFuture;

    fn call(&self, request: Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let (request, end) = crate::request_end::observe_end(request);
            let mut response = service.call(request).await;
            end.mark_unfinished(&mut response);
            announce_connection_verdict(&mut response);
            Ok(response)
        })
    }
}

impl<B, H, Operations> tower::Service<Request<B>> for MonomorphicService<H, Operations>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    H: Send + Sync + 'static,
    Operations: MonomorphicOperationSet<H>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = ServiceFuture;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let (request, end) = crate::request_end::observe_end(request);
            let mut response = service.call(request).await;
            end.mark_unfinished(&mut response);
            announce_connection_verdict(&mut response);
            Ok(response)
        })
    }
}

impl<B, H, Operations> hyper::service::Service<Request<B>> for MonomorphicService<H, Operations>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    H: Send + Sync + 'static,
    Operations: MonomorphicOperationSet<H>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = ServiceFuture;

    fn call(&self, request: Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let (request, end) = crate::request_end::observe_end(request);
            let mut response = service.call(request).await;
            end.mark_unfinished(&mut response);
            announce_connection_verdict(&mut response);
            Ok(response)
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// a-asm-0020. Negative — the error type is `Infallible`, so "return `Err` from `call`" is not a path that
    /// exists rather than one nobody takes. This is a compile-time assertion.
    #[test]
    fn neither_adapter_can_return_an_error() {
        fn assert_infallible<S, R>()
        where
            S: tower::Service<R, Error = Infallible>,
        {
        }
        assert_infallible::<S3Service, Request<http_body_util::Full<bytes::Bytes>>>();
    }

    /// a-asm-0007. The monomorphic service is a drop-in tower and hyper service too.
    #[test]
    fn the_static_service_has_both_infallible_adapters() {
        type Operations = crate::OperationSetNode<crate::dto::ListBuckets, crate::OperationSetEnd>;
        type Service = crate::MonomorphicService<crate::tests::NoBackend, Operations>;
        type Request = http::Request<http_body_util::Full<bytes::Bytes>>;

        fn assert_tower<S>()
        where
            S: tower::Service<Request, Error = Infallible>,
        {
        }
        fn assert_hyper<S>()
        where
            S: hyper::service::Service<Request, Error = Infallible>,
        {
        }
        assert_tower::<Service>();
        assert_hyper::<Service>();
    }

    /// Negative — `poll_ready` never reports pending, so a tower stack cannot mistake this service
    /// for one that applies back-pressure.
    #[test]
    fn poll_ready_is_always_ready() {
        let mut service = crate::tests::minimal_service();
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        let ready =
            <S3Service as tower::Service<Request<http_body_util::Full<bytes::Bytes>>>>::poll_ready(&mut service, &mut context);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
    }
}
