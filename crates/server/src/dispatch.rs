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

//! Generic request-path prefix dispatch.
//!
//! Responsible for: selecting the first caller-supplied prefix or a fallback service.
//! NOT responsible for: interpreting any particular path or normalizing a request target.
//! Upstream: caller-owned route prefixes. Downstream: caller-owned tower services.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::Request;
use tower::{Service, ServiceExt};

/// A tower service that selects a route by raw URI path prefix.
#[derive(Clone, Debug)]
pub struct PrefixDispatch<S, F> {
    routes: Vec<(&'static str, S)>,
    fallback: F,
}

impl<S, F> PrefixDispatch<S, F> {
    /// Creates a dispatcher. Routes are tested in the order supplied.
    #[must_use]
    pub fn new(routes: Vec<(&'static str, S)>, fallback: F) -> Self {
        Self { routes, fallback }
    }
}

impl<S, F, B> Service<Request<B>> for PrefixDispatch<S, F>
where
    S: Service<Request<B>> + Clone + Send + 'static,
    F: Service<Request<B>, Response = S::Response, Error = S::Error> + Clone + Send + 'static,
    S::Future: Send + 'static,
    F::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if let Some((_, service)) = self
            .routes
            .iter()
            .find(|(prefix, _)| request.uri().path().starts_with(prefix))
        {
            let mut service = service.clone();
            Box::pin(async move { service.ready().await?.call(request).await })
        } else {
            let mut fallback = self.fallback.clone();
            Box::pin(async move { fallback.ready().await?.call(request).await })
        }
    }
}
