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
use std::task::{Context, Poll, ready};

use http::Request;
use tower::Service;

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
    S: Service<Request<B>>,
    F: Service<Request<B>, Response = S::Response, Error = S::Error>,
    S::Future: Send + 'static,
    F::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        for (_, service) in &mut self.routes {
            ready!(service.poll_ready(context))?;
        }
        self.fallback.poll_ready(context)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if let Some((_, service)) = self
            .routes
            .iter_mut()
            .find(|(prefix, _)| request.uri().path().starts_with(prefix))
        {
            Box::pin(service.call(request))
        } else {
            Box::pin(self.fallback.call(request))
        }
    }
}
