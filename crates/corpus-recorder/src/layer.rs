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

//! Responsible for: the tower `Layer`/`Service` pair a host mounts, its checked constructor,
//! and capturing the request head and response head around the inner service.
//! Not responsible for: the body tap (`body`), naming the operation (`classify`), the runtime
//! gate's rules (`config`), or anything written to disk (`writer`).
//! Upstream: the host's `tower::ServiceBuilder`, in a build with `corpus-record` on.
//! Downstream: the inner service, which receives the same request with its body wrapped in a
//! pass-through [`TapBody`].

use std::fs::OpenOptions;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use http::{HeaderMap, Request, Response};
use pin_project_lite::pin_project;
use rustfs_gateway::{HostResolver, PathStyleOnly};

use crate::body::{Capture, Head, TapBody};
use crate::classify;
use crate::config::{self, RecorderConfig, RecorderRefused};
use crate::writer::{RecorderStats, Sink};

struct Shared {
    sink: Arc<Sink>,
    resolver: Arc<dyn HostResolver>,
}

/// Records every request the wrapped service serves as a corpus entry.
///
/// Construct it with [`CorpusRecorderLayer::new_checked`] at startup and propagate the error: a
/// refusal means this process must not serve. Clones share one writer and one set of counters.
#[derive(Clone)]
pub struct CorpusRecorderLayer {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for CorpusRecorderLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorpusRecorderLayer").field("stats", &self.stats()).finish()
    }
}

impl CorpusRecorderLayer {
    /// Builds a recorder, or refuses to.
    ///
    /// Refuses unless the process environment sets [`crate::RECORD_ENV`] to exactly `1` **and**
    /// every configured access key is on [`crate::TEST_ACCESS_KEYS`], and unless the source is on
    /// the corpus allowlist and the output file opens. Starts the writer thread on success.
    ///
    /// # Errors
    ///
    /// Every [`RecorderRefused`] variant; the host must not start serving on any of them.
    pub fn new_checked(config: RecorderConfig) -> Result<Self, RecorderRefused> {
        Self::new_checked_with_env(config, |name| std::env::var(name).ok())
    }

    /// [`Self::new_checked`] with the environment supplied by the caller, so a test can exercise
    /// the gate without mutating the process environment.
    ///
    /// # Errors
    ///
    /// As [`Self::new_checked`].
    pub fn new_checked_with_env(config: RecorderConfig, env: impl Fn(&str) -> Option<String>) -> Result<Self, RecorderRefused> {
        config::check(&config, &env)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.output)
            .map_err(RecorderRefused::Output)?;
        let sink = Sink::start(
            file,
            config.src,
            config.sut,
            config.queue_capacity,
            config.max_body_bytes,
            config.max_in_flight_bytes,
        )
        .map_err(RecorderRefused::Output)?;
        Ok(Self {
            shared: Arc::new(Shared {
                sink,
                resolver: Arc::new(PathStyleOnly),
            }),
        })
    }

    /// Names operations with `resolver`'s addressing rule instead of path-style only. A host that
    /// serves virtual-hosted buckets passes the same resolver it routes with.
    #[must_use]
    pub fn with_host_resolver(self, resolver: Arc<dyn HostResolver>) -> Self {
        Self {
            shared: Arc::new(Shared {
                sink: Arc::clone(&self.shared.sink),
                resolver,
            }),
        }
    }

    /// What the recorder has done so far.
    pub fn stats(&self) -> RecorderStats {
        self.shared.sink.counters.read()
    }
}

impl<S> tower::Layer<S> for CorpusRecorderLayer {
    type Service = CorpusRecorderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CorpusRecorderService {
            inner,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The service [`CorpusRecorderLayer`] wraps around an inner service.
#[derive(Clone)]
pub struct CorpusRecorderService<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S> std::fmt::Debug for CorpusRecorderService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorpusRecorderService").finish_non_exhaustive()
    }
}

/// Header pairs as text, in the map's order, or `None` if any value is not UTF-8.
fn text_headers(map: &HeaderMap) -> Option<Vec<(String, String)>> {
    map.iter()
        .map(|(name, value)| {
            std::str::from_utf8(value.as_bytes())
                .ok()
                .map(|text| (name.as_str().to_owned(), text.to_owned()))
        })
        .collect()
}

impl Shared {
    fn capture_for(&self, parts: &http::request::Parts) -> Option<Arc<Capture>> {
        let counters = &self.sink.counters;
        let Some(op) = classify::operation(parts, self.resolver.as_ref()) else {
            counters.unrouted.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let (Some(target), Some(headers)) = (parts.uri.path_and_query(), text_headers(&parts.headers)) else {
            counters.unrepresentable_head.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        Some(Capture::new(
            Head {
                op,
                method: parts.method.as_str().to_owned(),
                target: target.as_str().to_owned(),
                headers,
            },
            Arc::clone(&self.sink),
        ))
    }
}

impl<S, B, ResBody> tower::Service<Request<B>> for CorpusRecorderService<S>
where
    S: tower::Service<Request<TapBody<B>>, Response = Response<ResBody>>,
    B: http_body::Body<Data = bytes::Bytes>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let capture = self.shared.capture_for(&parts);
        let body = match &capture {
            Some(capture) => TapBody::recording(body, Arc::clone(capture)),
            None => TapBody::passthrough(body),
        };
        ResponseFuture {
            inner: self.inner.call(Request::from_parts(parts, body)),
            capture,
        }
    }
}

pin_project! {
    /// The inner service's future, noting the response head for the record on the way out.
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        capture: Option<Arc<Capture>>,
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let output = std::task::ready!(this.inner.poll(context));
        if let Some(capture) = this.capture.take()
            && let Ok(response) = &output
        {
            let headers = response
                .headers()
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
                .collect();
            capture.set_response(response.status().as_u16(), headers);
        }
        Poll::Ready(output)
    }
}
