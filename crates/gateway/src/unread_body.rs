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

//! Reading and discarding what an HTTP/1 request body still owed after its answer, on a connection
//! the service does not own — the RustFS profile's answer to a hosting Hyper server that would
//! otherwise reset the socket under the answer (rustfs/gateway#1120).
//!
//! Responsible for: [`UnreadBodyDrain`], the setting; [`retain`], which wraps the transport's body
//! so that dropping it before its end hands it back instead of releasing it; and [`Retention::settle`],
//! which, for an HTTP/1.x request whose body was handed back, announces `Connection: close` on the
//! answer and reads the rest of the body in a task of its own until its end, a transport error, or
//! the idle bound.
//! NOT responsible for: whether or how a request is refused, or its connection verdict
//! (`crate::close`); the lingering close of this crate's own server, which owns its socket and reads
//! it there (`rustfs-gateway-server`); or HTTP/2, where dropping a body resets only its stream.
//! Upstream: `crate::adapt`, the tower and Hyper entries. Downstream: the host's connection, through
//! the body it handed the service.
//!
//! # What legacy RustFS does, and why a host needs it
//!
//! Hyper stops reading an HTTP/1 connection as soon as the service drops a request body it has not
//! read to the end, and closes it after the answer; octets the peer is still sending then meet a
//! closed socket, the kernel answers them with `RST`, and a reverse proxy streaming the upload turns
//! the reset into a `502` that hides the answer. RustFS keeps the dropped body alive for that reason
//! (`EarlyResponseBodyService`, `rustfs/src/server/http.rs:706-1010`, rustfs/rustfs#7019): for an
//! HTTP/1.x request whose body had not ended when it arrived, a body its service leaves before the
//! end is read and discarded in the background, raw — no payload hashing, no aws-chunked decoding —
//! with a per-frame idle bound (`RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT`, 300 s, zero for none), and
//! the answer carries `Connection: close`, so the connection ends cleanly once the peer has finished
//! sending. A body read to its end, an empty one and a failed one are left alone, and an HTTP/2
//! stream is dropped as it always was.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Buf;
use http::{HeaderValue, Request, Response, Version, header::CONNECTION};
use http_body::{Body, Frame, SizeHint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Inserted into a request by [`crate::SelfHeldHttp1Driver`], which owns its socket and handles
/// unread request bodies directly on its connection lock rather than via a detached drain task.
/// Crate-private, so external callers cannot construct or spoof it.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SelfHeldTransport;

/// Inserted into a response by [`crate::S3Service`] when a request was refused without an
/// authenticated identity, signalling [`Retention::settle`] to drop any unread body immediately
/// rather than spending background drain work on an unauthenticated peer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SkipUnreadBodyDrain;

/// Whether, and under which bounds, an assembly reads what an HTTP/1 request body still owed
/// after its answer.
///
/// Installed with [`crate::ServiceBuilder::drain_unread_request_bodies`]. Every drain is bounded
/// by an optional per-frame idle timeout, a total wall-clock duration cap, a total byte budget,
/// and a per-service concurrent task ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnreadBodyDrain {
    idle: Option<Duration>,
    max_duration: Duration,
    max_bytes: u64,
    max_concurrent: usize,
}

impl UnreadBodyDrain {
    /// Default total wall-clock cap for one background unread-body drain task.
    pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(30);

    /// Default total byte budget discarded by one background unread-body drain task (16 MiB).
    pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

    /// Default ceiling on concurrent background unread-body drain tasks per assembled service.
    pub const DEFAULT_MAX_CONCURRENT: usize = 64;

    /// A drain that stops once the peer has sent nothing for `idle` (in addition to the total
    /// duration cap, total byte budget, and concurrency ceiling).
    ///
    /// A zero `idle` is [`UnreadBodyDrain::unbounded`], as RustFS reads a zero
    /// `RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT`.
    #[must_use]
    pub const fn with_idle_timeout(idle: Duration) -> Self {
        if idle.is_zero() {
            Self::unbounded()
        } else {
            Self {
                idle: Some(idle),
                max_duration: Self::DEFAULT_MAX_DURATION,
                max_bytes: Self::DEFAULT_MAX_BYTES,
                max_concurrent: Self::DEFAULT_MAX_CONCURRENT,
            }
        }
    }

    /// A drain with no per-frame idle timeout, still bounded by [`Self::DEFAULT_MAX_DURATION`],
    /// [`Self::DEFAULT_MAX_BYTES`], and [`Self::DEFAULT_MAX_CONCURRENT`].
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            idle: None,
            max_duration: Self::DEFAULT_MAX_DURATION,
            max_bytes: Self::DEFAULT_MAX_BYTES,
            max_concurrent: Self::DEFAULT_MAX_CONCURRENT,
        }
    }

    /// Sets the total wall-clock duration cap for one background drain task.
    ///
    /// A zero duration disables background draining fail-closed.
    #[must_use]
    pub const fn with_max_duration(mut self, max_duration: Duration) -> Self {
        self.max_duration = max_duration;
        self
    }

    /// Sets the maximum total bytes one background drain task will read and discard.
    ///
    /// Zero disables background draining fail-closed.
    #[must_use]
    pub const fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Sets the maximum number of concurrent background drain tasks an assembled service may run.
    ///
    /// Zero disables background draining fail-closed; excess unread bodies are dropped immediately.
    #[must_use]
    pub const fn with_max_concurrent(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent = max_concurrent;
        self
    }

    /// The per-frame idle bound, if there is one.
    #[must_use]
    pub const fn idle_timeout(&self) -> Option<Duration> {
        self.idle
    }

    /// The total wall-clock duration cap for one drain task.
    #[must_use]
    pub const fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// The total byte budget for one drain task.
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// The maximum number of concurrent background drain tasks.
    #[must_use]
    pub const fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    const fn allows_draining(&self) -> bool {
        !self.max_duration.is_zero() && self.max_bytes > 0 && self.max_concurrent > 0
    }
}

/// Where a retained body is handed back on drop.
type Slot<B> = Arc<Mutex<Option<Pin<Box<B>>>>>;

pin_project_lite::pin_project! {
    /// The transport's request body, as the service sees it once [`retain`] has wrapped it.
    #[project = RetainedProjection]
    pub(crate) enum Retained<B: Body> {
        /// Not retained: no drain, not HTTP/1.x, or nothing owed on arrival. Costs nothing.
        Through {
            #[pin]
            body: B,
        },
        /// Retained: dropped before its end, the body goes back through `slot`.
        Kept {
            body: Option<Pin<Box<B>>>,
            slot: Slot<B>,
            ended: bool,
        },
    }

    impl<B: Body> PinnedDrop for Retained<B> {
        fn drop(this: Pin<&mut Self>) {
            if let RetainedProjection::Kept { body, slot, ended } = this.project() {
                if *ended {
                    return;
                }
                let Some(body) = body.take() else {
                    return;
                };
                if body.is_end_stream() {
                    return;
                }
                if let Ok(mut kept) = slot.lock() {
                    *kept = Some(body);
                }
            }
        }
    }
}

impl<B: Body> Body for Retained<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            RetainedProjection::Through { body } => body.poll_frame(context),
            RetainedProjection::Kept { body, ended, .. } => {
                let Some(body) = body.as_mut() else {
                    return Poll::Ready(None);
                };
                let polled = body.as_mut().poll_frame(context);
                // A body that ended or failed owes nothing more: neither is handed back.
                if matches!(polled, Poll::Ready(None | Some(Err(_)))) {
                    *ended = true;
                }
                polled
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Through { body } => body.is_end_stream(),
            Self::Kept { body, ended, .. } => *ended || body.as_ref().is_none_or(|body| body.is_end_stream()),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Through { body } => body.size_hint(),
            Self::Kept { body, .. } => body.as_ref().map_or_else(SizeHint::default, |body| body.size_hint()),
        }
    }
}

/// What the adapter keeps of a [`retain`]ed request to settle its answer with.
pub(crate) struct Retention<B: Body> {
    kept: Option<(Slot<B>, UnreadBodyDrain, Option<Arc<Semaphore>>)>,
}

/// Wraps `request`'s body so that a drop before its end hands it back, when `drain` is set, the
/// request is HTTP/1.0 or HTTP/1.1, the transport is not self-held, and its body had not ended on
/// arrival.
pub(crate) fn retain<B: Body>(
    request: Request<B>,
    drain: Option<UnreadBodyDrain>,
    permits: Option<Arc<Semaphore>>,
) -> (Request<Retained<B>>, Retention<B>) {
    let (parts, body) = request.into_parts();
    #[cfg(feature = "server")]
    let driver_managed = parts.extensions.get::<SelfHeldTransport>().is_some();
    #[cfg(not(feature = "server"))]
    let driver_managed = false;
    let owed = !driver_managed && matches!(parts.version, Version::HTTP_10 | Version::HTTP_11) && !body.is_end_stream();
    match drain.filter(|drain| owed && drain.allows_draining()) {
        Some(drain) => {
            let slot: Slot<B> = Arc::new(Mutex::new(None));
            let body = Retained::Kept {
                body: Some(Box::pin(body)),
                slot: Arc::clone(&slot),
                ended: false,
            };
            (
                Request::from_parts(parts, body),
                Retention {
                    kept: Some((slot, drain, permits)),
                },
            )
        }
        None => (Request::from_parts(parts, Retained::Through { body }), Retention { kept: None }),
    }
}

impl<B> Retention<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
{
    /// Settles `response` against the body the service left: when it was handed back, the answer
    /// announces `Connection: close` and the rest of the body is read and discarded in a bounded
    /// background task. Unauthenticated refusals ([`SkipUnreadBodyDrain`]), concurrency-saturated
    /// services, finished bodies, and never-retained bodies are released immediately without
    /// spawning.
    ///
    /// The drain needs a Tokio runtime to run on; without one the body is released as it would be
    /// without the setting.
    pub(crate) fn settle<T>(self, response: &mut Response<T>) {
        let Some((slot, drain, permits)) = self.kept else {
            return;
        };
        if response.extensions().get::<SkipUnreadBodyDrain>().is_some() || !drain.allows_draining() {
            return;
        }
        let Some(body) = slot.lock().ok().and_then(|mut kept| kept.take()) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let permit = match permits {
            Some(semaphore) => match semaphore.try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return,
            },
            None => None,
        };
        response.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
        runtime.spawn(discard(body, drain, permit));
    }
}

/// Reads `body` until EOF, a transport error, `drain.idle` without a frame, `drain.max_duration`
/// total elapsed time, or `drain.max_bytes` discarded bytes, holding `_permit` for the task's life.
async fn discard<B: Body>(mut body: Pin<Box<B>>, drain: UnreadBodyDrain, _permit: Option<OwnedSemaphorePermit>) {
    if !drain.allows_draining() {
        return;
    }
    let mut drained_bytes = 0_u64;
    let _ = tokio::time::timeout(drain.max_duration, async {
        loop {
            let next = poll_fn(|context| body.as_mut().poll_frame(context));
            let frame = match drain.idle {
                Some(idle) => match tokio::time::timeout(idle, next).await {
                    Ok(frame) => frame,
                    Err(_) => return,
                },
                None => next.await,
            };
            match frame {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        drained_bytes = drained_bytes.saturating_add(data.remaining() as u64);
                        if drained_bytes >= drain.max_bytes {
                            return;
                        }
                    }
                }
                Some(Err(_)) | None => return,
            }
        }
    })
    .await;
}

#[cfg(test)]
#[path = "unread_body_tests.rs"]
mod tests;
