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

use http::{HeaderValue, Request, Response, Version, header::CONNECTION};
use http_body::{Body, Frame, SizeHint};

/// Whether, and with which idle bound, an assembly reads what an HTTP/1 request body still owed
/// after its answer.
///
/// Installed with [`crate::ServiceBuilder::drain_unread_request_bodies`]. The bound applies to each
/// wait for the next frame, not to the whole body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnreadBodyDrain {
    idle: Option<Duration>,
}

impl UnreadBodyDrain {
    /// A drain that stops once the peer has sent nothing for `idle`.
    ///
    /// A zero `idle` is [`UnreadBodyDrain::unbounded`], as RustFS reads a zero
    /// `RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT`.
    #[must_use]
    pub const fn with_idle_timeout(idle: Duration) -> Self {
        if idle.is_zero() {
            Self::unbounded()
        } else {
            Self { idle: Some(idle) }
        }
    }

    /// A drain that waits for the peer for as long as the connection lasts.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self { idle: None }
    }

    /// The idle bound, if there is one.
    #[must_use]
    pub const fn idle_timeout(&self) -> Option<Duration> {
        self.idle
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
    kept: Option<(Slot<B>, UnreadBodyDrain)>,
}

/// Wraps `request`'s body so that a drop before its end hands it back, when `drain` is set, the
/// request is HTTP/1.0 or HTTP/1.1, and its body had not ended on arrival.
pub(crate) fn retain<B: Body>(request: Request<B>, drain: Option<UnreadBodyDrain>) -> (Request<Retained<B>>, Retention<B>) {
    let (parts, body) = request.into_parts();
    let owed = matches!(parts.version, Version::HTTP_10 | Version::HTTP_11) && !body.is_end_stream();
    match drain.filter(|_| owed) {
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
                    kept: Some((slot, drain)),
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
    /// announces `Connection: close` and the rest of the body is read and discarded in a task of
    /// its own. A body the service still holds, read to its end, or never retained is left alone.
    ///
    /// The drain needs a Tokio runtime to run on; without one the body is released as it would be
    /// without the setting.
    pub(crate) fn settle<T>(self, response: &mut Response<T>) {
        let Some((slot, drain)) = self.kept else {
            return;
        };
        let Some(body) = slot.lock().ok().and_then(|mut kept| kept.take()) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads everything an unread HTTP/1 body
        // still owes, whoever sent it and however large it is, bounded only by the idle wait. That
        // keeps a proxy from turning the answer into a `502`, and it also spends this server's reads
        // on a peer it may have just refused. The intended future behaviour is this crate's
        // server-side lingering close: a byte budget, no linger for an unauthenticated peer.
        response.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
        runtime.spawn(discard(body, drain.idle));
    }
}

/// Reads `body` to its end, a transport error, or `idle` without a frame, and discards every frame.
async fn discard<B: Body>(mut body: Pin<Box<B>>, idle: Option<Duration>) {
    loop {
        let next = poll_fn(|context| body.as_mut().poll_frame(context));
        let frame = match idle {
            Some(idle) => match tokio::time::timeout(idle, next).await {
                Ok(frame) => frame,
                Err(_) => return,
            },
            None => next.await,
        };
        match frame {
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return,
        }
    }
}

#[cfg(test)]
#[path = "unread_body_tests.rs"]
mod tests;
