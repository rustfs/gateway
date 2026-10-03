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

//! The send-progress deadline of an HTTP/2 response (rustfs/gateway#1206).
//!
//! Responsible for: running every HTTP/2 stream Hyper spawns under [`SendDeadline`], and abandoning
//! a stream — dropping it, which resets it — once its response has waited `write_progress_timeout`
//! on the peer for send capacity while it still holds its request permit.
//! NOT responsible for: HTTP/1.1, where the same stall is a socket that stops accepting writes and
//! `io.rs`'s write-progress deadline ends it; time the service spends producing a response or a
//! body frame, which is never charged here; or a stream whose response already released its
//! permit, which the connection's own deadlines bound.
//! Upstream: Hyper's HTTP/2 server, through [`StreamExecutor`]; `connection_service` reports each
//! response's progress. Downstream: Tokio.
//!
//! # Why the executor
//!
//! A response body over HTTP/2 finishes only when the peer grants it send capacity. Hyper polls one
//! frame and then waits for capacity with no deadline, and does not poll the body again until it
//! has some (hyper 1.11 `PipeToSendStream::poll`), so neither the body nor the socket sees anything
//! happen: the socket is not stalled, it simply has nothing it may send. The response keeps its
//! request permit for that whole wait, and a peer that advertises a zero window over enough
//! streams holds every permit the listener has, at which point the listener stops accepting. The
//! only code that runs for a stream while it waits is the task Hyper spawned for it, so that is
//! where the deadline lives.
//!
//! That task's future learns its stream's [`SendProgress`] from a task-local set only while
//! [`SendDeadline`] polls it; `ConnectionService` reads it on its first poll. A request served
//! outside such a task — HTTP/1.1, or a self-held driver — finds none and arms nothing.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use pin_project_lite::pin_project;
use tokio::time::{Instant, Sleep};

use crate::io::transport_now;

tokio::task_local! {
    static STREAM_PROGRESS: SendProgress;
}

/// One HTTP/2 response's send progress, shared by its stream task and its response body: when the
/// transport began holding a body frame it cannot send yet, or `None` while the service is
/// producing the next one, which is never charged.
#[derive(Clone, Default)]
pub(crate) struct SendProgress {
    waiting_since: Arc<Mutex<Option<Instant>>>,
}

impl SendProgress {
    /// The progress of the HTTP/2 stream whose task is polling the caller, if there is one.
    pub(crate) fn current() -> Option<Self> {
        STREAM_PROGRESS.try_with(Clone::clone).ok()
    }

    /// The transport now holds a body frame that is not the body's last, and asks for nothing more
    /// until the peer lets it send that frame.
    pub(crate) fn wait_for_peer(&self) {
        *self.lock() = Some(transport_now());
    }

    /// The transport asked the body for its next frame: whatever it held has been sent.
    pub(crate) fn producing(&self) {
        *self.lock() = None;
    }

    fn waiting_since(&self) -> Option<Instant> {
        *self.lock()
    }

    fn lock(&self) -> MutexGuard<'_, Option<Instant>> {
        self.waiting_since.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pin_project! {
    /// One HTTP/2 stream task, abandoned once its response has waited `timeout` on the peer.
    pub(crate) struct SendDeadline<F> {
        #[pin]
        stream: F,
        progress: SendProgress,
        timeout: Duration,
        #[pin]
        sleep: Option<Sleep>,
    }
}

impl<F> SendDeadline<F> {
    pub(crate) fn new(stream: F, timeout: Duration) -> Self {
        Self {
            stream,
            progress: SendProgress::default(),
            timeout,
            sleep: None,
        }
    }
}

impl<F: Future> Future for SendDeadline<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        let stream = this.stream;
        if STREAM_PROGRESS
            .sync_scope(this.progress.clone(), || stream.poll(context))
            .is_ready()
        {
            return Poll::Ready(());
        }
        // A timeout past what an instant can hold is never reached.
        let Some(deadline) = this
            .progress
            .waiting_since()
            .and_then(|since| since.checked_add(*this.timeout))
        else {
            return Poll::Pending;
        };
        match this.sleep.as_mut().as_pin_mut() {
            Some(sleep) if sleep.deadline() == deadline => {}
            Some(sleep) => sleep.reset(deadline),
            None => this.sleep.set(Some(tokio::time::sleep_until(deadline))),
        }
        let expired = this.sleep.as_pin_mut().is_some_and(|sleep| sleep.poll(context).is_ready());
        if !expired {
            return Poll::Pending;
        }
        tracing::debug!(
            timeout_ms = u64::try_from(this.timeout.as_millis()).unwrap_or(u64::MAX),
            "HTTP/2 response abandoned: its peer granted no send capacity within write_progress_timeout"
        );
        Poll::Ready(())
    }
}

/// The executor Hyper spawns each HTTP/2 stream on: Tokio's, with every stream under a
/// [`SendDeadline`] of `write_progress_timeout`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamExecutor {
    timeout: Duration,
}

impl StreamExecutor {
    pub(crate) const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<F> hyper::rt::Executor<F> for StreamExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, stream: F) {
        tokio::spawn(SendDeadline::new(stream, self.timeout));
    }
}
