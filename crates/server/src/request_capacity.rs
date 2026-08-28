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

//! Global request permits shared by every HTTP/1 and HTTP/2 connection.
//!
//! Responsible for: notifying the accept loop when request capacity changes, holding a permit
//! through the response body, and letting a detached request observe that its peer stopped waiting.
//! NOT responsible for: connection or per-IP admission. Upstream:
//! `ServerConfig::max_global_inflight_requests`. Downstream: `conn` accept and service adapters.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, watch};

/// A request-local signal that becomes `true` when the transport stops waiting for the response.
///
/// The server inserts one into every request extension. A service that starts durable work should
/// wait for the value to change beside that work and finish rollback before returning. Ignoring it
/// leaves cleanup to the service's own deadline policy.
pub type RequestCancellation = watch::Receiver<bool>;

pub(super) struct RequestCancellationSource {
    sender: watch::Sender<bool>,
}

impl RequestCancellationSource {
    pub(super) fn pair() -> (Self, RequestCancellation) {
        let (sender, receiver) = watch::channel(false);
        (Self { sender }, receiver)
    }
}

impl Drop for RequestCancellationSource {
    fn drop(&mut self) {
        let _ = self.sender.send(true);
    }
}

pub(super) struct RequestCancellationFuture<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    future: Option<Pin<Box<F>>>,
    cancellation: Option<RequestCancellationSource>,
    force_abort: Arc<AtomicBool>,
}

impl<F> RequestCancellationFuture<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    pub(super) fn new(future: F, cancellation: RequestCancellationSource, force_abort: Arc<AtomicBool>) -> Self {
        Self {
            future: Some(Box::pin(future)),
            cancellation: Some(cancellation),
            force_abort,
        }
    }
}

impl<F> Future for RequestCancellationFuture<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(future) = this.future.as_mut() else {
            return Poll::Pending;
        };
        match future.as_mut().poll(context) {
            Poll::Ready(output) => {
                this.future.take();
                this.cancellation.take();
                Poll::Ready(output)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F> Drop for RequestCancellationFuture<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn drop(&mut self) {
        let Some(future) = self.future.take() else {
            return;
        };
        self.cancellation.take();
        if self.force_abort.load(Ordering::Acquire) {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = future.await;
            });
        }
    }
}

pub(super) struct RequestCapacity {
    semaphore: Arc<Semaphore>,
    available: watch::Sender<usize>,
}

impl RequestCapacity {
    pub(super) fn new(limit: usize) -> (Arc<Self>, watch::Receiver<usize>) {
        let (available, receiver) = watch::channel(limit);
        (
            Arc::new(Self {
                semaphore: Arc::new(Semaphore::new(limit)),
                available,
            }),
            receiver,
        )
    }

    pub(super) async fn acquire(self: Arc<Self>) -> Result<RequestPermit, AcquireError> {
        let permit = Arc::clone(&self.semaphore).acquire_owned().await?;
        let _ = self.available.send(self.semaphore.available_permits());
        Ok(RequestPermit {
            capacity: self,
            permit: Some(permit),
        })
    }
}

pub(crate) struct RequestPermit {
    capacity: Arc<RequestCapacity>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        self.permit.take();
        let _ = self.capacity.available.send(self.capacity.semaphore.available_permits());
    }
}
