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
//! Responsible for: notifying the accept loop when request capacity changes and holding a permit
//! through the response body. NOT responsible for: connection or per-IP admission. Upstream:
//! `ServerConfig::max_global_inflight_requests`. Downstream: `conn` accept and service adapters.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, watch};

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

pub(super) struct RequestPermit {
    capacity: Arc<RequestCapacity>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        self.permit.take();
        let _ = self.capacity.available.send(self.capacity.semaphore.available_permits());
    }
}

pin_project! {
    pub(super) struct RequestPermitBody<B> {
        #[pin]
        body: B,
        permit: Option<RequestPermit>,
    }
}

impl<B> RequestPermitBody<B> {
    pub(super) fn new(body: B, permit: RequestPermit) -> Self {
        Self {
            body,
            permit: Some(permit),
        }
    }
}

impl<B: Body> Body for RequestPermitBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let frame = ready!(this.body.as_mut().poll_frame(context));
        if frame.is_none() || this.body.is_end_stream() {
            this.permit.take();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
