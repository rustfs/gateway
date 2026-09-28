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

//! The transport's side of a request body, and a one-thread executor.
//!
//! Responsible for: handing each stack the same body pieces, with the same exact length, through
//! the interface that stack reads (`http_body::Body` for the gateway, the s3s byte stream for
//! s3s); and running a future to completion without a runtime.
//! NOT responsible for: what a handler does with the bytes (`gateway.rs`, `oracle.rs` drain and
//! digest them).
//! Upstream: `request.rs`. Downstream: both sides of the diff.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use bytes::Bytes;
use futures_core::Stream;

use crate::s3s;

/// A body that hands out fixed pieces, in order, and then ends.
pub(crate) struct ProbeBody {
    pieces: VecDeque<Bytes>,
    remaining: u64,
}

impl ProbeBody {
    pub(crate) fn new(pieces: &[Bytes]) -> Self {
        let pieces: VecDeque<Bytes> = pieces.iter().filter(|piece| !piece.is_empty()).cloned().collect();
        let remaining = pieces.iter().map(|piece| piece.len() as u64).sum();
        Self { pieces, remaining }
    }

    fn next_piece(&mut self) -> Option<Bytes> {
        let piece = self.pieces.pop_front()?;
        self.remaining -= piece.len() as u64;
        Some(piece)
    }
}

impl http_body::Body for ProbeBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.get_mut().next_piece().map(|piece| Ok(http_body::Frame::data(piece))))
    }

    fn is_end_stream(&self) -> bool {
        self.pieces.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.remaining)
    }
}

impl Stream for ProbeBody {
    type Item = Result<Bytes, s3s::StdError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().next_piece().map(Ok))
    }
}

impl s3s::stream::ByteStream for ProbeBody {
    fn remaining_length(&self) -> s3s::stream::RemainingLength {
        usize::try_from(self.remaining)
            .map_or_else(|_| s3s::stream::RemainingLength::unknown(), s3s::stream::RemainingLength::new_exact)
    }
}

struct ParkSignal {
    thread: thread::Thread,
    woken: AtomicBool,
}

impl Wake for ParkSignal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

/// Runs a future to completion on this thread. Both services under test complete without a
/// runtime; a hang here is a service that never answered.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let signal = Arc::new(ParkSignal {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&signal));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                while !signal.woken.swap(false, Ordering::Acquire) {
                    thread::park();
                }
            }
        }
    }
}
