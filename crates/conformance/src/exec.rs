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

//! Driving one future to completion on the calling thread.
//!
//! Responsible for: [`block_on`], twenty lines of `std` that let a synchronous [`crate::sut::Sut`]
//! call an `async` service entry point.
//! NOT responsible for: timers, I/O readiness, or concurrency. There is none of any of them here:
//! the in-process assembly reads an in-memory body and never registers with a reactor, so a future
//! that returns `Pending` is waiting on something this crate did not create — and the park below
//! is then exactly the diagnosis, a hang rather than a wrong answer.
//! Upstream: nothing. Downstream: `crate::inprocess`.
//!
//! # Why not an async runtime
//!
//! This crate is a product other S3 implementations run against themselves, and every dependency
//! it carries is one they inherit. A work-stealing scheduler to run one future at a time on one
//! thread is the largest thing it could have inherited for the least reason.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// Wakes the thread that parked itself waiting for the future.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls `future` on this thread until it is ready, parking in between.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive — a future that is ready immediately never parks.
    #[test]
    fn a_ready_future_returns_its_value() {
        assert_eq!(block_on(async { 7_u8 }), 7);
    }

    /// Positive — a future that yields once is resumed by the waker rather than hanging, which is
    /// the only property of this executor that is not trivially true.
    #[test]
    fn a_future_that_yields_once_is_woken_again() {
        struct YieldOnce(bool);
        impl Future for YieldOnce {
            type Output = &'static str;
            fn poll(mut self: std::pin::Pin<&mut Self>, context: &mut Context<'_>) -> Poll<&'static str> {
                if self.0 {
                    return Poll::Ready("resumed");
                }
                self.0 = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
        assert_eq!(block_on(YieldOnce(false)), "resumed");
    }
}
