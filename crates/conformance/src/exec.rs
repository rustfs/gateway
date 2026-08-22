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

//! Driving futures to completion on the calling thread.
//!
//! Responsible for: [`block_on`], a minimal driver for direct fixture futures, and
//! `ServiceRuntime`, the current-thread Tokio runtime required by facade calls.
//! NOT responsible for: I/O readiness or a work-stealing scheduler. The service runtime enables
//! only timers so committed responses can make progress after returning their frozen head.
//! Upstream: nothing. Downstream: direct fixture tests, `crate::inprocess`, and `crate::socket`.
//!
//! # Why two drivers
//!
//! Direct fixture futures need no runtime. Facade calls do: a committed response captures the
//! current Tokio handle, returns its head, and completes on a detached task while the body is
//! drained. Keeping one current-thread runtime across both polls preserves that ownership contract.

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// A single-thread driver kept alive across a facade call and response drain.
pub(crate) struct ServiceRuntime(tokio::runtime::Runtime);

impl ServiceRuntime {
    /// Builds a timer-enabled runtime without an I/O or work-stealing driver.
    pub(crate) fn new() -> Result<Self, std::io::Error> {
        tokio::runtime::Builder::new_current_thread().enable_time().build().map(Self)
    }

    /// Drives one future while keeping detached facade work on the same runtime alive.
    pub(crate) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }
}

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
