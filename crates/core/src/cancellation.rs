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

//! Runtime-independent handler cancellation primitives.
//!
//! Responsible for: one monotonic framework signal and every handler task awaiting it.
//! NOT responsible for: choosing deadlines, polling handlers, or deciding response bytes.
//! Upstream: the facade's handler-deadline owner. Downstream: typed operation handlers.

use std::future::poll_fn;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Poll, Waker};

/// Why the framework asked a handler to stop work.
///
/// The list is intentionally closed inside this crate but non-exhaustive to downstream handlers.
/// A handler should use [`HandlerContext::cancelled`] instead of assuming that deadlines remain the
/// only cancellation source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HandlerCancellation {
    /// The operation-specific handler deadline expired.
    Deadline,
    /// The transport stopped waiting for this request, for example after a client reset.
    RequestAborted,
}

impl HandlerCancellation {
    const NONE: u8 = 0;
    const DEADLINE: u8 = 1;
    const REQUEST_ABORTED: u8 = 2;

    const fn code(self) -> u8 {
        match self {
            Self::Deadline => Self::DEADLINE,
            Self::RequestAborted => Self::REQUEST_ABORTED,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            Self::DEADLINE => Some(Self::Deadline),
            Self::REQUEST_ABORTED => Some(Self::RequestAborted),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct HandlerCancellationState {
    reason: AtomicU8,
    waiters: Mutex<Vec<(Weak<()>, Waker)>>,
}

impl HandlerCancellationState {
    fn reason(&self) -> Option<HandlerCancellation> {
        HandlerCancellation::from_code(self.reason.load(Ordering::Acquire))
    }

    fn waiters(&self) -> MutexGuard<'_, Vec<(Weak<()>, Waker)>> {
        match self.waiters.lock() {
            Ok(waiters) => waiters,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct HandlerCancellationRegistration {
    state: Arc<HandlerCancellationState>,
    key: Arc<()>,
}

impl HandlerCancellationRegistration {
    fn poll(&mut self, context: &mut std::task::Context<'_>) -> Poll<HandlerCancellation> {
        if let Some(reason) = self.state.reason() {
            return Poll::Ready(reason);
        }
        let key = Arc::downgrade(&self.key);
        let mut waiters = self.state.waiters();
        if let Some(reason) = self.state.reason() {
            return Poll::Ready(reason);
        }
        if let Some((_, waiter)) = waiters.iter_mut().find(|(candidate, _)| Weak::ptr_eq(candidate, &key)) {
            if !waiter.will_wake(context.waker()) {
                *waiter = context.waker().clone();
            }
        } else {
            waiters.push((key, context.waker().clone()));
        }
        Poll::Pending
    }
}

impl Drop for HandlerCancellationRegistration {
    fn drop(&mut self) {
        let key = Arc::downgrade(&self.key);
        self.state.waiters().retain(|(candidate, _)| !Weak::ptr_eq(candidate, &key));
    }
}

/// Framework-owned half of one handler cancellation signal.
///
/// A service creates a paired handle and [`HandlerContext`] before invoking a handler. The handler
/// receives only the context; retaining the handle is what lets the framework signal a deadline
/// without giving the backend authority to manufacture one.
#[derive(Clone, Debug)]
pub struct HandlerCancellationSource {
    state: Arc<HandlerCancellationState>,
}

impl HandlerCancellationSource {
    /// Creates the framework handle and the context passed to one handler invocation.
    #[must_use]
    pub fn pair() -> (Self, HandlerContext) {
        let state = Arc::new(HandlerCancellationState {
            reason: AtomicU8::new(HandlerCancellation::NONE),
            waiters: Mutex::new(Vec::new()),
        });
        (
            Self {
                state: Arc::clone(&state),
            },
            HandlerContext { state },
        )
    }

    /// Signals cancellation once and wakes every registered handler waiter.
    ///
    /// Returns `true` only for the first signal. Later calls cannot replace the first reason.
    pub fn cancel(&self, reason: HandlerCancellation) -> bool {
        if self
            .state
            .reason
            .compare_exchange(HandlerCancellation::NONE, reason.code(), Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let waiters = {
            let mut registered = self.state.waiters();
            std::mem::take(&mut *registered)
        };
        for (registration, waiter) in waiters {
            if registration.upgrade().is_some() {
                waiter.wake();
            }
        }
        true
    }
}

/// Request-scoped execution signals available to a typed handler.
///
/// This is deliberately separate from [`crate::Req`]: cancellation is execution state, not
/// decoded request data, and ADR-0010 fixes the request wrapper's exact layout. Clones observe the
/// same monotonic signal and may await it from separate handler tasks.
#[derive(Clone, Debug)]
pub struct HandlerContext {
    state: Arc<HandlerCancellationState>,
}

impl HandlerContext {
    /// Whether the framework has asked this handler to stop.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.reason().is_some()
    }

    /// The first cancellation reason, if one has been signalled.
    #[must_use]
    pub fn cancellation_reason(&self) -> Option<HandlerCancellation> {
        self.state.reason()
    }

    /// Waits until the framework asks this handler to stop and returns the reason.
    pub async fn cancelled(&self) -> HandlerCancellation {
        let mut registration = HandlerCancellationRegistration {
            state: Arc::clone(&self.state),
            key: Arc::new(()),
        };
        poll_fn(|context| registration.poll(context)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn counting_waker() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        (Arc::clone(&count), Waker::from(count))
    }

    /// Positive — a fresh handler context remains pending until the framework signals it.
    #[test]
    fn a_fresh_handler_context_is_not_cancelled() {
        let (_source, context) = HandlerCancellationSource::pair();
        assert!(!context.is_cancelled());
        assert_eq!(context.cancellation_reason(), None);

        let (_count, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut cancelled = std::pin::pin!(context.cancelled());
        assert_eq!(cancelled.as_mut().poll(&mut cx), Poll::Pending);
    }

    /// Negative — one deadline must wake every handler task waiting on the same request token.
    #[test]
    fn a_deadline_wakes_every_registered_handler_waiter() {
        let (source, context) = HandlerCancellationSource::pair();
        let sibling = context.clone();
        let (first_count, first_waker) = counting_waker();
        let (second_count, second_waker) = counting_waker();
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);
        let mut first = std::pin::pin!(context.cancelled());
        let mut second = std::pin::pin!(sibling.cancelled());

        assert_eq!(first.as_mut().poll(&mut first_cx), Poll::Pending);
        assert_eq!(second.as_mut().poll(&mut second_cx), Poll::Pending);
        assert!(source.cancel(HandlerCancellation::Deadline));
        assert_eq!(first_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(first.as_mut().poll(&mut first_cx), Poll::Ready(HandlerCancellation::Deadline));
        assert_eq!(second.as_mut().poll(&mut second_cx), Poll::Ready(HandlerCancellation::Deadline));
    }

    /// Negative — repeated polls from one task must not create a wake-amplification list.
    #[test]
    fn repeated_poll_registers_one_waker() {
        let (source, context) = HandlerCancellationSource::pair();
        let (count, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut cancelled = std::pin::pin!(context.cancelled());

        assert_eq!(cancelled.as_mut().poll(&mut cx), Poll::Pending);
        assert_eq!(cancelled.as_mut().poll(&mut cx), Poll::Pending);
        assert!(source.cancel(HandlerCancellation::Deadline));
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
    }

    /// Negative — dropping an awaiter before cancellation must unregister its stale waker.
    #[test]
    fn a_dropped_cancellation_waiter_is_not_woken() {
        let (source, context) = HandlerCancellationSource::pair();
        let (count, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut cancelled = std::pin::pin!(context.cancelled());
            assert_eq!(cancelled.as_mut().poll(&mut cx), Poll::Pending);
        }
        assert!(source.cancel(HandlerCancellation::Deadline));
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
    }

    /// Negative — cancellation is monotonic and only the first framework signal wins.
    #[test]
    fn only_the_first_cancellation_signal_wins() {
        let (source, context) = HandlerCancellationSource::pair();
        assert!(source.cancel(HandlerCancellation::Deadline));
        assert!(!source.cancel(HandlerCancellation::Deadline));
        assert!(context.is_cancelled());
        assert_eq!(context.cancellation_reason(), Some(HandlerCancellation::Deadline));
    }
}
