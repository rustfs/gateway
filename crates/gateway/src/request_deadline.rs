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

//! Runtime-independent request deadlines.
//!
//! Responsible for: handler, policy snapshot and security failure-floor deadlines without
//! assuming a Tokio runtime.
//! NOT responsible for: choosing either duration or rendering a timeout response.
//! Upstream: clocks and policy sources. Downstream: `service`.

use std::future::Future;
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use rustfs_gateway_core::{BoxFuture, HandlerCancellation, HandlerCancellationSource};
use rustfs_gateway_sig::timing::FailureFloor;

use crate::clock::{MonotonicClock, MonotonicNow};
use crate::ext::{PolicyError, PolicySnapshot, PolicySource};

pub(crate) enum HandlerDeadlineOutcome<T> {
    Completed(T),
    Expired { cleanup_completed: bool },
}

pub(crate) async fn handler_with_deadline<T>(
    mut handler: BoxFuture<'static, T>,
    cancellation: HandlerCancellationSource,
    deadline: Duration,
    cleanup_grace: Duration,
) -> HandlerDeadlineOutcome<T> {
    let mut deadline = Box::pin(futures_timer::Delay::new(deadline));
    let completed = poll_fn(|context| {
        if deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(None);
        }
        if let Poll::Ready(output) = handler.as_mut().poll(context) {
            return Poll::Ready(Some(output));
        }
        Poll::Pending
    })
    .await;
    if let Some(output) = completed {
        return HandlerDeadlineOutcome::Completed(output);
    }

    cancellation.cancel(HandlerCancellation::Deadline);
    let mut grace = Box::pin(futures_timer::Delay::new(cleanup_grace));
    let cleanup_completed = poll_fn(|context| {
        if grace.as_mut().poll(context).is_ready() {
            return Poll::Ready(false);
        }
        if handler.as_mut().poll(context).is_ready() {
            return Poll::Ready(true);
        }
        Poll::Pending
    })
    .await;
    HandlerDeadlineOutcome::Expired { cleanup_completed }
}

pub(crate) async fn policy_snapshot_with_timeout<'a>(
    source: &'a dyn PolicySource,
    identity: Option<&'a rustfs_gateway_sig::Identity>,
    timeout: Duration,
) -> Option<Result<PolicySnapshot, PolicyError>> {
    let mut snapshot = source.snapshot(identity);
    let mut deadline = Box::pin(wait_without_runtime(timeout));
    let mut first_poll = true;
    poll_fn(move |context| {
        if first_poll {
            first_poll = false;
            if let Poll::Ready(result) = snapshot.as_mut().poll(context) {
                return Poll::Ready(Some(result));
            }
            if deadline.as_mut().poll(context).is_ready() {
                return Poll::Ready(None);
            }
            return Poll::Pending;
        }
        if deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(None);
        }
        if let Poll::Ready(result) = snapshot.as_mut().poll(context) {
            return Poll::Ready(Some(result));
        }
        Poll::Pending
    })
    .await
}

async fn wait_without_runtime(duration: Duration) {
    struct Signal {
        fired: AtomicBool,
        waker: Mutex<Option<std::task::Waker>>,
    }

    let signal = Arc::new(Signal {
        fired: AtomicBool::new(false),
        waker: Mutex::new(None),
    });
    let sleeper = Arc::clone(&signal);
    if std::thread::Builder::new()
        .name(String::from("gateway-deadline"))
        .spawn(move || {
            std::thread::sleep(duration);
            sleeper.fired.store(true, Ordering::Release);
            if let Ok(mut slot) = sleeper.waker.lock()
                && let Some(waker) = slot.take()
            {
                waker.wake();
            }
        })
        .is_err()
    {
        return;
    }

    poll_fn(move |context| {
        if signal.fired.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let Ok(mut slot) = signal.waker.lock() else {
            return Poll::Ready(());
        };
        *slot = Some(context.waker().clone());
        if signal.fired.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

pub(crate) fn elapsed_since(clock: &dyn MonotonicClock, started: MonotonicNow) -> Duration {
    Duration::from_millis(clock.monotonic().saturating_millis_since(started))
}

pub(crate) async fn hold_failure_floor(floor: FailureFloor, clock: &dyn MonotonicClock, started: MonotonicNow) {
    if let Some(remaining) = floor.remaining(elapsed_since(clock, started)) {
        wait_without_runtime(remaining).await;
    }
}
