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
//! Responsible for: handler, body-progress, committed-continuation, policy snapshot and security
//! failure-floor deadlines without assuming a Tokio runtime.
//! NOT responsible for: choosing any duration or rendering a timeout response.
//! Upstream: clocks and policy sources. Downstream: `service`, `dispatch`, `monomorphic`.

use std::future::Future;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use rustfs_gateway_core::{BoxFuture, HandlerCancellation, HandlerCancellationSource, HandlerError, ResponseKind};
use rustfs_gateway_sig::timing::FailureFloor;

use crate::clock::{MonotonicClock, MonotonicNow};
use crate::close::ConnectionIntent;
use crate::ext::{PolicyError, PolicySnapshot, PolicySource};
use crate::render::S3Error;
use crate::request_body::{BodyEvent, BodyMonitor};
use crate::wire_read::RequestBodyUnfinished;

pub(crate) enum HandlerCancellationOutcome<T> {
    Completed(T),
    Expired { cleanup_completed: bool },
    RequestAborted { cleanup_completed: bool },
}

pub(crate) enum BodyMonitoredOutcome<T> {
    Completed(T),
    /// The handler answered, and dropped its body before one octet of it was read; the caller
    /// settles the answer with [`unread_body_answer`].
    Unread {
        output: T,
        body_unfinished: Option<RequestBodyUnfinished>,
    },
    Failed(S3Error),
}

/// The response kind the service renders a handler refusal for.
pub(crate) fn response_kind_of(method: &http::Method) -> ResponseKind {
    if *method == http::Method::HEAD {
        ResponseKind::Head
    } else {
        ResponseKind::Other
    }
}

/// What a handler's answer over a body it dropped unread becomes (rustfs/gateway#794).
///
/// A refusal is the answer. The handler made it without reading the body — the bucket is gone,
/// the caller may not write, a quota is spent — and a `400 IncompleteBody` in its place would
/// blame the client's framing for octets the server chose not to read, inviting a retry that
/// fails the same way. It is rendered exactly as the service renders every handler refusal, plus
/// the proof that the body is still owed, so the transport treats the remainder as it treats any
/// refusal made before the body: lingering over it rather than reading it as the next request
/// (`crate::close::attach_lingering_read`, c-object-0051).
///
/// A success is refused: nothing may be committed from a body that never arrived (`c-ck-0062`).
pub(crate) fn unread_body_answer<X>(
    answer: Result<X, HandlerError>,
    response: ResponseKind,
    body_unfinished: Option<RequestBodyUnfinished>,
) -> S3Error {
    match answer {
        Err(refusal) => {
            let mut refusal = crate::render::from_handler(refusal, response, ConnectionIntent::MayKeepAlive);
            refusal.body_unfinished = body_unfinished;
            // The handler's own answer, which leaves by the body stage: not a refusal of the
            // gateway's to report (`crate::logging::Refused::reading_the_body`).
            refusal.answered_by_handler = true;
            refusal
        }
        Ok(_) => crate::gate::incomplete(),
    }
}

pub(crate) async fn handler_with_body_monitor<T>(
    mut handler: BoxFuture<'static, T>,
    cancellation: HandlerCancellationSource,
    cleanup_grace: Duration,
    mut monitor: Option<BodyMonitor>,
) -> BodyMonitoredOutcome<T> {
    let Some(ref mut monitor) = monitor else {
        return BodyMonitoredOutcome::Completed(handler.await);
    };
    let mut body_event = Box::pin(monitor.next_event());
    let raced = poll_fn(|context| {
        // The terminal body verdict wins a wake shared with the handler result. An unread drop is
        // not a verdict: both orders end in `Unread`, and the handler's answer decides it.
        if let Poll::Ready(event) = body_event.as_mut().poll(context) {
            return Poll::Ready(Err(event));
        }
        if let Poll::Ready(output) = handler.as_mut().poll(context) {
            return Poll::Ready(Ok(output));
        }
        Poll::Pending
    })
    .await;
    match raced {
        Ok(output) => match body_event.await {
            BodyEvent::Complete(Ok(_)) => BodyMonitoredOutcome::Completed(output),
            BodyEvent::Complete(Err(error)) => BodyMonitoredOutcome::Failed(error),
            BodyEvent::Unread(progress) => BodyMonitoredOutcome::Unread {
                output,
                body_unfinished: progress.request_body_unfinished(),
            },
            BodyEvent::Idle(progress) => {
                BodyMonitoredOutcome::Failed(crate::gate::body_idle_timeout(progress.request_body_unfinished()))
            }
            BodyEvent::Throughput(progress) => {
                BodyMonitoredOutcome::Failed(crate::gate::body_throughput_timeout(progress.request_body_unfinished()))
            }
            BodyEvent::Quota(progress) => {
                cancellation.cancel(HandlerCancellation::BodyQuota);
                BodyMonitoredOutcome::Failed(crate::gate::body_quota_refusal(progress.request_body_unfinished()))
            }
        },
        Err(BodyEvent::Complete(Ok(_))) => BodyMonitoredOutcome::Completed(handler.await),
        Err(BodyEvent::Complete(Err(error))) => BodyMonitoredOutcome::Failed(error),
        Err(BodyEvent::Unread(progress)) => BodyMonitoredOutcome::Unread {
            output: handler.await,
            body_unfinished: progress.request_body_unfinished(),
        },
        Err(BodyEvent::Quota(progress)) => {
            cancellation.cancel(HandlerCancellation::BodyQuota);
            let mut grace = Box::pin(futures_timer::Delay::new(cleanup_grace));
            let cleanup_completed = poll_fn(|context| {
                if handler.as_mut().poll(context).is_ready() {
                    return Poll::Ready(true);
                }
                if grace.as_mut().poll(context).is_ready() {
                    return Poll::Ready(false);
                }
                Poll::Pending
            })
            .await;
            let _ = cleanup_completed;
            BodyMonitoredOutcome::Failed(crate::gate::body_quota_refusal(progress.request_body_unfinished()))
        }
        Err(BodyEvent::Idle(progress)) => {
            cancellation.cancel(HandlerCancellation::BodyIdle);
            let mut grace = Box::pin(futures_timer::Delay::new(cleanup_grace));
            let cleanup_completed = poll_fn(|context| {
                if handler.as_mut().poll(context).is_ready() {
                    return Poll::Ready(true);
                }
                if grace.as_mut().poll(context).is_ready() {
                    return Poll::Ready(false);
                }
                Poll::Pending
            })
            .await;
            let _ = cleanup_completed;
            BodyMonitoredOutcome::Failed(crate::gate::body_idle_timeout(progress.request_body_unfinished()))
        }
        Err(BodyEvent::Throughput(progress)) => {
            cancellation.cancel(HandlerCancellation::BodyThroughput);
            let mut grace = Box::pin(futures_timer::Delay::new(cleanup_grace));
            let cleanup_completed = poll_fn(|context| {
                if handler.as_mut().poll(context).is_ready() {
                    return Poll::Ready(true);
                }
                if grace.as_mut().poll(context).is_ready() {
                    return Poll::Ready(false);
                }
                Poll::Pending
            })
            .await;
            let _ = cleanup_completed;
            BodyMonitoredOutcome::Failed(crate::gate::body_throughput_timeout(progress.request_body_unfinished()))
        }
    }
}

/// The timer for one configured deadline, or none for [`crate::NO_DEADLINE`]: a deadline the host
/// lifted arms nothing (ADR-0034).
pub(crate) fn armed(deadline: Duration) -> Option<futures_timer::Delay> {
    (deadline != crate::NO_DEADLINE).then(|| futures_timer::Delay::new(deadline))
}

/// [`armed`] as the future a deadline race polls: one that never completes when nothing is armed.
fn expiry(deadline: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    match armed(deadline) {
        Some(delay) => Box::pin(delay),
        None => Box::pin(core::future::pending()),
    }
}

pub(crate) async fn handler_with_request_cancellation<T>(
    mut handler: BoxFuture<'static, T>,
    cancellation: HandlerCancellationSource,
    deadline: Duration,
    cleanup_grace: Duration,
    request_cancellation: Option<tokio::sync::watch::Receiver<bool>>,
) -> HandlerCancellationOutcome<T> {
    let mut deadline = expiry(deadline);
    let mut request_cancellation = request_cancellation.map(|mut cancellation| {
        Box::pin(async move {
            while !*cancellation.borrow() {
                if cancellation.changed().await.is_err() {
                    core::future::pending::<()>().await;
                }
            }
        }) as Pin<Box<dyn Future<Output = ()> + Send>>
    });
    let stopped = poll_fn(|context| {
        if deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(HandlerCancellation::Deadline));
        }
        if request_cancellation
            .as_mut()
            .is_some_and(|cancelled| cancelled.as_mut().poll(context).is_ready())
        {
            return Poll::Ready(Err(HandlerCancellation::RequestAborted));
        }
        if let Poll::Ready(output) = handler.as_mut().poll(context) {
            return Poll::Ready(Ok(output));
        }
        Poll::Pending
    })
    .await;
    let reason = match stopped {
        Ok(output) => return HandlerCancellationOutcome::Completed(output),
        Err(reason) => reason,
    };

    cancellation.cancel(reason);
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
    match reason {
        HandlerCancellation::Deadline => HandlerCancellationOutcome::Expired { cleanup_completed },
        _ => HandlerCancellationOutcome::RequestAborted { cleanup_completed },
    }
}

/// Bounds the time a committed continuation may go without producing its outcome.
///
/// # Why this is a second deadline and not the handler's
///
/// The handler cancellation boundary produces a [`rustfs_gateway_core::Resp`]. A backend that
/// commits its head returns from that call **immediately**, handing back a
/// continuation the framework drives afterwards — so the three operations AWS documents as
/// flushing their head early are precisely the three the handler deadline stops covering at the
/// moment they start doing the long-running work it was written for.
///
/// # Why the work is dropped rather than cancelled
///
/// There is no cancellation channel into a [`rustfs_gateway_core::CommitWork`]; unlike a handler
/// call there is no [`rustfs_gateway_core::HandlerContext`] to signal on, so there is nothing to
/// wait a cleanup grace for. The continuation is therefore dropped, which cancels it at whatever
/// await point it reached. That is a real cost and it is the reason `P3-06` §4.3 item 2 asks for
/// the work to be spawned so that it outlives the response: doing so needs a runtime, and this
/// crate deliberately has none. Until then the trade is a continuation cancelled after the bound
/// against a request held open for ever, and the second is worse — a client that never learns
/// anything retries, and the retry starts another continuation beside the first.
pub(crate) fn commit_with_progress_deadline<T>(
    work: BoxFuture<'static, Result<T, rustfs_gateway_core::HandlerError>>,
    deadline: Duration,
) -> BoxFuture<'static, Result<T, rustfs_gateway_core::HandlerError>>
where
    T: 'static,
{
    // A lifted bound wraps nothing: the continuation runs exactly as the backend built it.
    if deadline == crate::NO_DEADLINE {
        return work;
    }
    let mut work = work;
    Box::pin(async move {
        let mut expired = expiry(deadline);
        poll_fn(|context| {
            // The work first, and the order is load-bearing: a continuation whose outcome is ready
            // in the same wake as the expiry is an outcome, not a timeout. Polling the timer first
            // would make the bound decide races it is not there to decide.
            if let Poll::Ready(outcome) = work.as_mut().poll(context) {
                return Poll::Ready(outcome);
            }
            if expired.as_mut().poll(context).is_ready() {
                return Poll::Ready(Err(rustfs_gateway_core::HandlerError::internal_error(
                    crate::commit::COMMIT_PROGRESS_EXPIRED,
                )));
            }
            Poll::Pending
        })
        .await
    })
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
    futures_timer::Delay::new(duration).await;
}

pub(crate) fn elapsed_since(clock: &dyn MonotonicClock, started: MonotonicNow) -> Duration {
    Duration::from_millis(clock.monotonic().saturating_millis_since(started))
}

pub(crate) async fn hold_failure_floor(floor: FailureFloor, clock: &dyn MonotonicClock, started: MonotonicNow) {
    if let Some(remaining) = floor.remaining(elapsed_since(clock, started)) {
        wait_without_runtime(remaining).await;
    }
}

#[cfg(test)]
#[path = "request_deadline_resource_tests.rs"]
mod resource_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_core::HandlerError;
    use rustfs_gateway_types::ErrorCode;
    use std::sync::{Arc, Mutex};

    fn bound<T: 'static>(
        work: BoxFuture<'static, Result<T, HandlerError>>,
        deadline: Duration,
    ) -> BoxFuture<'static, Result<T, HandlerError>> {
        commit_with_progress_deadline(work, deadline)
    }

    /// Negative — a handler that keeps running without polling its live body receives the body-idle
    /// reason before the ordinary handler deadline.
    #[tokio::test]
    async fn body_idle_cancels_the_handler_with_its_distinct_reason() {
        let timeouts = crate::gate::BodyTimeouts::new(Duration::from_millis(20), Duration::from_millis(20))
            .expect("non-zero body deadlines");
        let (monitor, _terminal, _progress) = crate::request_body::BodyMonitor::pending_for_test(timeouts);
        let (cancellation, context) = HandlerCancellationSource::pair();
        let observed = Arc::new(Mutex::new(None));
        let handler_observed = Arc::clone(&observed);
        let handler = Box::pin(async move {
            let reason = context.cancelled().await;
            *handler_observed.lock().expect("the observation lock") = Some(reason);
        });

        let outcome = handler_with_body_monitor(handler, cancellation, Duration::from_millis(100), Some(monitor)).await;
        assert!(matches!(outcome, BodyMonitoredOutcome::Failed(_)));
        assert_eq!(*observed.lock().expect("the observation lock"), Some(HandlerCancellation::BodyIdle));
    }

    /// Negative — cleanup can consume the final wire frame after the idle event fired, so the
    /// response must consult the shared EOF observation instead of retaining the event's snapshot.
    #[tokio::test]
    async fn cleanup_rechecks_body_completion_before_marking_the_refusal() {
        struct FinalFrameBody(Option<bytes::Bytes>);

        impl http_body::Body for FinalFrameBody {
            type Data = bytes::Bytes;
            type Error = core::convert::Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _context: &mut core::task::Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                Poll::Ready(self.get_mut().0.take().map(http_body::Frame::data).map(Ok))
            }

            fn is_end_stream(&self) -> bool {
                self.0.is_none()
            }
        }

        let timeouts = crate::gate::BodyTimeouts::new(Duration::from_millis(20), Duration::from_millis(20))
            .expect("non-zero body deadlines");
        let body = FinalFrameBody(Some(bytes::Bytes::from_static(b"last")));
        let wire_progress = crate::wire_read::WireProgress::for_body(crate::gate::BodyDigestObligation::None, Some(&body));
        let mut frames = crate::wire_read::WireFrames::new(
            body,
            wire_progress.clone(),
            crate::gate::BodyCeilings::of("PutObject", 1024),
            timeouts,
        );
        let (monitor, _terminal, _progress) =
            crate::request_body::BodyMonitor::pending_with_wire_progress_for_test(timeouts, wire_progress);
        let (cancellation, context) = HandlerCancellationSource::pair();
        let handler = Box::pin(async move {
            assert_eq!(context.cancelled().await, HandlerCancellation::BodyIdle);
            let frame = poll_fn(|poll_context| frames.poll_next(poll_context)).await;
            assert!(matches!(frame, Ok(Some(_))), "cleanup consumes the final frame");
        });

        let outcome = handler_with_body_monitor(handler, cancellation, Duration::from_millis(100), Some(monitor)).await;
        let BodyMonitoredOutcome::Failed(error) = outcome else {
            panic!("the idle policy must still refuse the request");
        };
        assert!(error.body_unfinished.is_none(), "cleanup reached EOF before the response was rendered");
    }

    /// Negative — byte-at-a-time progress cannot rearm the body deadline forever when one
    /// throughput window receives less than its configured floor.
    #[tokio::test]
    async fn trickle_progress_cancels_the_handler_with_the_throughput_reason() {
        let timeouts = crate::gate::BodyTimeouts::new(Duration::from_millis(50), Duration::from_millis(30))
            .expect("non-zero body deadlines")
            .try_with_throughput_floor(8, Duration::from_millis(40))
            .expect("a non-zero throughput floor");
        let (monitor, _terminal, progress) = crate::request_body::BodyMonitor::pending_for_test(timeouts);
        let feeder = tokio::spawn(async move {
            for delivered in 1..=6 {
                progress.send_replace(delivered);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let (cancellation, context) = HandlerCancellationSource::pair();
        let observed = Arc::new(Mutex::new(None));
        let handler_observed = Arc::clone(&observed);
        let handler = Box::pin(async move {
            let reason = context.cancelled().await;
            *handler_observed.lock().expect("the observation lock") = Some(reason);
        });

        let outcome = handler_with_body_monitor(handler, cancellation, Duration::from_millis(100), Some(monitor)).await;
        feeder.await.expect("the trickle feeder joins");
        assert!(matches!(outcome, BodyMonitoredOutcome::Failed(_)));
        assert_eq!(*observed.lock().expect("the observation lock"), Some(HandlerCancellation::BodyThroughput));
    }

    /// Negative — satisfying a throughput window is not fresh wire progress and cannot postpone
    /// the between-read idle deadline.
    #[tokio::test]
    async fn throughput_window_completion_does_not_rearm_body_idle() {
        let timeouts = crate::gate::BodyTimeouts::new(Duration::from_millis(200), Duration::from_millis(100))
            .expect("non-zero body deadlines")
            .try_with_throughput_floor(1, Duration::from_millis(100))
            .expect("a non-zero throughput floor");
        let (mut monitor, _terminal, progress) = crate::request_body::BodyMonitor::pending_for_test(timeouts);
        progress.send_replace(1);

        let event = monitor.next_event().await;

        assert!(matches!(event, BodyEvent::Idle(_)));
    }

    /// **Negative — a continuation that never resolves reports the bound, not a hang.**
    ///
    /// Both halves are asserted. `InternalError` is the code a client branches on, and the message
    /// is what makes this distinguishable from a backend that reported `InternalError` itself —
    /// which is the only other way that code reaches a committed body.
    #[tokio::test]
    async fn a_continuation_that_never_resolves_reports_the_progress_bound() {
        let work: BoxFuture<'static, Result<(), HandlerError>> = Box::pin(core::future::pending());
        let outcome = bound(work, Duration::from_millis(20)).await;
        let error = outcome.expect_err("a continuation that never resolves cannot have an outcome");
        assert_eq!(*error.code(), ErrorCode::INTERNAL_ERROR);
        assert_eq!(error.message(), crate::commit::COMMIT_PROGRESS_EXPIRED);
    }

    /// **Positive — the first control: an outcome inside the bound is the outcome.**
    ///
    /// Without this the implementation could report the bound unconditionally and the test above
    /// would still be green.
    #[tokio::test]
    async fn an_answer_inside_the_bound_is_the_answer() {
        let work: BoxFuture<'static, Result<u8, HandlerError>> = Box::pin(async { Ok(7) });
        assert_eq!(bound(work, Duration::from_secs(30)).await.ok(), Some(7));
    }

    /// **Negative — the second control: a refusal inside the bound is *that* refusal.**
    ///
    /// The bound wraps every continuation, so the way it goes wrong is by answering for one that
    /// already answered. A wrapper that replaced every `Err` with its own would pass the first test
    /// and this is what catches it.
    #[tokio::test]
    async fn a_refusal_inside_the_bound_keeps_its_own_code_and_message() {
        let work: BoxFuture<'static, Result<(), HandlerError>> =
            Box::pin(async { Err(HandlerError::new(ErrorCode::INVALID_PART, "the backend's own refusal")) });
        let error = bound(work, Duration::from_secs(30)).await.expect_err("the refusal survives");
        assert_eq!(*error.code(), ErrorCode::INVALID_PART);
        assert_eq!(error.message(), "the backend's own refusal");
    }

    /// **Negative — an outcome that is already there wins over a bound that has already elapsed.**
    ///
    /// The order the two are polled in decides who reports a race, and this is the only test that
    /// can tell the two orderings apart. Polling the timer first would let the bound decide a race
    /// it is not there to decide: it would report a failure for work that had in fact completed,
    /// and for `CompleteMultipartUpload` that is an upload the client is told failed and the
    /// backend finished.
    ///
    /// # Why it is driven by hand
    ///
    /// The obvious form — a zero deadline against a continuation that is `Ready` immediately —
    /// **cannot fail**, and it was written that way first. `futures_timer::Delay` answers `Pending`
    /// on its first poll whatever its duration, because that poll is where it arms; so the two are
    /// never ready in the same poll and the reversed order stays green. Reaching the race needs the
    /// state the implementation is actually in when it happens: the timer armed and elapsed, *then*
    /// the outcome arriving. One poll to arm, a real wait past the bound, the outcome switched on,
    /// and a second poll in which both are ready.
    #[test]
    fn an_outcome_already_in_hand_outranks_a_bound_that_has_already_elapsed() {
        // A channel rather than an atomic flag, and not for taste: `check_config_load_once.sh` pins
        // the one hot-configuration read by grepping this whole source tree — test code and comments
        // included — for the `load` call that performs it. An `AtomicBool` read in a test adds a line
        // to that ledger, and a security ledger carrying test noise stops being read.
        let (arrived, outcome) = std::sync::mpsc::channel::<u8>();
        let work: BoxFuture<'static, Result<u8, HandlerError>> = Box::pin(poll_fn(move |_context| match outcome.try_recv() {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(_) => Poll::Pending,
        }));

        let mut bounded = bound(work, Duration::from_millis(10));
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        assert!(
            bounded.as_mut().poll(&mut context).is_pending(),
            "the bound answered before it had armed anything"
        );

        std::thread::sleep(Duration::from_millis(60));
        arrived.send(9).expect("the continuation still holds its receiver");

        match bounded.as_mut().poll(&mut context) {
            Poll::Ready(reported) => {
                assert_eq!(reported.ok(), Some(9), "an elapsed bound reported a failure for work that had completed")
            }
            Poll::Pending => panic!("neither the outcome nor the elapsed bound was reported"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod lifted_deadline_tests {
    use super::*;

    /// Negative — only the lifted length arms nothing; any finite deadline, however long, still
    /// arms its timer.
    #[test]
    fn only_a_lifted_deadline_arms_nothing() {
        assert!(armed(crate::NO_DEADLINE).is_none());
        assert!(armed(Duration::from_millis(1)).is_some());
        assert!(armed(Duration::from_secs(u64::MAX)).is_some());
    }

    /// Negative — a lifted commit-progress bound hands the backend's continuation back untouched,
    /// so nothing is ever raced against it; a bounded one wraps it.
    #[test]
    fn a_lifted_commit_progress_bound_wraps_nothing() {
        fn address<T>(work: &BoxFuture<'static, Result<T, HandlerError>>) -> *const () {
            core::ptr::from_ref::<dyn Future<Output = Result<T, HandlerError>> + Send>(&**work).cast::<()>()
        }
        let work: BoxFuture<'static, Result<u8, HandlerError>> = Box::pin(async { Ok(1) });
        let before = address(&work);
        assert_eq!(address(&commit_with_progress_deadline(work, crate::NO_DEADLINE)), before);
        let work: BoxFuture<'static, Result<u8, HandlerError>> = Box::pin(async { Ok(1) });
        let before = address(&work);
        assert_ne!(address(&commit_with_progress_deadline(work, Duration::from_secs(60))), before);
    }
}
