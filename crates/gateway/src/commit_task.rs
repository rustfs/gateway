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

//! Detached ownership for work whose response head has already committed.
//!
//! Responsible for: spawning committed work independently of its response body, inside the
//! `tracing` span that was current when the service started it; delivering the terminal document
//! to that body's one-shot receiver; and counting every such task in the service's
//! [`DetachedWork`], so a host can wait for them before it stops its runtime.
//! NOT responsible for: polling a payload stream, rendering terminal documents, or deciding when
//! response-head finalization permits the task to start.
//! Upstream: `crate::commit`. Downstream: the Tokio runtime captured by the facade call, and the
//! host holding [`DetachedWork`].

use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::ErrorCode;
use tokio::runtime::Handle;
use tokio::sync::{oneshot, watch};
use tracing::Instrument;

/// The work a service started that outlives the response head it answered with.
///
/// A committed response (`Resp::commit`) finishes its operation after the head has gone out, in a
/// task of its own. The connection that carried the head no longer tells a host whether that
/// operation finished, so a graceful shutdown that waits for connections can stop the runtime
/// between the operation's first write and its last. This handle closes that gap: every clone of
/// one service's handle counts the same tasks, from the moment one is spawned until it finishes,
/// panics or is dropped, and [`Self::drained`] resolves once none is running.
///
/// Obtained from `S3Service::detached_work`. A host drains it after its listener has stopped
/// accepting and its connections have closed, and before it drops the runtime.
#[derive(Clone, Debug)]
pub struct DetachedWork {
    running: Arc<watch::Sender<usize>>,
}

impl Default for DetachedWork {
    fn default() -> Self {
        Self {
            running: Arc::new(watch::channel(0).0),
        }
    }
}

impl DetachedWork {
    /// How many detached tasks are running now.
    #[must_use]
    pub fn running(&self) -> usize {
        *self.running.borrow()
    }

    /// Resolves once no detached task is running; at once when none is.
    ///
    /// A task started while this is pending is waited for too. It never resolves early: a task is
    /// counted before it is spawned, and uncounted only when its future is dropped.
    pub async fn drained(&self) {
        let mut running = self.running.subscribe();
        // `wait_for` fails only once every sender is gone, and `self` holds one.
        let _ = running.wait_for(|count| *count == 0).await;
    }

    /// Starts `response`'s deferred work, if it has any, counted here.
    #[must_use]
    pub(crate) fn start(&self, response: &mut Response<Body>, complete: Box<dyn FnOnce(Option<ErrorCode>) + Send>) -> bool {
        crate::commit::start_counted(response, self, complete)
    }

    /// Counts one task until the returned guard is dropped.
    fn enter(&self) -> Running {
        self.running.send_modify(|count| *count += 1);
        Running(Arc::clone(&self.running))
    }
}

/// One counted task. Dropped with the task's future: on completion, on a panic, and when the
/// runtime drops the task unfinished.
struct Running(Arc<watch::Sender<usize>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count = count.saturating_sub(1));
    }
}

/// The terminal document and observer verdict produced by committed work.
pub(crate) struct CommitTaskResult {
    document: Bytes,
    error: Option<ErrorCode>,
}

impl CommitTaskResult {
    /// Builds a successful terminal result.
    pub(crate) fn answer(document: Bytes) -> Self {
        Self { document, error: None }
    }

    /// Builds a late refusal whose code must reach the observer.
    pub(crate) fn refusal(document: Bytes, error: Option<ErrorCode>) -> Self {
        Self { document, error }
    }
}

/// Work held inert until every response-head mutation has finished.
pub(crate) struct PendingCommit {
    runtime: Handle,
    sender: oneshot::Sender<Bytes>,
    task: BoxFuture<'static, CommitTaskResult>,
}

impl PendingCommit {
    /// Captures the runtime, result channel, and still-unpolled work.
    pub(crate) fn new(runtime: Handle, sender: oneshot::Sender<Bytes>, task: BoxFuture<'static, CommitTaskResult>) -> Self {
        Self { runtime, sender, task }
    }

    /// Starts work independently of the response body's ownership, counted in `work` and inside
    /// the span current here — the request's, when the host instruments the service call.
    pub(crate) fn start(self, work: &DetachedWork, complete: Box<dyn FnOnce(Option<ErrorCode>) + Send>) {
        let running = work.enter();
        let task = async move {
            let _running = running;
            let result = self.task.await;
            complete(result.error);
            let _ = self.sender.send(result.document);
        };
        self.runtime.spawn(task.instrument(tracing::Span::current()));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use http::{HeaderMap, StatusCode};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};
    use tracing_core::span::Current;

    use super::*;
    use crate::commit::pending_response;

    fn pending(task: BoxFuture<'static, CommitTaskResult>, runtime: Handle) -> Response<Body> {
        pending_response(HeaderMap::new(), StatusCode::OK, runtime, task, Bytes::from_static(b"<Canceled/>"))
            .expect("the pending response has consistent capabilities")
    }

    fn answered() -> CommitTaskResult {
        CommitTaskResult::answer(Bytes::from_static(b"<Done/>"))
    }

    async fn drained_within(work: &DetachedWork, wait: Duration) -> bool {
        tokio::time::timeout(wait, work.drained()).await.is_ok()
    }

    /// Positive — nothing started is nothing to wait for.
    #[tokio::test]
    async fn an_idle_service_is_drained_at_once() {
        let work = DetachedWork::default();
        assert_eq!(work.running(), 0);
        assert!(drained_within(&work, Duration::from_millis(50)).await);
    }

    /// Negative — a continuation whose response body is already gone is still counted, and the
    /// drain waits for its last write rather than resolving between its first and its last.
    #[tokio::test]
    async fn the_drain_waits_for_a_continuation_that_outlives_its_response() {
        let work = DetachedWork::default();
        let (release, wait) = oneshot::channel::<()>();
        let written = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&written);
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async move {
            log.lock().expect("never poisoned").push("first write");
            let _ = wait.await;
            log.lock().expect("never poisoned").push("last write");
            answered()
        });
        let mut response = pending(task, Handle::current());
        assert!(work.start(&mut response, Box::new(|_| {})));
        drop(response);
        tokio::task::yield_now().await;
        assert_eq!(work.running(), 1);
        assert!(
            !drained_within(&work.clone(), Duration::from_millis(50)).await,
            "the drain resolved while the continuation was between its writes"
        );
        release.send(()).expect("the continuation still owns its receiver");
        assert!(drained_within(&work, Duration::from_secs(5)).await);
        assert_eq!(work.running(), 0);
        assert_eq!(*written.lock().expect("never poisoned"), ["first write", "last write"]);
    }

    /// Negative — a continuation that panics is uncounted; a drain after it does not hang.
    #[tokio::test]
    async fn a_panicking_continuation_is_uncounted() {
        let work = DetachedWork::default();
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async { panic!("backend continuation panicked") });
        let mut response = pending(task, Handle::current());
        assert!(work.start(&mut response, Box::new(|_| {})));
        assert!(drained_within(&work, Duration::from_secs(5)).await);
        assert_eq!(work.running(), 0);
    }

    /// Negative — a continuation its runtime drops unfinished is uncounted too: the count follows
    /// the task's future, not its completion.
    #[test]
    fn a_continuation_dropped_with_its_runtime_is_uncounted() {
        let work = DetachedWork::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async { core::future::pending().await });
        let mut response = runtime.block_on(async { pending(task, Handle::current()) });
        assert!(work.start(&mut response, Box::new(|_| {})));
        assert_eq!(work.running(), 1);
        runtime.shutdown_timeout(Duration::from_millis(100));
        assert_eq!(work.running(), 0);
    }

    /// Negative — every clone observes one count, so the host's handle sees what the service
    /// started through its own clone.
    #[tokio::test]
    async fn every_clone_observes_one_count() {
        let work = DetachedWork::default();
        let host = work.clone();
        let (release, wait) = oneshot::channel::<()>();
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async move {
            let _ = wait.await;
            answered()
        });
        let mut response = pending(task, Handle::current());
        assert!(work.start(&mut response, Box::new(|_| {})));
        assert_eq!(host.running(), 1);
        release.send(()).expect("the continuation still owns its receiver");
        assert!(drained_within(&host, Duration::from_secs(5)).await);
    }

    /// Records span entries and exits, and one marker the continuation writes, in one order.
    #[derive(Default)]
    struct SpanLog {
        next: AtomicU64,
        metadata: Mutex<HashMap<u64, &'static Metadata<'static>>>,
        entered: Mutex<Vec<Id>>,
        log: Mutex<Vec<String>>,
    }

    impl Subscriber for SpanLog {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, attributes: &Attributes<'_>) -> Id {
            let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
            self.metadata
                .lock()
                .expect("never poisoned")
                .insert(id, attributes.metadata());
            Id::from_u64(id)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, _event: &Event<'_>) {}

        fn enter(&self, span: &Id) {
            self.entered.lock().expect("never poisoned").push(span.clone());
            self.log
                .lock()
                .expect("never poisoned")
                .push(format!("enter {}", span.into_u64()));
        }

        fn exit(&self, span: &Id) {
            let mut entered = self.entered.lock().expect("never poisoned");
            if let Some(position) = entered.iter().rposition(|id| id == span) {
                entered.remove(position);
            }
            self.log
                .lock()
                .expect("never poisoned")
                .push(format!("exit {}", span.into_u64()));
        }

        fn current_span(&self) -> Current {
            let entered = self.entered.lock().expect("never poisoned");
            match entered.last() {
                Some(id) => match self.metadata.lock().expect("never poisoned").get(&id.into_u64()) {
                    Some(metadata) => Current::new(id.clone(), metadata),
                    None => Current::none(),
                },
                None => Current::none(),
            }
        }
    }

    /// Negative — the continuation runs inside the span that was current when the service started
    /// it, although it runs after that span was exited and on a task of its own.
    #[tokio::test]
    async fn a_continuation_runs_in_the_span_current_when_it_started() {
        let subscriber = Arc::new(SpanLog::default());
        let _default = tracing::subscriber::set_default(Arc::clone(&subscriber));
        let work = DetachedWork::default();
        let marker = Arc::clone(&subscriber);
        let task: BoxFuture<'static, CommitTaskResult> = Box::pin(async move {
            marker.log.lock().expect("never poisoned").push("continuation".to_owned());
            answered()
        });
        let mut response = pending(task, Handle::current());
        let request = tracing::info_span!("request");
        let id = request.id().expect("the recording subscriber assigns ids").into_u64();
        {
            let _entered = request.enter();
            assert!(work.start(&mut response, Box::new(|_| {})));
        }
        assert!(drained_within(&work, Duration::from_secs(5)).await);
        let log = subscriber.log.lock().expect("never poisoned").clone();
        let at = log
            .iter()
            .position(|entry| entry == "continuation")
            .expect("the continuation ran");
        assert_eq!(log.get(at.wrapping_sub(1)), Some(&format!("enter {id}")), "{log:?}");
        assert_eq!(log.get(at + 1), Some(&format!("exit {id}")), "{log:?}");
    }
}
