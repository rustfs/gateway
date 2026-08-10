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

//! Deterministic accept-to-header deadline synchronization for connection tests.
//!
//! Responsible for: observing real pending polls from both transport and Hyper header timers.
//! NOT responsible for: production metrics, public test hooks or timeout policy.
//! Upstream: the private connection driver. Downstream: `a-srv-0010` only.

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::rt::{Sleep as HyperSleep, Timer};
use hyper_util::rt::TokioTimer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tower::service_fn;

use super::{RunningServer, Server, ServerConfig};
use crate::io::HeaderPendingObserver;

#[derive(Clone)]
pub(super) struct PendingSignal {
    state: Arc<PendingState>,
}

struct PendingState {
    observed: AtomicBool,
    notify: Notify,
}

impl PendingSignal {
    fn new() -> Self {
        Self {
            state: Arc::new(PendingState {
                observed: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    fn observe(&self) {
        if !self.state.observed.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_waiters();
        }
    }

    async fn wait(&self) {
        while !self.state.observed.load(Ordering::Acquire) {
            self.state.notify.notified().await;
        }
    }
}

#[derive(Clone)]
pub(super) struct DeadlineArmObserver {
    target_accepted: usize,
    progress: PendingSignal,
    hyper: PendingSignal,
}

impl DeadlineArmObserver {
    fn new(target_accepted: usize) -> Self {
        Self {
            target_accepted,
            progress: PendingSignal::new(),
            hyper: PendingSignal::new(),
        }
    }

    pub(super) const fn target_accepted(&self) -> usize {
        self.target_accepted
    }

    pub(super) fn progress_callback(&self) -> HeaderPendingObserver {
        let signal = self.progress.clone();
        Arc::new(move || signal.observe())
    }

    pub(super) fn hyper_pending(&self) -> PendingSignal {
        self.hyper.clone()
    }

    async fn wait_until_armed(&self) {
        tokio::join!(self.progress.wait(), self.hyper.wait());
    }
}

pub(super) struct ObservedTimer {
    inner: TokioTimer,
    pending: PendingSignal,
}

impl ObservedTimer {
    pub(super) fn new(pending: PendingSignal) -> Self {
        Self {
            inner: TokioTimer::new(),
            pending,
        }
    }

    fn observed(&self, inner: Pin<Box<dyn HyperSleep>>) -> Pin<Box<dyn HyperSleep>> {
        Box::pin(ObservedSleep {
            inner,
            pending: self.pending.clone(),
            observed: false,
        })
    }
}

impl Timer for ObservedTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn HyperSleep>> {
        self.observed(self.inner.sleep(duration))
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn HyperSleep>> {
        self.observed(self.inner.sleep_until(deadline))
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn HyperSleep>>, deadline: Instant) {
        if let Some(mut observed) = sleep.as_mut().downcast_mut_pin::<ObservedSleep>() {
            self.inner.reset(&mut observed.inner, deadline);
            observed.observed = false;
        } else {
            *sleep = self.sleep_until(deadline);
        }
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

struct ObservedSleep {
    inner: Pin<Box<dyn HyperSleep>>,
    pending: PendingSignal,
    observed: bool,
}

impl Future for ObservedSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let poll = self.inner.as_mut().poll(context);
        if poll.is_pending() && !self.observed {
            self.observed = true;
            self.pending.observe();
        }
        poll
    }
}

impl HyperSleep for ObservedSleep {}

fn rss_bytes() -> Option<usize> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kibibytes = String::from_utf8(output.stdout).ok()?.trim().parse::<usize>().ok()?;
    kibibytes.checked_mul(1024)
}

#[tokio::test(start_paused = true)]
async fn a_srv_0010_half_header_is_closed_after_header_timeout() {
    const CHILD_MARKER: &str = "RUSTFS_GATEWAY_SERVER_RSS_CHILD";
    const TEST_NAME: &str = "conn::deadline_test::a_srv_0010_half_header_is_closed_after_header_timeout";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let status = Command::new(std::env::current_exe().expect("test executable path is available"))
            .args(["--exact", TEST_NAME])
            .env(CHILD_MARKER, "1")
            .status()
            .expect("isolated RSS test starts");
        assert!(status.success(), "isolated RSS test failed");
        return;
    }

    let mut config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_millis(100),
        keep_alive_idle: Duration::from_millis(250),
        ..ServerConfig::default()
    };
    config.max_connections = 1;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let service_entered = Arc::clone(&entered);
    let service_release = Arc::clone(&release);
    let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
        let entered = Arc::clone(&service_entered);
        let release = Arc::clone(&service_release);
        async move {
            entered.notify_one();
            release.notified().await;
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }
    });
    let observer = DeadlineArmObserver::new(2);
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = Server::new(config, service)
        .observe_deadline_arm(observer.clone())
        .serve()
        .expect("server starts");

    let mut first = TcpStream::connect(local_addr).await.expect("first connection succeeds");
    first
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("first request writes");
    entered.notified().await;
    assert_eq!(metrics.active_connections(), 1, "the blocked handler owns the admission permit");
    let before_rss = rss_bytes();

    let mut stream = TcpStream::connect(local_addr).await.expect("second connection succeeds");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost:")
        .await
        .expect("partial header writes");
    assert_eq!(metrics.accepted_connections(), 1, "the partial header is queued before accept");
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), observer.wait_until_armed())
        .await
        .expect("both header deadlines are polled pending before time advances");
    drop(first);

    let started = crate::io::test_deadline_now();
    tokio::time::advance(Duration::from_millis(101)).await;
    let mut byte = [0_u8; 1];
    assert_eq!(stream.read(&mut byte).await.expect("close is observable"), 0);
    assert!(
        started.elapsed() < Duration::from_millis(150),
        "the header deadline, rather than the longer keep-alive timer, closed the socket"
    );
    if let (Some(before), Some(after)) = (before_rss, rss_bytes()) {
        assert!(
            after.saturating_sub(before) < 1024 * 1024,
            "one partial header grew RSS by at least 1 MiB"
        );
    }
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}
