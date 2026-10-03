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

//! The unread-body drain's unit suite, split out of its module for size.
//!
//! Responsible for: the scenarios of RustFS's own `EarlyResponseBodyService` tests
//! (`rustfs/src/server/http.rs:2951-3185`), restated over [`retain`] and [`Retention::settle`] with a
//! body whose octets a test hands in one by one: a body read to its end, a body left unread on
//! HTTP/1.1, a body the service wrapped in its own transform before leaving it, an HTTP/2 stream, an
//! idle peer, and the setting switched off.
//! NOT responsible for: a real socket (`tests/unread_body_drain.rs` hosts the service on Hyper).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::mpsc;

/// A request body whose octets arrive when the test sends them, counting what was read.
struct Owed {
    receiver: mpsc::UnboundedReceiver<Bytes>,
    read: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl Body for Owed {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(bytes)) => {
                self.read.fetch_add(bytes.len(), Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }
}

impl Drop for Owed {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

struct Probe {
    sender: mpsc::UnboundedSender<Bytes>,
    read: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

fn owed(version: Version) -> (Request<Owed>, Probe) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let read = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let body = Owed {
        receiver,
        read: Arc::clone(&read),
        dropped: Arc::clone(&dropped),
    };
    let request = Request::builder()
        .version(version)
        .method(http::Method::PUT)
        .uri("/bucket/key")
        .body(body)
        .expect("a valid request");
    (request, Probe { sender, read, dropped })
}

fn drain() -> Option<UnreadBodyDrain> {
    Some(UnreadBodyDrain::with_idle_timeout(Duration::from_secs(5)))
}

fn closes(response: &Response<()>) -> bool {
    response.headers().get(CONNECTION).is_some_and(|value| value == "close")
}

async fn until_dropped(dropped: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the drain let the body go");
}

/// Negative — a body the service read to its end owes nothing: no drain, no close.
#[tokio::test]
async fn n_a_body_read_to_its_end_is_left_alone() {
    let (request, probe) = owed(Version::HTTP_11);
    probe.sender.send(Bytes::from_static(b"payload")).expect("the body is open");
    let (request, retention) = retain(request, drain());
    drop(probe.sender);
    {
        let mut body = std::pin::pin!(request.into_body());
        while poll_fn(|context| body.as_mut().poll_frame(context)).await.is_some() {}
    }
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(!closes(&response), "a finished body closed the connection");
    assert_eq!(probe.read.load(Ordering::Relaxed), 7);
    assert!(probe.dropped.load(Ordering::Acquire));
}

/// Positive — an HTTP/1.1 body the service left unread is read to its end behind the answer, which
/// closes the connection.
#[tokio::test]
async fn a_body_left_unread_on_http1_is_drained_behind_a_closing_answer() {
    let (request, probe) = owed(Version::HTTP_11);
    let (request, retention) = retain(request, drain());
    drop(request);
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(closes(&response), "the answer did not announce the close");
    assert!(!probe.dropped.load(Ordering::Acquire), "the body was released instead of drained");
    probe
        .sender
        .send(Bytes::from_static(b"payload"))
        .expect("the drain still reads");
    drop(probe.sender);
    until_dropped(&probe.dropped).await;
    assert_eq!(probe.read.load(Ordering::Relaxed), 7, "the drain did not read what the peer sent");
}

/// A transform the service wraps the body in before leaving it, counting its own polls.
struct Transform<B> {
    inner: B,
    polls: Arc<AtomicUsize>,
}

impl<B: Body + Unpin> Body for Transform<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut self.inner).poll_frame(context)
    }
}

/// Positive — the drain reads the transport's own body, below anything the service wrapped
/// around it: the service's transform is never polled again.
#[tokio::test]
async fn the_drain_reads_the_raw_body_below_the_services_transforms() {
    let (request, probe) = owed(Version::HTTP_11);
    let (request, retention) = retain(request, drain());
    let polls = Arc::new(AtomicUsize::new(0));
    drop(Transform {
        inner: Box::pin(request.into_body()),
        polls: Arc::clone(&polls),
    });
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(closes(&response));
    probe
        .sender
        .send(Bytes::from_static(b"payload"))
        .expect("the drain still reads");
    drop(probe.sender);
    until_dropped(&probe.dropped).await;
    assert_eq!(probe.read.load(Ordering::Relaxed), 7);
    assert_eq!(polls.load(Ordering::Relaxed), 0, "the drain went through the service's transform");
}

/// Negative — an HTTP/2 stream keeps its own cancellation: the body is released with the answer,
/// nothing is read, and no `Connection` header is written.
#[tokio::test]
async fn n_an_http2_body_is_released_not_drained() {
    let (request, probe) = owed(Version::HTTP_2);
    let (request, retention) = retain(request, drain());
    drop(request);
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(response.headers().get(CONNECTION).is_none());
    assert!(probe.dropped.load(Ordering::Acquire), "an HTTP/2 body was kept");
    assert!(probe.sender.send(Bytes::from_static(b"late")).is_err());
    assert_eq!(probe.read.load(Ordering::Relaxed), 0);
}

/// Negative — a peer that goes quiet is let go once the idle bound passes.
#[tokio::test(start_paused = true)]
async fn n_an_idle_peer_is_let_go_after_the_idle_bound() {
    let (request, probe) = owed(Version::HTTP_11);
    let (request, retention) = retain(request, Some(UnreadBodyDrain::with_idle_timeout(Duration::from_secs(10))));
    drop(request);
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(closes(&response));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert!(!probe.dropped.load(Ordering::Acquire), "let go before the bound");
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert!(probe.dropped.load(Ordering::Acquire), "held past the bound");
}

/// Negative — with the setting off the unread body is released with the answer and nothing
/// announces a close; this is the behaviour the setting exists to change.
#[tokio::test]
async fn n_without_the_setting_the_body_is_released() {
    let (request, probe) = owed(Version::HTTP_11);
    let (request, retention) = retain(request, None);
    drop(request);
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(!closes(&response));
    assert!(probe.dropped.load(Ordering::Acquire));
    assert!(probe.sender.send(Bytes::from_static(b"late")).is_err());
}

/// Negative — a body that had already ended on arrival is not retained, and costs no drain.
#[tokio::test]
async fn n_a_body_ended_on_arrival_is_not_retained() {
    let (request, probe) = owed(Version::HTTP_11);
    drop(probe.sender);
    let (request, retention) = retain(request, drain());
    assert!(matches!(request.body(), Retained::Through { .. }));
    drop(request);
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(!closes(&response));
    assert!(probe.dropped.load(Ordering::Acquire));
}

/// A body whose transport fails on its first read.
struct Broken;

impl Body for Broken {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))))
    }
}

/// Negative — a body whose transport failed owes nothing that could be read: not retained.
#[tokio::test]
async fn n_a_failed_body_is_not_drained() {
    let request = Request::builder().body(Broken).expect("a valid request");
    let (request, retention) = retain(request, drain());
    {
        let mut body = std::pin::pin!(request.into_body());
        assert!(
            poll_fn(|context| body.as_mut().poll_frame(context))
                .await
                .is_some_and(|frame| frame.is_err())
        );
    }
    let mut response = Response::new(());
    retention.settle(&mut response);
    assert!(!closes(&response));
}

/// The setting's spelling: a zero idle bound is no bound, as RustFS reads a zero timeout.
#[test]
fn a_zero_idle_bound_is_unbounded() {
    assert_eq!(UnreadBodyDrain::with_idle_timeout(Duration::ZERO), UnreadBodyDrain::unbounded());
    assert_eq!(UnreadBodyDrain::unbounded().idle_timeout(), None);
    assert_eq!(
        UnreadBodyDrain::with_idle_timeout(Duration::from_secs(300)).idle_timeout(),
        Some(Duration::from_secs(300))
    );
}
