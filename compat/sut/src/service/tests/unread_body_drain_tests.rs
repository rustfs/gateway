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

//! The unread-body drain as the RustFS-profile launcher runs it (rustfs/gateway#1120).
//!
//! Responsible for: an HTTP/1.1 upload refused before its body is read — a `PutObject` into another
//! identity's bucket, denied by policy — reaching the assembly through its tower entry with its body
//! still arriving: the answer closes the connection, the rest of the body is read and discarded
//! behind it, and nothing is stored; and the controls, an upload the backend reads to its end and
//! an HTTP/2 stream, which announce no close.
//! NOT responsible for: the drain's rules or a real socket (`rustfs-gateway`'s
//! `src/unread_body_tests.rs` and `tests/unread_body_drain.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour: `EarlyResponseBodyService`, `rustfs/src/server/http.rs:706-1010`, wrapped around
//! the legacy stack at `:2025` with `RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT` (default 300 s) as its
//! idle bound (rustfs/rustfs#7019).

use super::*;

use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};

use http_body::Frame;
use tokio::sync::mpsc;

/// A request body whose octets arrive when the test sends them, counting what was read.
struct Owed {
    receiver: mpsc::UnboundedReceiver<Bytes>,
    read: Arc<AtomicU64>,
    dropped: Arc<AtomicBool>,
}

impl http_body::Body for Owed {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::convert::Infallible>>> {
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(bytes)) => {
                self.read.fetch_add(bytes.len() as u64, Ordering::Relaxed);
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
    read: Arc<AtomicU64>,
    dropped: Arc<AtomicBool>,
}

/// `request`, signed as it is, with its body replaced by one the test feeds.
fn owed(request: http::Request<Bytes>, version: http::Version) -> (http::Request<Owed>, Probe) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let read = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let (mut parts, _) = request.into_parts();
    parts.version = version;
    let body = Owed {
        receiver,
        read: Arc::clone(&read),
        dropped: Arc::clone(&dropped),
    };
    (http::Request::from_parts(parts, body), Probe { sender, read, dropped })
}

fn closes<T>(response: &http::Response<T>) -> bool {
    response
        .headers()
        .get(http::header::CONNECTION)
        .is_some_and(|value| value == "close")
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

const BODY: &[u8] = b"an upload the backend never reads";

/// Positive, and the data-layer half — an upload the policy denies is refused before its body is
/// read; the answer closes the connection and the rest of the body is read behind it; nothing is
/// stored.
#[tokio::test]
async fn an_upload_refused_before_its_body_is_drained_behind_a_closing_answer() {
    let root = TestRoot::new();
    let (_backend, mut service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/drained", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let (request, probe) = owed(
        as_alt(http::Method::PUT, "/drained/key", Bytes::from_static(BODY)),
        http::Version::HTTP_11,
    );
    let response = tower::Service::call(&mut service, request).await.expect("infallible");
    assert_eq!(response.status(), 403);
    assert!(closes(&response), "the refusal did not announce the close");
    assert!(!probe.dropped.load(Ordering::Acquire), "the body was released instead of drained");
    probe.sender.send(Bytes::from_static(BODY)).expect("the drain still reads");
    drop(probe.sender);
    until_dropped(&probe.dropped).await;
    assert_eq!(probe.read.load(Ordering::Relaxed), BODY.len() as u64);
    let stored = exchange(&service, as_main(http::Method::GET, "/drained/key", Bytes::new())).await;
    assert_eq!(stored.status(), 404, "{}", body_of(&stored));
}

/// Negative — an upload the backend reads to its end owes nothing after its answer: stored, and no
/// close is announced.
#[tokio::test]
async fn n_an_upload_read_to_its_end_announces_no_close() {
    let root = TestRoot::new();
    let (_backend, mut service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/drained", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let (request, probe) = owed(
        as_main(http::Method::PUT, "/drained/key", Bytes::from_static(BODY)),
        http::Version::HTTP_11,
    );
    probe.sender.send(Bytes::from_static(BODY)).expect("the body is open");
    drop(probe.sender);
    let response = tower::Service::call(&mut service, request).await.expect("infallible");
    assert_eq!(response.status(), 200);
    assert!(!closes(&response), "a finished upload closed the connection");
    let stored = exchange(&service, as_main(http::Method::GET, "/drained/key", Bytes::new())).await;
    assert_eq!(stored.body().as_ref(), BODY);
}

/// Negative — an HTTP/2 stream keeps its own cancellation: the refused upload's body is released
/// with the answer and no `Connection` header is written.
#[tokio::test]
async fn n_an_http2_upload_is_released_not_drained() {
    let root = TestRoot::new();
    let (_backend, mut service) = assembled(&two_identity_options(&root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/drained", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let (request, probe) = owed(as_alt(http::Method::PUT, "/drained/key", Bytes::from_static(BODY)), http::Version::HTTP_2);
    let response = tower::Service::call(&mut service, request).await.expect("infallible");
    assert_eq!(response.status(), 403);
    assert!(response.headers().get(http::header::CONNECTION).is_none());
    assert!(probe.dropped.load(Ordering::Acquire), "an HTTP/2 body was kept");
    assert_eq!(probe.read.load(Ordering::Relaxed), 0);
}
