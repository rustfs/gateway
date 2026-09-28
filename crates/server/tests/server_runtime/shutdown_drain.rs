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

//! Responsible for: proving a response counts as drained at shutdown only once its bytes reached
//! the socket, not when Hyper took its final body frame (rustfs/gateway#657).
//! NOT responsible for: the healthy full-body drain (`drain_fixture.rs`) or admission.
//! Upstream: the server runtime integration suite. Downstream: `ShutdownReport` accounting.

use std::pin::Pin;
use std::task::{Context, Poll};

use http_body::{Body, Frame, SizeHint};
use tokio::net::TcpSocket;
use tokio::sync::oneshot;

use super::*;

/// Large enough that neither socket buffer can hold it, so the write blocks while the peer is
/// not reading.
const BLOCKING_BODY_LEN: usize = 64 * 1024 * 1024;

/// A one-frame body that reports the moment its final frame has been handed to the transport.
struct FinalFrameSignal {
    frame: Option<Bytes>,
    taken: Option<oneshot::Sender<()>>,
}

impl Body for FinalFrameSignal {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        let frame = this.frame.take().map(|bytes| Ok(Frame::data(bytes)));
        if let Some(taken) = this.taken.take() {
            let _ = taken.send(());
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.frame.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.frame.as_ref().map_or(0, |bytes| bytes.len() as u64))
    }
}

/// A server whose only response is one `BLOCKING_BODY_LEN` frame, and a client that has sent
/// its request and reads nothing until told to. Returns once Hyper has taken the final frame.
async fn final_frame_taken() -> (RunningServer, TcpStream) {
    let (taken, taken_receiver) = oneshot::channel();
    let taken = Arc::new(std::sync::Mutex::new(Some(taken)));
    let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
        let taken = taken.lock().expect("fixture lock").take();
        async move {
            Ok::<_, Infallible>(Response::new(FinalFrameSignal {
                frame: Some(Bytes::from(vec![b'x'; BLOCKING_BODY_LEN])),
                taken,
            }))
        }
    });
    let config = ServerConfig {
        so_sndbuf: Some(16 * 1024),
        write_progress_timeout: Duration::from_secs(60),
        keep_alive_idle: Duration::from_secs(60),
        ..plaintext_config()
    };
    let running = Server::new(config, service).serve().expect("server starts");
    let socket = TcpSocket::new_v4().expect("client socket");
    socket.set_recv_buffer_size(4 * 1024).expect("small client receive buffer");
    let mut client = socket.connect(running.local_addr).await.expect("client connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    tokio::time::timeout(Duration::from_secs(10), taken_receiver)
        .await
        .expect("Hyper takes the final frame")
        .expect("the body reports its final frame");
    (running, client)
}

/// Waits until the listener refuses new connections: the server has left its accept loop and
/// started shutting down, on this current-thread runtime in the same poll.
async fn shutdown_has_begun(addr: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while TcpStream::connect(addr).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the listener closes once shutdown begins");
}

/// Negative — the counter-example. Hyper has taken the last frame, but the peer reads nothing, so
/// the write is still blocked when the grace expires. That response was not drained; it was cut
/// off, and the report must say so.
#[tokio::test]
async fn a_final_frame_blocked_on_the_socket_is_aborted_at_shutdown_grace() {
    let (running, client) = final_frame_taken().await;
    let report = running.shutdown.trigger(Duration::from_millis(100)).await;
    assert_eq!(report, ShutdownReport { drained: 0, aborted: 1 });
    drop(client);
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive — the same response, read by the peer after shutdown has begun, reaches the socket
/// within the grace and is counted drained.
#[tokio::test]
async fn a_final_frame_written_after_shutdown_began_is_drained() {
    let (running, mut client) = final_frame_taken().await;
    let addr = running.local_addr;
    let shutdown = tokio::spawn(running.shutdown.trigger(Duration::from_secs(20)));
    shutdown_has_begun(addr).await;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("the response reads");
    assert!(response.len() > BLOCKING_BODY_LEN, "the peer received the whole response");
    let report = shutdown.await.expect("shutdown joins");
    assert_eq!(report, ShutdownReport { drained: 1, aborted: 0 });
    assert!(running.task.await.expect("server task joins").is_ok());
}
