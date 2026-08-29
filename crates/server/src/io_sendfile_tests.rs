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

//! Real-socket controls for the sendfile writable-readiness handoff.
//!
//! Responsible for: proving both stale-ready clearing and preservation of a newly writable level.
//! NOT responsible for: sendfile progress, retry batching or write-timeout policy.
//! Upstream: `ProgressIo<TcpStream>`. Downstream: the operating system's socket readiness state.

use std::io::{self, Write};
use std::net::TcpStream as StdTcpStream;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::{Context, Poll};
use std::time::Duration;

use super::{ProgressIo, deadline_after, send_file_level_after_poll, writable_repoll_needs_retry};

fn progress_io(socket: tokio::net::TcpStream) -> ProgressIo<tokio::net::TcpStream> {
    ProgressIo::new(
        socket,
        Arc::new(AtomicUsize::new(1)),
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::from_secs(60)),
        Duration::from_secs(60),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
}

fn fill_to_backpressure(socket: &tokio::net::TcpStream) -> StdTcpStream {
    let mut duplicate = StdTcpStream::from(socket.as_fd().try_clone_to_owned().expect("test duplicates the socket"));
    duplicate.set_nonblocking(true).expect("test duplicate is nonblocking");
    write_until_backpressure(&mut duplicate);
    duplicate
}

fn write_until_backpressure(duplicate: &mut StdTcpStream) {
    let block = [0_u8; 64 * 1024];
    let mut filled = 0_usize;
    loop {
        match duplicate.write(&block) {
            Ok(0) => panic!("test socket made zero progress before backpressure"),
            Ok(written) => {
                filled += written;
                assert!(filled <= 64 * 1024 * 1024, "test socket reaches backpressure inside its safety bound");
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) => panic!("test socket fill failed: {error}"),
        }
    }
}

async fn socket_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("test listener binds");
    let peer = tokio::net::TcpStream::connect(listener.local_addr().expect("test listener has an address"))
        .await
        .expect("test peer connects");
    let (socket, _) = listener.accept().await.expect("test listener accepts");
    socket.writable().await.expect("socket starts writable");
    (socket, peer)
}

#[test]
fn writable_readiness_seen_after_would_block_requires_an_immediate_retry() {
    assert!(writable_repoll_needs_retry(Poll::Ready(Ok(()))).expect("ready state is valid"));
    assert!(!writable_repoll_needs_retry::<()>(Poll::Pending).expect("pending state is valid"));
    let error =
        writable_repoll_needs_retry::<()>(Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture readiness error"))))
            .expect_err("readiness errors remain errors");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn a_failed_level_probe_never_overrides_transfer_progress() {
    assert!(!send_file_level_after_poll(Err(nix::errno::Errno::EINTR), true));
    assert!(!send_file_level_after_poll(Err(nix::errno::Errno::EBADF), true));
    assert!(send_file_level_after_poll(Ok(1), true));
}

#[tokio::test]
async fn sendfile_would_block_clears_stale_writable_readiness() {
    let (socket, peer) = socket_pair().await;
    let mut duplicate = fill_to_backpressure(&socket);
    let mut io = progress_io(socket);

    for _ in 0..32 {
        io.record_send_file_would_block();
        if !io.send_file_retry_ready {
            break;
        }
        write_until_backpressure(&mut duplicate);
        tokio::task::yield_now().await;
    }
    assert!(!io.send_file_retry_ready, "a full socket has no immediate retry level");
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut io).poll_send_file_ready(&mut context).is_pending(),
        "stale writable readiness must not trigger an immediate retry"
    );
    drop(peer);
}

#[tokio::test]
async fn sendfile_would_block_preserves_a_new_writable_level_while_clearing_stale_readiness() {
    let (socket, peer) = socket_pair().await;
    let mut duplicate = fill_to_backpressure(&socket);
    peer.readable().await.expect("backpressured bytes become readable");
    let mut block = [0_u8; 64 * 1024];
    loop {
        match peer.try_read(&mut block) {
            Ok(0) => panic!("test peer remains connected"),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("test peer drain failed: {error}"),
        }
    }
    let mut io = progress_io(socket);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match duplicate.write(b"x") {
                Ok(0) => panic!("test socket remains connected"),
                Ok(_) => {
                    io.record_send_file_would_block();
                    if io.send_file_retry_ready {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("test writable confirmation failed: {error}"),
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("draining the peer makes the socket writable before readiness clear");
    assert!(io.send_file_retry_ready, "the post-clear level check preserves a new writable transition");
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut io).poll_send_file_ready(&mut context).is_ready(),
        "a writable level observed after clear retries without waiting for another edge"
    );
}
