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

//! Responsible for: the global connection limit pausing accept until a permit is released, measured
//! against the same queued socket before and after release.
//! NOT responsible for: per-IP limits, in-flight request limits, or production deadlines.
//! Upstream: the server runtime integration suite. Downstream: `Server` admission and the Tokio clock.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{RunningServer, echo_server, frozen_clock, plaintext_config};

/// How long the queued socket must stay unaccepted while the only permit is held.
const REFUSAL_WINDOW: Duration = Duration::from_millis(50);

#[tokio::test]
async fn a_srv_0014_global_limit_pauses_accept_before_the_next_socket() {
    global_limit_pauses_accept(Duration::ZERO).await;
}

/// #886: a host stall longer than the 100ms header deadline while the first socket holds the only
/// permit. The fixture must not let that stall expire the first socket and hand its permit on.
#[tokio::test]
async fn a_srv_0014_global_limit_survives_a_scheduling_stall_before_the_refusal_window() {
    global_limit_pauses_accept(Duration::from_millis(250)).await;
}

async fn global_limit_pauses_accept(stall: Duration) {
    let mut config = plaintext_config();
    config.max_connections = 1;
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(config);
    // The first socket deliberately sends no header, so a stall past the 100ms header deadline
    // would legitimately expire it and hand its permit to the queued socket. Fixture deadlines stay
    // frozen from its connect until the refusal has been observed; the refusal window itself is
    // measured in wall time and polled throughout.
    let (first, mut second, refused_for) = frozen_clock::with_header_clock_frozen(async {
        let first = TcpStream::connect(local_addr).await.expect("first connection succeeds");
        while metrics.active_connections() != 1 {
            tokio::task::yield_now().await;
        }
        // Blocks the whole current-thread runtime, as a descheduled test process would.
        std::thread::sleep(stall);
        let mut second = TcpStream::connect(local_addr)
            .await
            .expect("the kernel completes the second TCP handshake");
        second
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("the queued connection accepts request bytes");
        let window = std::time::Instant::now();
        while window.elapsed() < REFUSAL_WINDOW {
            assert_eq!(metrics.accepted_connections(), 1, "the listener must wait for a permit before accept");
            tokio::task::yield_now().await;
        }
        let refused_for = window.elapsed();
        assert_eq!(metrics.active_connections(), 1, "the first socket still owns the only permit");
        assert_eq!(metrics.accepted_connections(), 1, "the second socket was not accepted then reset");
        let mut probe = [0_u8; 1];
        let error = second
            .try_read(&mut probe)
            .expect_err("the queued socket has neither a response nor EOF/RST");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        (first, second, refused_for)
    })
    .await;
    assert!(refused_for >= REFUSAL_WINDOW, "the refusal was observed for only {refused_for:?}");

    drop(first);
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.accepted_connections() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("releasing the permit lets the accept loop take the queued socket");
    let mut response = Vec::new();
    second
        .read_to_end(&mut response)
        .await
        .expect("the same queued socket receives a response");
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let _ = shutdown.trigger(Duration::from_millis(100)).await;
    assert!(task.await.expect("server task joins").is_ok());
}
