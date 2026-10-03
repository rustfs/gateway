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

//! The listener keeps no finished connection task while it runs (rustfs/gateway#1208).
//!
//! Responsible for: a health-check-shaped connect/close loop against a live listener, read through
//! `ServerMetrics::retained_connection_tasks`, and the control that live connections are counted.
//! NOT responsible for: what a connection does while it is open, or shutdown accounting.
//! Upstream: `crates/server/src/conn.rs`'s accept loop. Downstream: none.

use std::time::Duration;

use rustfs_gateway_server::{RunningServer, ServerMetrics, ShutdownReport};
use tokio::net::TcpStream;

use super::{echo_server, get, plaintext_config};

/// Waits, boundedly, until `condition` holds for the listener's counters.
async fn eventually(metrics: &ServerMetrics, what: &str, condition: impl Fn(&ServerMetrics) -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition(metrics) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{what}: active {} retained {}",
            metrics.active_connections(),
            metrics.retained_connection_tasks()
        )
    });
}

/// Negative — a load balancer's health check: 64 sequential connections that each ask for one
/// response and close. Before rustfs/gateway#1208 every one of them left its finished task in the
/// listener's set until shutdown, so the count read 64 at the end of the loop.
#[tokio::test]
async fn a_closed_connection_leaves_no_task_behind_while_the_listener_runs() {
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(plaintext_config());
    for round in 1..=64 {
        let response = get(local_addr).await;
        assert!(response.starts_with(b"HTTP/1.1 200"), "round {round} is served");
        eventually(&metrics, "the closed connection releases its seat", |metrics| {
            metrics.active_connections() == 0
        })
        .await;
        // The task that just closed may still be finishing, and the one before it may be the one
        // the next accept reaps; nothing older than that may remain.
        assert!(
            metrics.retained_connection_tasks() <= 2,
            "round {round} still holds {} finished connection tasks",
            metrics.retained_connection_tasks()
        );
    }
    assert_eq!(metrics.accepted_connections(), 64);
    eventually(&metrics, "an idle listener reaps its last finished task", |metrics| {
        metrics.retained_connection_tasks() == 0
    })
    .await;
    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport::default());
    assert!(task.await.expect("server task joins").is_ok());
}

/// Negative — connections queued behind a one-connection ceiling keep the next accept ready every
/// time the loop comes back to it, so the listener never idles between them: finished tasks have to
/// be joined between accepts, not only while the listener waits. Each client reads the count just
/// after its own response, when every earlier connection has finished.
#[tokio::test]
async fn a_queue_of_connections_is_reaped_between_accepts() {
    const CLIENTS: usize = 32;
    let mut config = plaintext_config();
    config.max_connections = 1;
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(config);
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..CLIENTS {
        let metrics = metrics.clone();
        clients.spawn(async move {
            let response = get(local_addr).await;
            assert!(response.starts_with(b"HTTP/1.1 200"), "a queued connection is served");
            metrics.retained_connection_tasks()
        });
    }
    let mut most = 0;
    while let Some(retained) = clients.join_next().await {
        most = most.max(retained.expect("client task joins"));
    }
    assert_eq!(metrics.accepted_connections(), CLIENTS);
    // One live connection, plus tasks that released their seat and had not yet returned when the
    // next accept looked; a set that is never joined between accepts reads close to `CLIENTS`.
    assert!(most <= 8, "a client saw {most} connection tasks retained behind a one-connection ceiling");
    eventually(&metrics, "the drained queue leaves no task behind", |metrics| {
        metrics.retained_connection_tasks() == 0
    })
    .await;
    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport::default());
    assert!(task.await.expect("server task joins").is_ok());
}

/// Positive control — the count is an observation, not a constant: connections that are still
/// open are counted, and closing them is what brings the count down.
#[tokio::test]
async fn open_connections_are_counted_until_they_close() {
    let mut config = plaintext_config();
    // Held open without a request for the whole assertion, so the header deadline must not close
    // them first.
    config.header_read_timeout = Duration::from_secs(30);
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(config);
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(TcpStream::connect(local_addr).await.expect("TCP connects"));
    }
    eventually(&metrics, "three open connections are admitted", |metrics| {
        metrics.active_connections() == 3
    })
    .await;
    assert_eq!(metrics.retained_connection_tasks(), 3, "every open connection keeps its task");
    drop(open);
    eventually(&metrics, "closed connections release their tasks", |metrics| {
        metrics.active_connections() == 0 && metrics.retained_connection_tasks() == 0
    })
    .await;
    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport::default());
    assert!(task.await.expect("server task joins").is_ok());
}
