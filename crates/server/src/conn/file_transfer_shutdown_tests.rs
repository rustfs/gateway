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

//! Listener shutdown against blocking file work detached from its connection task.
//!
//! Responsible for: the drain waiting for detached file work and the force abort not waiting for it.
//! NOT responsible for: the accept loop or connection admission.
//! Upstream: `conn`'s shutdown helpers. Downstream: none.

use std::sync::mpsc;
use std::time::Duration;

use tokio::task::JoinSet;

use super::{drain_connections_and_file_transfers, finish_shutdown};
use crate::connection_service::RequestStats;
use crate::sendfile_task::BlockingFileTransferExecutor;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn listener_drain_waits_for_file_work_detached_from_its_connection_task() {
    let executor = BlockingFileTransferExecutor::new(1);
    let transfer_executor = executor.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let transfer = tokio::spawn(async move {
        transfer_executor
            .run(move |_permit| {
                entered_tx.send(()).expect("test receiver remains alive");
                release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test releases the blocking job");
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("blocking file work starts");
    transfer.abort();
    assert!(
        transfer
            .await
            .expect_err("connection-side waiter is cancelled")
            .is_cancelled()
    );

    let drain_executor = executor.clone();
    let (drain_done_tx, drain_done_rx) = mpsc::channel();
    let drain = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        drain_connections_and_file_transfers(&mut connections, &drain_executor).await;
        drain_done_tx.send(()).expect("test receiver remains alive");
    });
    assert!(
        matches!(
            drain_done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "listener drain includes detached file work"
    );

    release_tx.send(()).expect("blocking job still waits for release");
    drain_done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("listener drain completes after file work exits");
    drain.await.expect("listener drain joins after file work exits");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn force_abort_finishes_without_waiting_for_detached_file_work() {
    let executor = BlockingFileTransferExecutor::new(1);
    let transfer_executor = executor.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let transfer = tokio::spawn(async move {
        transfer_executor
            .run(move |_permit| {
                entered_tx.send(()).expect("test receiver remains alive");
                release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test releases the blocking job");
                Ok::<_, std::io::Error>(())
            })
            .await
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("blocking file work starts");
    transfer.abort();
    assert!(
        transfer
            .await
            .expect_err("connection-side waiter is cancelled")
            .is_cancelled()
    );

    let request_stats = RequestStats::default();
    let mut connections = JoinSet::new();
    connections.spawn(std::future::pending());
    tokio::time::timeout(
        Duration::from_millis(100),
        finish_shutdown(&mut connections, &executor, &request_stats, Duration::from_millis(10)),
    )
    .await
    .expect("force abort has a hard return bound");
    assert!(
        request_stats.force_abort.load(std::sync::atomic::Ordering::Acquire),
        "the production grace-timeout seam marks in-flight requests for force abort"
    );

    release_tx
        .send(())
        .expect("detached file work remains alive until explicitly released");
    executor.wait_idle().await;
}
