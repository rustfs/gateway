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

//! Exercises real lease exclusion at the drain fixture and load-child boundaries.
//!
//! Responsible for: observing both acquisition directions and the complete drain lease scope.
//! NOT responsible for: replacing body delivery assertions or measuring host performance.
//! Upstream: load coordination and runtime drain fixtures. Downstream: the integration harness.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use super::*;

#[tokio::test]
async fn drain_fixture_waits_for_load_and_holds_exclusion_through_join() {
    let competing_load = shared_server_load_lease().await;
    tokio::time::pause();
    let checkpoints = AtomicUsize::new(0);
    let fixture = crate::server_runtime::observed_shutdown_drain(|| {
        assert!(
            SERVER_LOAD_ISOLATION.try_read().is_err(),
            "the drain fixture excludes load through both joins"
        );
        checkpoints.fetch_add(1, Ordering::SeqCst);
    });
    tokio::pin!(fixture);
    std::future::poll_fn(|cx| {
        assert!(fixture.as_mut().poll(cx).is_pending(), "the actual fixture waits for active load");
        Poll::Ready(())
    })
    .await;
    assert_eq!(checkpoints.load(Ordering::SeqCst), 0, "listener setup must not start beside load");
    let completion = async {
        std::future::poll_fn(|cx| {
            assert!(
                fixture.as_mut().poll(cx).is_pending(),
                "the fixture exposes acquisition before completion"
            );
            if checkpoints.load(Ordering::SeqCst) == 0 {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        tokio::time::timeout(Duration::from_secs(5), fixture)
            .await
            .expect("drain fixture finishes within its execution budget");
    };
    tokio::pin!(completion);
    std::future::poll_fn(|cx| {
        assert!(completion.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_secs(6)).await;
    std::future::poll_fn(|cx| {
        assert!(
            completion.as_mut().poll(cx).is_pending(),
            "waiting for competing load must not consume the execution budget"
        );
        Poll::Ready(())
    })
    .await;
    assert_eq!(checkpoints.load(Ordering::SeqCst), 0, "the competing load still excludes listener setup");
    drop(competing_load);
    tokio::time::resume();
    completion.await;
    assert_eq!(checkpoints.load(Ordering::SeqCst), 2, "both pre-listener and post-join checks ran");
}

#[tokio::test]
async fn load_child_waits_for_exclusive_drain_lease() {
    let exclusive = exclusive_server_load_lease().await;
    let child = run_isolated("isolation::load_child_waits_for_exclusive_drain_lease");
    tokio::pin!(child);
    // The re-executed test uses the real child-marker path and must not recurse.
    if std::env::var_os(RSS_CHILD_MARKER).is_some() {
        assert!(child.await, "the named child takes the isolated-child path");
        return;
    }
    std::future::poll_fn(|cx| {
        assert!(
            child.as_mut().poll(cx).is_pending(),
            "a real load child cannot start during the drain lease"
        );
        Poll::Ready(())
    })
    .await;
    drop(exclusive);
    assert!(!child.await, "the parent observed a successful real child and its test census");
}
