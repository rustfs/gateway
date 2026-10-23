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

//! Responsible for: bounded listener-stop probes and falsifiable observer controls.
//! Not responsible for: production listener state, response draining, or TLS shutdown.
//! Upstream: established-H1 and drain fixtures. Downstream: supplied connection probe futures.

use std::future::{Future, pending};
use std::io;
use std::time::Duration;

pub(super) async fn wait_for_listener_stop<F, P>(mut probe: F) -> Result<(), tokio::time::error::Elapsed>
where
    F: FnMut() -> P,
    P: Future<Output = io::Result<()>>,
{
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            // An older connect can remain pending after fresh connections already fail.
            // Retry within the original deadline; a probe timeout is not closure evidence.
            if let Ok(Err(_)) = tokio::time::timeout(Duration::from_millis(50), probe()).await {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

#[tokio::test]
async fn a_stalled_first_probe_does_not_hide_a_later_refusal() {
    let mut attempts = 0;
    let observed = wait_for_listener_stop(|| {
        attempts += 1;
        let first = attempts == 1;
        async move {
            if first {
                pending::<io::Result<()>>().await
            } else {
                Err(io::ErrorKind::ConnectionRefused.into())
            }
        }
    });
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Ok(()))));
}

#[tokio::test]
async fn an_immediate_refusal_observes_listener_stop() {
    let observed = wait_for_listener_stop(|| async { Err(io::ErrorKind::ConnectionRefused.into()) });
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Ok(()))));
}

#[tokio::test]
async fn a_successful_connection_is_retried_before_a_refusal() {
    let mut attempts = 0;
    let observed = wait_for_listener_stop(|| {
        attempts += 1;
        let first = attempts == 1;
        async move {
            if first {
                Ok(())
            } else {
                Err(io::ErrorKind::ConnectionRefused.into())
            }
        }
    });
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Ok(()))));
}

#[tokio::test]
async fn a_listener_that_always_accepts_never_observes_stop() {
    let observed = wait_for_listener_stop(|| async { Ok(()) });
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Err(_))));
}

#[tokio::test]
async fn probes_that_all_stall_never_observe_stop() {
    let observed = wait_for_listener_stop(pending::<io::Result<()>>);
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Err(_))));
}

#[tokio::test]
async fn a_successful_probe_followed_by_stalls_never_observes_stop() {
    let mut attempts = 0;
    let observed = wait_for_listener_stop(|| {
        attempts += 1;
        let first = attempts == 1;
        async move { if first { Ok(()) } else { pending::<io::Result<()>>().await } }
    });
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Err(_))));
}

#[tokio::test]
async fn a_stalled_probe_followed_by_live_connections_never_observes_stop() {
    let mut attempts = 0;
    let observed = wait_for_listener_stop(|| {
        attempts += 1;
        let first = attempts == 1;
        async move { if first { pending::<io::Result<()>>().await } else { Ok(()) } }
    });
    assert!(matches!(tokio::time::timeout(Duration::from_secs(2), observed).await, Ok(Err(_))));
}
