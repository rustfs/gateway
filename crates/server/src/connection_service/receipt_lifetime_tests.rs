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

//! Responsible for: separating transport receipt settlement from detached handler cleanup.
//! NOT responsible for: observing real socket writes or choosing the service's cleanup deadline.
//! Upstream: the managed service and request cancellation. Downstream: no runtime consumer.

#![allow(clippy::expect_used)] // Test-only synchronization terminates the scenario on failure.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Context;
use std::time::Duration;

use bytes::Bytes;
use futures_util::task::noop_waker_ref;
use http::{Request, Response};
use http_body_util::Full;
use tokio::sync::Notify;
use tower::{Service, service_fn};

use super::RequestStats;
use super::cancellation_capacity_tests::managed_service;
use crate::request_capacity::RequestCancellation;

#[tokio::test]
async fn n_detached_cleanup_does_not_delay_aborted_transport_receipts() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let finished = Arc::new(Notify::new());
    let inner = service_fn({
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        let finished = Arc::clone(&finished);
        move |request: Request<()>| {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            let finished = Arc::clone(&finished);
            async move {
                let mut cancellation = request
                    .extensions()
                    .get::<RequestCancellation>()
                    .cloned()
                    .expect("managed cancellation");
                while !*cancellation.borrow() {
                    cancellation.changed().await.expect("cancellation source signals peer loss");
                }
                started.notify_one();
                release.notified().await;
                finished.notify_one();
                Ok::<_, io::Error>(Response::new(Full::new(Bytes::from_static(b"cleanup finished"))))
            }
        }
    });
    let stats = Arc::new(RequestStats::default());
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (mut service, available) = managed_service(inner, Arc::clone(&stats), Arc::clone(&in_flight));
    stats.begin_shutdown();
    // A different response on this connection handed over its final frame but has no write receipt.
    service.receipts.handed_over(true);
    let mut request = Service::call(&mut service, Request::new(()));
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(request.as_mut().poll(&mut context).is_pending(), "the handler waits for cancellation");
    drop(request);
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("detached cleanup starts");
    let capacity_while_cleaning = *available.borrow();
    let in_flight_while_cleaning = in_flight.load(Ordering::Relaxed);
    stats.force_abort();
    // Simulate disposal of the transport's last service owner while detached cleanup is held.
    drop(service);
    let aborted_before_cleanup = stats.aborted();
    eprintln!(
        "before cleanup: available={capacity_while_cleaning}, in_flight={in_flight_while_cleaning}, aborted={aborted_before_cleanup}"
    );
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), finished.notified())
        .await
        .expect("cleanup finishes");
    assert_eq!(
        aborted_before_cleanup, 1,
        "the aborted transport settles its existing unconfirmed response immediately"
    );
    assert_eq!(capacity_while_cleaning, 0, "detached cleanup still owns its request permit");
    assert_eq!(in_flight_while_cleaning, 1, "detached cleanup still owns its request guard");
    assert_eq!(*available.borrow(), 1, "completed cleanup releases its request permit");
    assert_eq!(in_flight.load(Ordering::Relaxed), 0, "completed cleanup releases its request guard");
    assert_eq!(stats.aborted(), 2, "transport and unfinished request are each accounted once");
}
