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

//! Observer panic isolation after ordinary and committed responses are decided.
//!
//! Responsible for: proving callback panics cannot replace success or refusal documents, and
//! that isolation still calls the observer exactly once per request.
//! NOT responsible for: handler panics, which `handler_panic` covers, or middleware hot updates.
//! Upstream: `rustfs-gateway` and `support` fixtures. Downstream: nothing.

#![allow(clippy::panic)] // The fixture must panic to exercise the observer boundary.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{Method, StatusCode};
use rustfs_gateway::{Observer, RequestEvent};

use crate::support::{self, Backend, CopyCommit, Ping, RefuseEverything, exchange, plain, wired};

struct PanickingObserver(Arc<AtomicUsize>);

impl Observer for PanickingObserver {
    fn on_response(&self, _event: &RequestEvent<'_>) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("observer panic fixture");
    }
}

/// Negative — a callback panic neither destroys a success nor poisons the next request.
#[tokio::test]
async fn an_observer_panic_cannot_break_ordinary_successes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .observer(PanickingObserver(Arc::clone(&calls)))
        .build()
        .expect("a complete assembly");

    let mut responses = Vec::new();
    for _ in 0..2 {
        let (status, body) = exchange(&service, plain(Method::POST, "/")).await;
        responses.push((status, body.contains("pong")));
    }
    assert_eq!((responses, calls.load(Ordering::SeqCst)), (vec![(StatusCode::OK, true); 2], 2));
}

/// c-mw-0028. A callback panic cannot prevent the original refusal from returning.
#[tokio::test]
async fn an_observer_panic_cannot_break_an_ordinary_refusal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .governor(RefuseEverything)
        .observer(PanickingObserver(Arc::clone(&calls)))
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, plain(Method::POST, "/")).await;
    assert_eq!(
        (status, body.contains("<Code>SlowDown</Code>"), calls.load(Ordering::SeqCst)),
        (StatusCode::SERVICE_UNAVAILABLE, true, 1),
        "{body}"
    );
}

/// Negative — a panicking completion callback cannot cancel delivery of the successful document.
#[tokio::test]
async fn an_observer_panic_cannot_break_a_committed_success() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::copy_commit_builder(CopyCommit::Answer)
        .observer(PanickingObserver(Arc::clone(&calls)))
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, support::copy_commit_request()).await;
    assert_eq!(
        (status, body.contains("<CopyObjectResult"), calls.load(Ordering::SeqCst)),
        (StatusCode::OK, true, 1),
        "{body}"
    );
}

/// c-mw-0028. A committed refusal must keep its own code instead of the canceled-work fallback.
#[tokio::test]
async fn an_observer_panic_cannot_replace_a_committed_refusal() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::copy_commit_builder(CopyCommit::Fail)
        .observer(PanickingObserver(Arc::clone(&calls)))
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, support::copy_commit_request()).await;
    assert_eq!(
        (status, body.contains("<Code>NoSuchKey</Code>"), calls.load(Ordering::SeqCst)),
        (StatusCode::OK, true, 1),
        "{body}"
    );
}

struct DropPayload {
    drops: Arc<AtomicUsize>,
    panic_on_drop: bool,
}

impl Drop for DropPayload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if self.panic_on_drop {
            panic!("observer payload drop fixture");
        }
    }
}

struct PayloadObserver {
    drops: Arc<AtomicUsize>,
    panic_on_drop: bool,
}

impl Observer for PayloadObserver {
    fn on_response(&self, _event: &RequestEvent<'_>) {
        std::panic::panic_any(DropPayload {
            drops: Arc::clone(&self.drops),
            panic_on_drop: self.panic_on_drop,
        });
    }
}

/// Negative — unwinding during payload destruction must not destroy the ordinary response.
#[tokio::test]
async fn an_observer_payload_drop_panic_cannot_break_an_ordinary_response() {
    let drops = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .observer(PayloadObserver {
            drops: Arc::clone(&drops),
            panic_on_drop: true,
        })
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(Method::POST, "/")).await;
    assert_eq!((status, body.contains("pong"), drops.load(Ordering::SeqCst)), (StatusCode::OK, true, 1));
}

/// Negative — payload destruction must not replace the committed terminal refusal.
#[tokio::test]
async fn an_observer_payload_drop_panic_cannot_replace_a_committed_refusal() {
    let drops = Arc::new(AtomicUsize::new(0));
    let service = support::copy_commit_builder(CopyCommit::Fail)
        .observer(PayloadObserver {
            drops: Arc::clone(&drops),
            panic_on_drop: true,
        })
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, support::copy_commit_request()).await;
    assert_eq!(
        (status, body.contains("<Code>NoSuchKey</Code>"), drops.load(Ordering::SeqCst)),
        (StatusCode::OK, true, 1),
        "{body}"
    );
}

/// Positive — ordinary panic payloads are destroyed, not leaked on every failed callback.
#[tokio::test]
async fn an_observer_panic_payload_is_released() {
    let drops = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .observer(PayloadObserver {
            drops: Arc::clone(&drops),
            panic_on_drop: false,
        })
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(Method::POST, "/")).await;
    assert_eq!((status, body.contains("pong"), drops.load(Ordering::SeqCst)), (StatusCode::OK, true, 1));
}
