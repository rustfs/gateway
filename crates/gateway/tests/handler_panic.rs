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

//! Handler panic isolation at the assembled service boundary.
//!
//! Responsible for: proving a panicking handler becomes a `500` and cannot poison the service for
//! the following request.
//! NOT responsible for: authorizer and credential-provider panics, which their own suites cover.
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::panic)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{Handler, HandlerResult, Req, Resp};
use support::{Ping, PingOutput, exchange, ping_route, plain, wired};

struct PanicsOnce {
    calls: AtomicUsize,
}

impl Handler<Ping> for PanicsOnce {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("handler panic fixture");
        }
        Ok(Resp::new(PingOutput {
            message: "recovered".to_owned(),
        }))
    }
}

/// a-asm-0019. A handler panic is rendered as a protocol response and the same service remains
/// usable for the next request.
#[tokio::test]
async fn a_handler_panic_is_a_500_and_the_next_request_still_runs() {
    let service = wired()
        .register::<Ping, _>(Arc::new(PanicsOnce {
            calls: AtomicUsize::new(0),
        }))
        .route(ping_route())
        .build()
        .expect("a complete assembly");

    let first = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(first.0, http::StatusCode::INTERNAL_SERVER_ERROR, "{}", first.1);

    let second = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(second.0, http::StatusCode::OK, "{}", second.1);
    assert!(second.1.contains("recovered"), "{}", second.1);
}
