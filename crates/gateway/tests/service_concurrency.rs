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

//! Concurrent clone-and-request coverage for the assembled service.
//!
//! Responsible for: driving one shared service from one hundred operating-system threads.
//! NOT responsible for: running ThreadSanitizer, which is an external nightly tool invocation.
//! Upstream: `rustfs-gateway`. Downstream: P7 connection handling and the documented TSAN command.

mod support;

use std::sync::{Arc, Barrier};

/// a-asm-0024. One hundred connection-style clones can answer requests concurrently.
#[test]
fn one_hundred_clones_answer_concurrently() {
    let service = support::service();
    let start = Arc::new(Barrier::new(100));
    let mut workers = Vec::with_capacity(100);

    for _ in 0..100 {
        let service = service.clone();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a current-thread runtime");
            start.wait();
            runtime.block_on(async {
                let (status, _) = support::exchange(&service, support::plain(http::Method::POST, "/")).await;
                assert_eq!(status, http::StatusCode::OK);
            });
        }));
    }

    for worker in workers {
        worker.join().expect("a request thread must not panic");
    }
}
