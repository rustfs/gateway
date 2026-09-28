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
//! NOT responsible for: installing nightly; `scripts/run_gateway_tsan.sh` owns the sanitizer
//! invocation and CI installs its pinned toolchain.
//! Upstream: `rustfs-gateway`. Downstream: P7 connection handling and the TSAN CI job.

use crate::support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

const THREADS: usize = 100;

/// a-asm-0024. One hundred connection-style clones can answer requests concurrently.
#[test]
fn one_hundred_clones_answer_concurrently() {
    let service = support::service();
    let start = Arc::new(Barrier::new(THREADS));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(THREADS);

    let built = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicUsize::new(0));
    let answered = Arc::new(AtomicUsize::new(0));
    {
        let (built, passed, answered, completed) = (Arc::clone(&built), Arc::clone(&passed), Arc::clone(&answered), Arc::clone(&completed));
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/tsan-diag.log").expect("diag log");
                let _ = writeln!(
                    file,
                    "DIAG t={:?} built={} passed_barrier={} answered={} completed={}",
                    started.elapsed(),
                    built.load(Ordering::SeqCst),
                    passed.load(Ordering::SeqCst),
                    answered.load(Ordering::SeqCst),
                    completed.load(Ordering::SeqCst)
                );
            }
        });
    }
    for _ in 0..THREADS {
        let service = service.clone();
        let start = Arc::clone(&start);
        let completed = Arc::clone(&completed);
        let (built, passed, answered) = (Arc::clone(&built), Arc::clone(&passed), Arc::clone(&answered));
        workers.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a current-thread runtime");
            built.fetch_add(1, Ordering::SeqCst);
            start.wait();
            passed.fetch_add(1, Ordering::SeqCst);
            runtime.block_on(async {
                let (status, _) = support::exchange(&service, support::plain(http::Method::POST, "/")).await;
                answered.fetch_add(1, Ordering::SeqCst);
                assert_eq!(status, http::StatusCode::OK);
            });
            completed.fetch_add(1, Ordering::SeqCst);
        }));
    }

    for worker in workers {
        worker.join().expect("a request thread must not panic");
    }
    assert_eq!(completed.load(Ordering::SeqCst), 100, "not every OS request thread completed");
}
