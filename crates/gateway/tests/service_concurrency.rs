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
    #[cfg(gateway_tsan)]
    assert_the_system_allocator_serves_this_binary();
    let service = support::service();
    let start = Arc::new(Barrier::new(THREADS));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(THREADS);

    for _ in 0..THREADS {
        let service = service.clone();
        let start = Arc::clone(&start);
        let completed = Arc::clone(&completed);
        workers.push(std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a current-thread runtime");
            start.wait();
            runtime.block_on(async {
                let (status, _) = support::exchange(&service, support::plain(http::Method::POST, "/")).await;
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

/// Under ThreadSanitizer this binary must allocate through the system allocator, never through
/// `dhat::Alloc`, whose global lock would order every allocating thread and could hide a race
/// (rustfs/gateway#958). A dhat testing profiler counts blocks only when `dhat::Alloc` is the
/// global allocator, so a counted allocation means the instrumentation is back.
#[cfg(gateway_tsan)]
fn assert_the_system_allocator_serves_this_binary() {
    let profiler = dhat::Profiler::builder().testing().build();
    let probe = std::hint::black_box(vec![0_u8; 4096]);
    let stats = dhat::HeapStats::get();
    drop(probe);
    drop(profiler);
    assert_eq!(
        stats.total_blocks, 0,
        "the TSAN build allocates through dhat::Alloc; its global lock orders every allocating thread"
    );
}
