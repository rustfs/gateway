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

//! Responsible for: freezing fixture deadlines while polling real socket operations.
//! NOT responsible for: production deadlines or changing server scheduling.
//! Upstream: slow-header admission tests. Downstream: Tokio clock and socket reactor.

use std::time::Duration;

/// Poll real sockets without letting scheduler stalls expire the partial-header fixtures.
/// A runnable yield branch also prevents Tokio's paused clock from auto-advancing on idle I/O.
pub(super) async fn with_header_clock_frozen<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::pause();
    let started = std::time::Instant::now();
    tokio::pin!(future);
    let result = loop {
        tokio::select! {
            result = &mut future => break result,
            () = tokio::task::yield_now() => {
                assert!(started.elapsed() < Duration::from_secs(10), "socket admission or healthy request stalled");
            }
        }
    };
    tokio::time::resume();
    result
}
