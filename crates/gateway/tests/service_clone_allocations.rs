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

//! Allocation evidence for cloning the assembled service.
//!
//! Responsible for: proving ten thousand connection-style clones allocate no heap blocks.
//! NOT responsible for: measuring request processing or initial assembly.
//! Upstream: `rustfs-gateway`. Downstream: P7 server connection handling.

use crate::support;
use std::process::Command;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

const ALLOCATION_PROBE_ENV: &str = "RUSTFS_GATEWAY_CLONE_ALLOCATION_PROBE";
const ALLOCATION_PROBE_SENTINEL: &str = "rustfs-gateway clone allocation probe passed";
const ALLOCATION_PROBE_TEST: &str = "service_clone_allocations::cloning_a_service_has_zero_allocations";

/// a-asm-0002. Cloning a built service ten thousand times allocates no heap blocks.
#[test]
fn cloning_a_service_has_zero_allocations() {
    if std::env::var_os(ALLOCATION_PROBE_ENV).is_none() {
        let executable = std::env::current_exe().expect("the active test binary has a path");
        let output = Command::new(executable)
            .args(["--exact", ALLOCATION_PROBE_TEST, "--nocapture"])
            .env(ALLOCATION_PROBE_ENV, "1")
            .output()
            .expect("the isolated allocation probe starts");
        assert!(
            output.status.success(),
            "isolated allocation probe failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output
                .stdout
                .split(|byte| *byte == b'\n')
                .any(|line| line == ALLOCATION_PROBE_SENTINEL.as_bytes()),
            "isolated allocation probe emitted no success sentinel:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let service = support::service();
    let _profiler = dhat::Profiler::builder().testing().build();

    for _ in 0..10_000 {
        core::hint::black_box(service.clone());
    }

    let stats = dhat::HeapStats::get();
    assert_eq!(stats.total_blocks, 0, "S3Service::clone allocated heap blocks");
    println!("{ALLOCATION_PROBE_SENTINEL}");
}
