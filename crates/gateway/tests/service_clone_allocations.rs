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

mod support;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// a-asm-0002. Cloning a built service ten thousand times allocates no heap blocks.
#[test]
fn cloning_a_service_has_zero_allocations() {
    let service = support::service();
    let _profiler = dhat::Profiler::builder().testing().build();

    for _ in 0..10_000 {
        core::hint::black_box(service.clone());
    }

    let stats = dhat::HeapStats::get();
    assert_eq!(stats.total_blocks, 0, "S3Service::clone allocated heap blocks");
}
