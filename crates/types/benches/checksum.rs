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

//! Checksum throughput records and the hardware-acceleration gate.
//!
//! Responsible for: rustfs/backlog#1766 `checksum/{crc32,crc32c,crc64nvme,sha256,md5}` — GiB/s,
//! printed and never asserted — and a-pf-0007 / a-pf-0014: on x86_64 and aarch64 every CRC must
//! run on the SIMD calculator `crc-fast` selected for this host, read from the library rather than
//! inferred from CPU flags, so a build that silently fell back to tables fails.
//! NOT responsible for: digest correctness (`scalar::tests::checksum_tests`) or a time threshold.
//! Upstream: `ChecksumAlgorithm`. Downstream: `perf-evidence.yml`.

use std::hint::black_box;
use std::time::Instant;

use rustfs_gateway_types::ChecksumAlgorithm;

const BUFFER: usize = 1 << 20;
const ROUNDS: usize = 256;

/// Whether `target` names a hardware calculator. `crc-fast` spells its table fallback
/// `software-fallback-tables`; every other target is a SIMD one.
fn is_hardware(target: &str) -> bool {
    !target.starts_with("software")
}

fn main() {
    assert!(!is_hardware("software-fallback-tables"), "the gate must recognise the fallback");
    assert!(is_hardware("x86_64-avx512-vpclmulqdq"), "the gate must accept a SIMD target");

    let data: Vec<u8> = (0..BUFFER).map(|index| (index % 251) as u8).collect();
    let simd_host = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));
    for algo in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Crc64Nvme,
    ] {
        let target = algo.crc_acceleration_target().expect("a CRC has a crc-fast calculator");
        println!("checksum/{algo}: calculator {target}");
        if simd_host {
            assert!(is_hardware(&target), "{algo} fell back to {target} on a host with SIMD CRC support");
        } else {
            println!("SKIP checksum/{algo} acceleration: no SIMD CRC calculator exists for this architecture");
        }
    }
    #[cfg(target_arch = "x86_64")]
    println!("checksum/sha256: host SHA extensions {}", std::arch::is_x86_feature_detected!("sha"));
    #[cfg(target_arch = "aarch64")]
    println!("checksum/sha256: host SHA extensions {}", std::arch::is_aarch64_feature_detected!("sha2"));

    for algo in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Crc64Nvme,
        ChecksumAlgorithm::Sha256,
        ChecksumAlgorithm::Md5,
    ] {
        let started = Instant::now();
        let mut digest = algo.checksummer();
        for _ in 0..ROUNDS {
            digest.update(black_box(&data));
        }
        black_box(digest.finalize());
        let seconds = started.elapsed().as_secs_f64();
        let gib = (BUFFER * ROUNDS) as f64 / f64::from(1_u32 << 30);
        println!(
            "checksum/{}: {:.2} GiB/s ({} MiB; record-only, non-blocking)",
            algo.to_string().to_lowercase(),
            gib / seconds,
            (BUFFER * ROUNDS) >> 20
        );
    }
}
