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

//! Peak-RSS and healthy-latency evidence for the four-GiB chunk refusal (c-lim-0042, c-lim-0064).
//!
//! Responsible for: re-running this test binary as OS-observed probe children under
//! `/usr/bin/time`, comparing their peak RSS with a control and a touched ballast, and measuring
//! healthy requests in on-CPU time while one hundred attacks run.
//! NOT responsible for: the header refusal itself (`ingest_chunk_rules`, c-ing-0021) or any other
//! chunk-grammar rule.
//! Upstream: the ingest pipeline test support. Downstream: `scripts/check_chunk_limits.sh`.
//!
//! 0 positive / 2 negative.

use crate::support::ingest::{drain_pipeline, no_observers, unsigned_pipeline};
use rustfs_gateway_http::{ChunkLimits, ChunkReject};

use super::ingest_chunk_rules::FOUR_GIB_CHUNK_HEADER;

const RSS_HEADROOM_BYTES: u64 = 8 * 1024 * 1024;
const RSS_BALLAST_BYTES: usize = 24 * 1024 * 1024;
const RSS_PROBE_ENV: &str = "RUSTFS_GATEWAY_CHUNK_LIMIT_RSS_PROBE";
const RSS_PROBE_TEST: &str = "c_lim_0042_four_gibibyte_chunk_peak_rss_stays_below_eight_mibibytes";
const CONCURRENT_PROBE_ENV: &str = "RUSTFS_GATEWAY_CONCURRENT_CHUNK_LIMIT_PROBE";
const CONCURRENT_PROBE_TEST: &str = "c_lim_0064_concurrent_four_gibibyte_chunks_preserve_rss_and_healthy_p99";
const CONCURRENT_ATTACKERS: usize = 100;
const HEALTHY_PROBES: usize = 500;

#[derive(Clone, Copy)]
enum PeakMode {
    Control,
    Attack,
    Ballast,
}

impl PeakMode {
    fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Attack => "attack",
            Self::Ballast => "ballast",
        }
    }

    fn requested() -> Option<Self> {
        match std::env::var(RSS_PROBE_ENV).ok()?.as_str() {
            "control" => Some(Self::Control),
            "attack" => Some(Self::Attack),
            "ballast" => Some(Self::Ballast),
            other => panic!("unknown c-lim-0042 RSS probe mode: {other}"),
        }
    }
}

fn run_peak_probe(mode: PeakMode) {
    let mut ballast = match mode {
        PeakMode::Ballast => vec![0_u8; RSS_BALLAST_BYTES],
        PeakMode::Control | PeakMode::Attack => Vec::new(),
    };
    for byte in ballast.iter_mut().step_by(4096) {
        *byte = 0xA5;
    }
    std::hint::black_box(&ballast);

    match mode {
        PeakMode::Attack => {
            let mut pipeline =
                unsigned_pipeline(FOUR_GIB_CHUNK_HEADER.to_vec(), 1024, 4096, no_observers(), ChunkLimits::default());
            let err = drain_pipeline(&mut pipeline, 4096).expect_err("the four-GiB chunk header is refused");
            assert_eq!(err.bytes_before_error(), 0);
            assert!(matches!(
                pipeline.reject(),
                Some(ChunkReject::ChunkSizeTooLarge {
                    declared: 0xffff_ffff,
                    ..
                })
            ));
            assert_eq!(pipeline.decoded_bytes(), 0);
        }
        PeakMode::Control | PeakMode::Ballast => {
            let mut pipeline = unsigned_pipeline(b"0\r\n\r\n".to_vec(), 8, 0, no_observers(), ChunkLimits::default());
            let decoded = drain_pipeline(&mut pipeline, 16).expect("the empty control body is accepted");
            assert!(decoded.is_empty());
        }
    }
    std::hint::black_box(&ballast);
}

#[cfg(target_os = "linux")]
fn parse_peak_rss(stderr: &str) -> u64 {
    let kibibytes = stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix("Maximum resident set size (kbytes):"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("GNU time reports maximum resident set size");
    kibibytes.checked_mul(1024).expect("peak RSS fits in u64")
}

#[cfg(target_os = "macos")]
fn parse_peak_rss(stderr: &str) -> u64 {
    stderr
        .lines()
        .find_map(|line| line.trim().strip_suffix("maximum resident set size"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("BSD time reports maximum resident set size")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn parse_peak_rss(_stderr: &str) -> u64 {
    panic!("c-lim-0042 peak RSS is supported only on Linux and macOS");
}

fn measure_peak_rss(mode: PeakMode) -> u64 {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let mut command = std::process::Command::new("/usr/bin/time");
    #[cfg(target_os = "linux")]
    command.arg("-v");
    #[cfg(target_os = "macos")]
    command.arg("-l");
    let output = command
        .arg(executable)
        .args(["--exact", &crate::probe_test_name!(RSS_PROBE_TEST), "--nocapture"])
        .env(RSS_PROBE_ENV, mode.name())
        .output()
        .expect("the peak-RSS probe starts under /usr/bin/time");
    assert!(
        output.status.success(),
        "the {} peak-RSS probe failed:\n{}{}",
        mode.name(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_peak_rss(&String::from_utf8_lossy(&output.stderr))
}

fn concurrent_probe_requested() -> Option<bool> {
    match std::env::var(CONCURRENT_PROBE_ENV).ok()?.as_str() {
        "control" => Some(false),
        "attack" => Some(true),
        other => panic!("unknown c-lim-0064 concurrent probe mode: {other}"),
    }
}

/// The calling thread's on-CPU time.
///
/// c-lim-0064's healthy latencies are measured in this rather than wall time. A hundred probe
/// threads on a four-CPU runner spend most of their wall time waiting for a CPU, so a wall-clock
/// p99 measured the host scheduler and CFS throttling of the moment: locally the same unchanged
/// probe ranged from 13µs to 2ms under load, and CI saw a single preemption exceed the 5ms
/// allowance (rustfs/gateway#1026). What an attack could cost a healthy request in this in-process
/// pipeline is its own work — parsing, allocation, allocator contention — all of which is on-CPU
/// time; being descheduled is not.
#[cfg(unix)]
fn thread_cpu_time() -> std::time::Duration {
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_THREAD_CPUTIME_ID).expect("the thread CPU clock is readable");
    std::time::Duration::from(now)
}

/// c-lim-0064 skips before probing on every platform without a peak-RSS observer.
#[cfg(not(unix))]
fn thread_cpu_time() -> std::time::Duration {
    panic!("c-lim-0064 measures thread CPU time only on the platforms it runs on")
}

fn run_concurrent_probe(attack: bool) {
    let start = std::sync::Arc::new(std::sync::Barrier::new(CONCURRENT_ATTACKERS + 1));
    let finish = std::sync::Arc::new(std::sync::Barrier::new(CONCURRENT_ATTACKERS + 1));
    let workers: Vec<_> = (0..CONCURRENT_ATTACKERS)
        .map(|_| {
            let start = std::sync::Arc::clone(&start);
            let finish = std::sync::Arc::clone(&finish);
            std::thread::spawn(move || {
                start.wait();
                // Each request's pipeline is held until every worker has finished, so all one
                // hundred are resident at once in both modes. The peak RSS is then the worst-case
                // overlap by construction rather than whatever overlap the host's scheduler
                // happened to produce (rustfs/gateway#1026).
                let (mut valid, _held) = if attack {
                    let mut body = FOUR_GIB_CHUNK_HEADER.to_vec();
                    body.extend_from_slice(&[b'z'; 4096]);
                    let mut pipeline = unsigned_pipeline(body, 1, 4096, no_observers(), ChunkLimits::default());
                    let refused = match drain_pipeline(&mut pipeline, 4096) {
                        Err(error) => {
                            error.bytes_before_error() == 0
                                && matches!(
                                    pipeline.reject(),
                                    Some(ChunkReject::ChunkSizeTooLarge {
                                        declared: 0xffff_ffff,
                                        ..
                                    })
                                )
                                && pipeline
                                    .reject()
                                    .is_some_and(|reject| reject.to_status() == http::StatusCode::BAD_REQUEST)
                                && pipeline.decoded_bytes() == 0
                                && pipeline.window_bytes() <= 64 * 1024
                        }
                        Ok(_) => false,
                    };
                    (refused, pipeline)
                } else {
                    let mut pipeline = unsigned_pipeline(b"0\r\n\r\n".to_vec(), 1, 0, no_observers(), ChunkLimits::default());
                    (drain_pipeline(&mut pipeline, 16).is_ok(), pipeline)
                };
                let mut healthy_latencies = Vec::with_capacity(HEALTHY_PROBES / CONCURRENT_ATTACKERS);
                for _ in 0..HEALTHY_PROBES / CONCURRENT_ATTACKERS {
                    let started = thread_cpu_time();
                    let mut pipeline = unsigned_pipeline(b"0\r\n\r\n".to_vec(), 1, 0, no_observers(), ChunkLimits::default());
                    valid &= drain_pipeline(&mut pipeline, 16).is_ok();
                    healthy_latencies.push(thread_cpu_time().saturating_sub(started));
                }
                finish.wait();
                (valid, healthy_latencies)
            })
        })
        .collect();

    start.wait();
    finish.wait();
    let mut valid = 0;
    let mut healthy_latencies = Vec::with_capacity(HEALTHY_PROBES);
    for worker in workers {
        let (worker_valid, mut worker_latencies) = worker.join().expect("a concurrent chunk worker joins");
        valid += usize::from(worker_valid);
        healthy_latencies.append(&mut worker_latencies);
    }
    assert_eq!(valid, CONCURRENT_ATTACKERS, "every concurrent chunk request has the expected outcome");
    assert_eq!(healthy_latencies.len(), HEALTHY_PROBES, "every worker contributes healthy p99 samples");
    healthy_latencies.sort_unstable();
    let rank = (HEALTHY_PROBES * 99).div_ceil(100).saturating_sub(1);
    let healthy_p99 = healthy_latencies[rank];
    println!("c-lim-0064 healthy p99 nanos: {}", healthy_p99.as_nanos());
}

fn measure_concurrent_probe(attack: bool) -> (u64, std::time::Duration) {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let mut command = std::process::Command::new("/usr/bin/time");
    #[cfg(target_os = "linux")]
    command.arg("-v");
    #[cfg(target_os = "macos")]
    command.arg("-l");
    let mode = if attack { "attack" } else { "control" };
    let output = command
        .arg(executable)
        .args(["--exact", &crate::probe_test_name!(CONCURRENT_PROBE_TEST), "--nocapture"])
        .env(CONCURRENT_PROBE_ENV, mode)
        .output()
        .expect("the concurrent chunk probe starts under /usr/bin/time");
    assert!(
        output.status.success(),
        "the {mode} concurrent chunk probe failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let p99_nanos = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("c-lim-0064 healthy p99 nanos: "))
        .and_then(|value| value.parse::<u64>().ok())
        .expect("the concurrent chunk probe reports healthy p99");
    (
        parse_peak_rss(&String::from_utf8_lossy(&output.stderr)),
        std::time::Duration::from_nanos(p99_nanos),
    )
}

/// c-lim-0042. The same exact rejection adds less than eight MiB to the process peak RSS.
#[test]
fn c_lim_0042_four_gibibyte_chunk_peak_rss_stays_below_eight_mibibytes() {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        eprintln!("SKIP c-lim-0042 peak RSS: this platform has no supported OS peak-RSS observer");
        return;
    }

    if let Some(mode) = PeakMode::requested() {
        run_peak_probe(mode);
        return;
    }

    let control = measure_peak_rss(PeakMode::Control);
    let attack = measure_peak_rss(PeakMode::Attack);
    let ballast = measure_peak_rss(PeakMode::Ballast);
    println!("c-lim-0042 peak RSS: control={control}, attack={attack}, ballast={ballast}");
    assert!(
        ballast.saturating_sub(control) >= RSS_HEADROOM_BYTES,
        "the RSS instrument saw only {} additional bytes from a {}-byte touched ballast",
        ballast.saturating_sub(control),
        RSS_BALLAST_BYTES
    );
    assert!(
        attack.saturating_sub(control) < RSS_HEADROOM_BYTES,
        "the four-GiB chunk declaration increased peak RSS by {} bytes (control {control}, attack {attack})",
        attack.saturating_sub(control)
    );
}

/// c-lim-0064. One hundred concurrent four-GiB announcements are all refused at the header;
/// their peak RSS stays flat and a normal empty body keeps its control-derived p99.
#[test]
fn c_lim_0064_concurrent_four_gibibyte_chunks_preserve_rss_and_healthy_p99() {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        eprintln!("SKIP c-lim-0064 peak RSS: this platform has no supported OS peak-RSS observer");
        return;
    }

    if let Some(attack) = concurrent_probe_requested() {
        run_concurrent_probe(attack);
        return;
    }

    let (control_rss, control_p99) = measure_concurrent_probe(false);
    let (attack_rss, attack_p99) = measure_concurrent_probe(true);
    let p99_ceiling = control_p99.saturating_mul(8) + std::time::Duration::from_millis(5);
    println!("c-lim-0064: RSS {control_rss}/{attack_rss}, p99 {control_p99:?}/{attack_p99:?}");
    assert!(
        attack_rss.saturating_sub(control_rss) < RSS_HEADROOM_BYTES,
        "one hundred concurrent chunk attacks increased peak RSS by {} bytes",
        attack_rss.saturating_sub(control_rss)
    );
    assert!(
        attack_p99 <= p99_ceiling,
        "healthy p99 {attack_p99:?} exceeded the control-derived {p99_ceiling:?} ceiling"
    );
}
