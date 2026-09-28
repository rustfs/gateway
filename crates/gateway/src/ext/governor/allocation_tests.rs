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

//! Allocator observations for the mandatory governor's synchronous decision path.
//!
//! Responsible for: counting the heap blocks `DefaultGovernor::try_acquire_sync` allocates on one
//! thread and under contention (c-gov-0001, c-gov-0030), and the heap and resident memory that a
//! million distinct source addresses leave behind (c-gov-0013).
//! NOT responsible for: whether a decision admits or refuses, which `default.rs` owns, or wall-clock
//! speed, which a shared runner cannot measure.
//! Upstream: `DefaultGovernor`, the lib-test binary's `dhat` allocator. Downstream: nothing.
//!
//! Every probe re-executes this binary on its own. `dhat` counts every thread of the process, so a
//! window opened while the rest of the suite runs would count the suite.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::{Arc, Barrier};

use super::{ClassKind, ClientAddr, DefaultGovernor, GovernorRates, GovernorRequest, Rate};

const PROBE_ENV: &str = "RUSTFS_GATEWAY_GOVERNOR_ALLOCATION_PROBE";
const SENTINEL: &str = "governor allocation probe: ";

/// Enough pre-authentication budget that every decision in a window reaches the address table.
fn roomy(tracked_clients: usize) -> GovernorRates {
    GovernorRates {
        aggregate: Rate::new(u32::MAX, u32::MAX),
        per_ip: Rate::new(2, 1),
        credential_lookup: Rate::new(u32::MAX, u32::MAX),
        cors_preflight: Rate::new(u32::MAX, u32::MAX),
        unauthenticated: Rate::new(u32::MAX, u32::MAX),
        tracked_clients,
    }
}

const KINDS: [ClassKind; 4] = [
    ClassKind::CredentialLookup,
    ClassKind::CorsPreflight,
    ClassKind::Unauthenticated,
    ClassKind::Authenticated,
];

/// A reproducible address stream: xorshift, alternating IPv4 hosts and distinct IPv6 `/64`s.
struct Addresses(u64);

impl Iterator for Addresses {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        let bits = self.0;
        Some(if bits & 1 == 0 {
            IpAddr::V4(Ipv4Addr::from((bits >> 16) as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(u128::from(bits) << 64))
        })
    }
}

fn decide(governor: &DefaultGovernor, kind: ClassKind, address: Option<IpAddr>) -> bool {
    let request = GovernorRequest::new("GetObject", None, None, None, address.map(ClientAddr::from_peer), kind);
    governor.try_acquire_sync(&request).is_some()
}

#[derive(Debug, Default)]
struct Observation {
    blocks: u64,
    bytes: u64,
    live_delta: i128,
    admitted: u64,
    refused: u64,
    tracked: usize,
    resident_delta: Option<i128>,
}

impl Observation {
    fn line(&self, probe: &str) -> String {
        format!(
            "{SENTINEL}{probe} blocks={} bytes={} live_delta={} admitted={} refused={} tracked={} resident_delta={}",
            self.blocks,
            self.bytes,
            self.live_delta,
            self.admitted,
            self.refused,
            self.tracked,
            self.resident_delta
                .map_or_else(|| "unavailable".to_owned(), |delta| delta.to_string()),
        )
    }

    fn parse(line: &str) -> Self {
        let mut observation = Self::default();
        for field in line.split_whitespace() {
            let Some((key, value)) = field.split_once('=') else { continue };
            match key {
                "blocks" => observation.blocks = value.parse().expect("blocks is a number"),
                "bytes" => observation.bytes = value.parse().expect("bytes is a number"),
                "live_delta" => observation.live_delta = value.parse().expect("live_delta is a number"),
                "admitted" => observation.admitted = value.parse().expect("admitted is a number"),
                "refused" => observation.refused = value.parse().expect("refused is a number"),
                "tracked" => observation.tracked = value.parse().expect("tracked is a number"),
                "resident_delta" => observation.resident_delta = value.parse().ok(),
                _ => {}
            }
        }
        observation
    }
}

/// Opens one `dhat` window around `work` and reports what it allocated.
fn measure(work: impl FnOnce() -> (u64, u64)) -> Observation {
    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    let resident_before = resident_bytes();
    let (admitted, refused) = work();
    let resident_after = resident_bytes();
    let after = dhat::HeapStats::get();
    drop(profiler);
    Observation {
        blocks: after.total_blocks - before.total_blocks,
        bytes: after.total_bytes - before.total_bytes,
        live_delta: i128::try_from(after.curr_bytes).unwrap_or(i128::MAX)
            - i128::try_from(before.curr_bytes).unwrap_or(i128::MAX),
        admitted,
        refused,
        tracked: 0,
        resident_delta: resident_before.zip(resident_after).map(|(before, after)| after - before),
    }
}

/// The anonymous part of this process's resident set, where the platform exposes it.
///
/// `RssAnon` rather than the whole resident set: the first run of any code faults its text pages
/// in, and those file-backed pages moved the total by about a mebibyte in every window on CI —
/// including the control's, which allocates one 64-byte box. Heap and table pages are anonymous.
/// Read into a stack buffer: this runs inside the allocation window, and a `String` here would be
/// the one allocation the window counted.
fn resident_bytes() -> Option<i128> {
    use std::io::Read;
    let mut buffer = [0_u8; 4096];
    let mut file = std::fs::File::open("/proc/self/status").ok()?;
    let mut filled = 0;
    loop {
        let read = file.read(buffer.get_mut(filled..)?).ok()?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    let text = std::str::from_utf8(buffer.get(..filled)?).ok()?;
    let kibibytes = text
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))?
        .split_whitespace()
        .next()?
        .parse::<i128>()
        .ok()?;
    Some(kibibytes * 1024)
}

/// Positive control: the instrument must see a real allocation, or every zero below is decoration.
fn control() -> Observation {
    measure(|| {
        let kept = Box::new([7_u8; 64]);
        core::hint::black_box(&kept);
        (0, 0)
    })
}

/// c-gov-0001: every class, first-seen and returning addresses, admitted and refused, one thread.
///
/// The governor is fresh, so the window includes the first insertions into an address table that
/// is not yet full: a table that grows on demand instead of being preallocated shows up here.
fn single_thread() -> Observation {
    let (governor, clock) = DefaultGovernor::manually_clocked(roomy(4096));
    let addresses: Vec<IpAddr> = Addresses(0x9E37_79B9_7F4A_7C15).take(1_024).collect();
    // Some platforms' `Mutex` allocates its OS lock on first use. That is a once-per-lock cost,
    // not a per-decision one, so every lock is taken once before the window; the address maps
    // themselves stay empty, so first insertions still happen inside it.
    assert_eq!(governor.tracked_clients(), 0);
    decide(&governor, ClassKind::Unauthenticated, None);
    let mut observation = measure(|| {
        let (mut admitted, mut refused) = (0, 0);
        for round in 0..8 {
            for (index, address) in addresses.iter().enumerate() {
                let kind = KINDS[index % KINDS.len()];
                let peer = (index % 17 != 0).then_some(*address);
                if decide(&governor, kind, peer) {
                    admitted += 1;
                } else {
                    refused += 1;
                }
            }
            if round % 2 == 1 {
                clock.advance_millis(1_000);
            }
        }
        (admitted, refused)
    });
    observation.tracked = governor.tracked_clients();
    observation
}

/// c-gov-0030: four threads decide against one governor with overlapping address sets.
///
/// Threads, their stacks and the barrier are created outside the window and every lock is warmed
/// once first, so what the window counts is the decision path under contention and nothing else.
fn contended() -> Observation {
    const THREADS: usize = 4;
    let (governor, _) = DefaultGovernor::manually_clocked(roomy(1_024));
    let governor = Arc::new(governor);
    let start = Arc::new(Barrier::new(THREADS + 1));
    let done = Arc::new(Barrier::new(THREADS + 1));
    let workers: Vec<_> = (0..THREADS)
        .map(|thread| {
            let governor = Arc::clone(&governor);
            let start = Arc::clone(&start);
            let done = Arc::clone(&done);
            let addresses: Vec<IpAddr> = Addresses(0x2545_F491_4F6C_DD1D + thread as u64 % 2).take(4_096).collect();
            std::thread::spawn(move || {
                let mut counts = (0_u64, 0_u64);
                for pass in 0..2 {
                    start.wait();
                    for (index, address) in addresses.iter().enumerate() {
                        let kind = KINDS[(index + thread) % KINDS.len()];
                        if decide(&governor, kind, Some(*address)) {
                            counts.0 += u64::from(pass == 1);
                        } else {
                            counts.1 += u64::from(pass == 1);
                        }
                    }
                    done.wait();
                }
                counts
            })
        })
        .collect();
    // Pass zero warms every shard lock, the barriers and the thread-locals outside the window.
    start.wait();
    done.wait();
    let mut observation = measure(|| {
        start.wait();
        done.wait();
        (0, 0)
    });
    for worker in workers {
        let (admitted, refused) = worker.join().expect("a decision thread does not panic");
        observation.admitted += admitted;
        observation.refused += refused;
    }
    observation.tracked = governor.tracked_clients();
    observation
}

/// c-gov-0013: one million distinct source addresses, from an empty table through saturation.
///
/// Construction is measured on its own: it is where the bounded table is allocated, and its byte
/// count is the budget the resident set is held to afterwards. The second window starts before the
/// first address is seen, so it covers filling every shard, the first eviction in each, and the
/// deleted slots a long run of evictions leaves behind.
fn one_million_addresses() -> (Observation, Observation) {
    const TRACKED: usize = 4_096;
    let mut built = None;
    let construction = measure(|| {
        built = Some(DefaultGovernor::manually_clocked(roomy(TRACKED)));
        (0, 0)
    });
    let (governor, clock) = built.expect("the governor was built inside the window");
    assert_eq!(governor.tracked_clients(), 0);
    decide(&governor, ClassKind::Unauthenticated, None);
    let mut addresses = Addresses(0xD1B5_4A32_D192_ED03);
    let mut observation = measure(|| {
        let (mut admitted, mut refused) = (0, 0);
        for (index, address) in addresses.by_ref().take(1_000_000).enumerate() {
            // A second per ten thousand addresses: an evicted meter is ~0.4 s old when its debt
            // passes to the next address, so both verdicts keep occurring all the way through.
            if index % 10_000 == 0 {
                clock.advance_millis(1_000);
            }
            if decide(&governor, ClassKind::Unauthenticated, Some(address)) {
                admitted += 1;
            } else {
                refused += 1;
            }
        }
        (admitted, refused)
    });
    observation.tracked = governor.tracked_clients();
    (construction, observation)
}

fn run_isolated(test: &str) -> Vec<(String, Observation)> {
    let output = Command::new(std::env::current_exe().expect("test binary path"))
        .args(["--exact", test, "--nocapture", "--test-threads", "1"])
        .env(PROBE_ENV, "1")
        .output()
        .expect("isolated governor probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "isolated governor probe failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observations: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.find(SENTINEL).and_then(|start| line.get(start + SENTINEL.len()..)))
        .map(|line| {
            let (probe, rest) = line.split_once(' ').expect("probe line has a name");
            eprintln!("{SENTINEL}{line}");
            (probe.to_owned(), Observation::parse(rest))
        })
        .collect();
    assert!(!observations.is_empty(), "isolated governor probe emitted no observation:\n{stdout}");
    observations
}

fn find<'a>(observations: &'a [(String, Observation)], probe: &str) -> &'a Observation {
    &observations
        .iter()
        .find(|(name, _)| name == probe)
        .unwrap_or_else(|| panic!("probe {probe} reported nothing"))
        .1
}

fn assert_instrument_counts(observations: &[(String, Observation)]) {
    let control = find(observations, "control");
    assert!(
        control.blocks >= 1 && control.bytes >= 64,
        "the allocator did not observe a kept 64-byte box ({control:?}); a zero below would mean nothing"
    );
}

/// c-gov-0001: the synchronous decision path allocates zero heap blocks on one thread.
#[test]
fn c_gov_0001_the_synchronous_decision_path_allocates_nothing() {
    if std::env::var_os(PROBE_ENV).is_some() {
        println!("{}", control().line("control"));
        println!("{}", single_thread().line("single"));
        return;
    }
    let observations =
        run_isolated("ext::governor::allocation_tests::c_gov_0001_the_synchronous_decision_path_allocates_nothing");
    assert_instrument_counts(&observations);
    let single = find(&observations, "single");
    assert!(
        single.admitted > 0 && single.refused > 0,
        "the window must exercise both verdicts: {single:?}"
    );
    assert!(single.tracked > 0, "the window must insert first-seen addresses: {single:?}");
    assert_eq!(
        (single.blocks, single.bytes),
        (0, 0),
        "{} governor decisions allocated heap blocks: {single:?}",
        single.admitted + single.refused
    );
}

/// c-gov-0030: four contending threads still allocate zero heap blocks deciding.
#[test]
fn c_gov_0030_contended_decisions_allocate_nothing() {
    if std::env::var_os(PROBE_ENV).is_some() {
        println!("{}", control().line("control"));
        println!("{}", contended().line("contended"));
        return;
    }
    let observations = run_isolated("ext::governor::allocation_tests::c_gov_0030_contended_decisions_allocate_nothing");
    assert_instrument_counts(&observations);
    let contended = find(&observations, "contended");
    assert_eq!(contended.admitted + contended.refused, 4 * 4_096, "every decision ran inside the window");
    assert!(
        contended.admitted > 0 && contended.refused > 0,
        "the window must exercise both verdicts: {contended:?}"
    );
    assert_eq!(
        (contended.blocks, contended.bytes),
        (0, 0),
        "contended governor decisions allocated heap blocks: {contended:?}"
    );
}

/// c-gov-0013: a million distinct addresses neither allocate nor grow live heap past the bound.
///
/// Anonymous resident memory is asserted where `/proc/self/status` reports it. Nothing in the window allocates, so
/// the only pages it may make resident are the table's own, allocated at construction: the budget is
/// that allocation plus 64 KiB of stack and page-rounding slack, whatever the address count.
#[test]
fn c_gov_0013_a_million_addresses_do_not_grow_memory() {
    if std::env::var_os(PROBE_ENV).is_some() {
        println!("{}", control().line("control"));
        let (construction, million) = one_million_addresses();
        println!("{}", construction.line("construction"));
        println!("{}", million.line("million"));
        return;
    }
    let observations = run_isolated("ext::governor::allocation_tests::c_gov_0013_a_million_addresses_do_not_grow_memory");
    assert_instrument_counts(&observations);
    let construction = find(&observations, "construction");
    let million = find(&observations, "million");
    assert!(
        construction.bytes > 0,
        "building the governor allocates its bounded table: {construction:?}"
    );
    assert_eq!(million.admitted + million.refused, 1_000_000);
    assert!(
        million.admitted > 0 && million.refused > 0,
        "the window must exercise both verdicts: {million:?}"
    );
    assert_eq!(million.tracked, 4_096, "the address table stays at its bound: {million:?}");
    assert_eq!(
        (million.blocks, million.live_delta),
        (0, 0),
        "a million new addresses allocated or retained heap: {million:?}"
    );
    let budget = i128::from(construction.bytes) + 64 * 1024;
    match million.resident_delta {
        Some(delta) => assert!(
            delta <= budget,
            "a million new addresses grew the resident set by {delta} bytes, past the {budget}-byte table the governor allocated at construction plus 64 KiB: {million:?}"
        ),
        None => {
            eprintln!(
                "SKIP c-gov-0013 resident set: this platform reports no RssAnon in /proc/self/status; the heap assertion above still ran"
            )
        }
    }
}
