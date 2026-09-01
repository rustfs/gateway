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

//! The isolated-probe harness every allocation gate in this binary runs through.
//!
//! Responsible for: running one test of this binary again as its own process at a chosen input
//! size, and reading back the numbers it printed — plus the `example:Ping` assembly those gates
//! send their requests to.
//! NOT responsible for: what any gate asserts about those numbers. Each gate owns its own
//! headroom, its own copies-allowed constant and its own floor, because each is a judgement about
//! a different path; sharing them would be sharing a conclusion rather than an instrument.
//! Upstream: `rustfs-gateway`. Downstream: `tests/request_allocations.rs`,
//! `tests/chunked_allocations.rs`.
//!
//! # Why a separate process, and how many
//!
//! `dhat` profiles a whole process, and the tests in this binary run in parallel threads, so a
//! window opened in place would count whatever the tests beside it were allocating at the time.
//! That is why the measurement is exiled to a process of its own, and it is not negotiable.
//!
//! *How many* processes is a different question, and rustfs/gateway#225 left it unanswered by
//! taking one per input size — a second window opened after the first was dropped being "a
//! question about `dhat`'s own bookkeeping that a gate should not have to answer". It is answered
//! now, because the answer is worth about twenty seconds of CI per gate. Measured both ways on the
//! `aws-chunked` probe at 64 KiB and 1 MiB:
//!
//! | | blocks | total bytes | peak bytes |
//! | --- | --- | --- | --- |
//! | two processes, difference between the sizes | 125 | 2,951,866 | 999,160 |
//! | two windows in one process, same difference | 125 | 2,951,962 | 999,160 |
//!
//! The block and peak differences are identical and the byte difference moves by 96 — allocator
//! state the second window inherits, four parts per hundred thousand of the quantity being
//! compared. Every gate here asserts on differences between sizes, never on an absolute, so a
//! probe may measure several sizes in one process. It must still be its own process.
//!
//! What does *not* follow is that two different gates may share one: each opens its own window
//! around its own exchange, and interleaving them would put one gate's allocations inside the
//! other's window.

use std::process::Command;
use std::sync::Arc;

use rustfs_gateway::{ClockSkewAck, S3Service};

use super::{Backend, Ping, fixed_clock, wired};

/// The assembly every allocation gate exchanges against: `example:Ping`, one backend, a clock
/// fixed to the instant the signed fixtures were built at.
#[must_use]
pub fn probe_service() -> S3Service {
    wired()
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&super::ping_dialect())
        .build()
        .expect("a complete assembly")
}

/// Runs `test` as an isolated process with `env` set to `sizes`, and returns the `fields` numbers
/// from each line it printed after `sentinel` — one line per size, in order.
///
/// # Panics
///
/// When the probe process fails, prints a different number of sentinel lines than there were
/// sizes, or prints something after one that is not `fields` whitespace-separated numbers. Every
/// one of those is the shape that would otherwise turn a gate into two zeroes compared against
/// each other: a probe that crashed before it measured anything, or one whose name no longer
/// selects a test, exits successfully with no line to find.
#[must_use]
pub fn measure(test: &str, env: &str, sentinel: &str, sizes: &[usize], fields: usize) -> Vec<Vec<u64>> {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let request = sizes.iter().map(usize::to_string).collect::<Vec<_>>().join(",");
    let output = Command::new(executable)
        .args(["--exact", test, "--nocapture"])
        .env(env, &request)
        .output()
        .expect("the isolated allocation probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the allocation probe for {request} failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<Vec<u64>> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(sentinel))
        .map(|line| line.split_whitespace().filter_map(|text| text.parse().ok()).collect())
        .collect();
    assert_eq!(
        rows.len(),
        sizes.len(),
        "the allocation probe for {request} printed {} measured lines, not {}:\n{stdout}",
        rows.len(),
        sizes.len()
    );
    for row in &rows {
        assert_eq!(
            row.len(),
            fields,
            "the allocation probe for {request} printed a line that is not {fields} numbers:\n{stdout}"
        );
    }
    rows
}

/// Parses the comma-separated sizes a probe process was asked for.
///
/// `None` when the variable is absent, which is how a probe test tells the two roles apart.
#[must_use]
pub fn requested_sizes(env: &str) -> Option<Vec<usize>> {
    let raw = std::env::var_os(env)?;
    Some(
        raw.to_string_lossy()
            .split(',')
            .map(|text| text.trim().parse().expect("a body size"))
            .collect(),
    )
}
