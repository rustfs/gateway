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
//! # Why a second process and not a second window
//!
//! `dhat` profiles a whole process, and the tests in this binary run in parallel threads, so a
//! window opened in-place would count whatever the tests beside it were allocating at the time. A
//! second window opened after the first has been dropped is a question about `dhat`'s own
//! bookkeeping that a gate should not have to answer. One process per size, each measuring one
//! thing, is the arrangement with no such question in it.

use std::process::Command;
use std::sync::Arc;

use rustfs_gateway::{ClockSkewAck, S3Service};

use super::{Backend, Ping, fixed_clock, ping_route, wired};

/// The assembly every allocation gate exchanges against: `example:Ping`, one backend, a clock
/// fixed to the instant the signed fixtures were built at.
#[must_use]
pub fn probe_service() -> S3Service {
    wired()
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly")
}

/// Runs `test` as an isolated process with `env` set to `len`, and returns the `fields` numbers it
/// printed after `sentinel`.
///
/// # Panics
///
/// When the probe process fails, prints no sentinel line, or prints something after it that is not
/// `fields` whitespace-separated numbers. Every one of those is the shape that would otherwise turn
/// a gate into two zeroes compared against each other: a probe that crashed before it measured
/// anything, or one whose name no longer selects a test, exits successfully with no line to find.
#[must_use]
pub fn measure(test: &str, env: &str, sentinel: &str, len: usize, fields: usize) -> Vec<u64> {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let output = Command::new(executable)
        .args(["--exact", test, "--nocapture"])
        .env(env, len.to_string())
        .output()
        .expect("the isolated allocation probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the {len}-byte allocation probe failed:\n{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix(sentinel))
        .unwrap_or_else(|| panic!("the {len}-byte allocation probe measured nothing:\n{stdout}"));
    let numbers: Vec<u64> = line.split_whitespace().filter_map(|text| text.parse().ok()).collect();
    assert_eq!(
        numbers.len(),
        fields,
        "the {len}-byte allocation probe printed `{line}`, which is not {fields} numbers"
    );
    numbers
}
