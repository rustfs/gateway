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

//! The `case.timeout_ms` verdict.
//!
//! Responsible for: proving the budget charges the target's share of the wall time and not the
//! harness's own waiting. NOT responsible for: measuring either, which the transports and the
//! runner do. Upstream: `super`. Downstream: Cargo's test harness.

use super::timeout_verdict;
/// Negative — the target's share over budget is a hang; positive — harness waiting alone is not,
/// however large; negative — a saturating subtraction cannot make the target look faster than
/// zero, and a budget that cannot be represented budgets nothing.
#[test]
fn the_timeout_verdict_charges_the_target_and_not_the_harness() {
    let over = timeout_verdict(12_000, 1_000, 10_000).expect("11s of target time over a 10s budget");
    assert!(over.contains("the target took 11000ms of the 12000ms"), "{over}");
    assert!(over.contains("1000ms was the harness's own waiting"), "{over}");
    assert!(over.contains("declares a 10000ms budget"), "{over}");
    assert_eq!(timeout_verdict(12_000, 3_000, 10_000), None, "9s of target time inside a 10s budget");
    assert_eq!(
        timeout_verdict(50_365, 49_000, 10_000),
        None,
        "c-cred-0006's shape: 100 observation windows"
    );
    assert_eq!(
        timeout_verdict(500, 9_000, 0),
        None,
        "harness waiting beyond the elapsed saturates to a zero target"
    );
    assert!(timeout_verdict(1, 0, 0).is_some(), "one millisecond of target time over a zero budget");
    assert_eq!(timeout_verdict(1, 0, -1), None, "a negative budget budgets nothing");
}
