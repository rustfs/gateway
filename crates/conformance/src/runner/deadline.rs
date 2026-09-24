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

//! Responsible for: case deadlines and validation of measured per-exchange expiry receipts.
//! NOT responsible for: driving sockets, judging response assertions, or concurrent time aggregation.
//! Upstream: the case runner; downstream: deadline diagnostics and bounded exchange plans.

use super::{Case, ExchangePlan, Value};

pub(super) fn case_deadline(
    started: std::time::Instant,
    timeout_ms: Option<i64>,
    harness_wait_ms: u64,
) -> Option<std::time::Instant> {
    let limit = u64::try_from(timeout_ms?).ok()?;
    started.checked_add(std::time::Duration::from_millis(limit.saturating_add(harness_wait_ms)))
}

pub(super) fn expiry_error(
    case: &Case,
    plan: &ExchangePlan<'_>,
    observed: &crate::observation::Observation,
    returned_at: std::time::Instant,
) -> Option<&'static str> {
    let scripted_hang = observed.outcome == crate::observation::Outcome::Hang
        && plan.request.read("requestSpec.h2_frames").is_some()
        && case
            .meta()
            .and_then(|meta| meta.read("caseMeta.schema_version"))
            .and_then(Value::as_integer)
            == Some(4);
    if scripted_hang {
        let budget = case
            .meta()
            .and_then(|meta| meta.read("caseMeta.timeout_ms"))
            .and_then(Value::as_integer);
        if !budget.is_some_and(|value| value > 0) {
            return Some("scripted HTTP/2 Hang requires an explicit positive case.timeout_ms");
        }
        if observed.deadline_expiry.is_none() {
            return Some("scripted HTTP/2 Hang requires a measured deadline-expiry receipt");
        }
    }
    observed.deadline_expiry.as_ref().and_then(|receipt| {
        (!valid_expiry(receipt, plan.deadline, observed, returned_at))
            .then_some("the reported deadline expiry does not match this exchange's measured clock")
    })
}

pub(super) fn valid_expiry(
    receipt: &crate::observation::DeadlineExpiry,
    deadline: Option<std::time::Instant>,
    observed: &crate::observation::Observation,
    returned_at: std::time::Instant,
) -> bool {
    observed.outcome == crate::observation::Outcome::Hang
        && deadline.and_then(|end| end.checked_add(receipt.harness_wait)) == Some(receipt.deadline)
        && receipt.observed_at >= receipt.deadline
        && receipt.observed_at <= returned_at
        && receipt.harness_wait.as_millis() <= u128::from(observed.harness_wait_ms)
}

/// The `case.timeout_ms` verdict: the diagnostic when the target's share of the case's wall time
/// exceeds the budget, `None` otherwise.
///
/// `harness_wait_ms` is subtracted from `elapsed_ms` before the comparison and both numbers are
/// printed, so a report reads "the target took N of the M the case took" rather than charging
/// the target for the harness's own pacing. A negative or absent budget budgets nothing.
pub(super) fn timeout_verdict(elapsed_ms: u64, harness_wait_ms: u64, limit_ms: i64) -> Option<String> {
    let limit = u64::try_from(limit_ms).ok()?;
    let target_ms = elapsed_ms.saturating_sub(harness_wait_ms);
    (target_ms > limit).then(|| {
        format!(
            "the target took {target_ms}ms of the {elapsed_ms}ms the case took ({harness_wait_ms}ms was the harness's \
             own waiting) and the case declares a {limit}ms budget"
        )
    })
}
