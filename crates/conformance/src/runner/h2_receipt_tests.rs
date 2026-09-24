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

//! Responsible for: receipt validation on serial and concurrent scripted HTTP/2 observations.
//! NOT responsible for: concurrent elapsed-time aggregation or transport deadline measurement.
//! Upstream: runner dispatch and synthetic observations; downstream: per-exchange denial diagnostics.

use super::*;
use crate::observation::{DeadlineExpiry, Observation, Outcome};
use std::time::{Duration, Instant};

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, _: &str) -> Result<Vec<u8>, String> {
        Err("this fixture declares no golden".to_owned())
    }
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    Missing,
    WrongDeadline,
    FutureTimestamp,
    NonHang,
}

struct Target {
    fault: Fault,
    bad_index: usize,
    seen: Vec<usize>,
}

impl Target {
    fn observation(&mut self, plan: &ExchangePlan<'_>) -> Observation {
        self.seen.push(plan.index);
        let mut observed = Observation::response(200, Vec::new(), Vec::new());
        if plan.index != self.bad_index {
            return observed;
        }
        observed.outcome = Outcome::Hang;
        let deadline = plan.deadline.expect("explicit positive fixture budget");
        observed.deadline_expiry = match self.fault {
            Fault::Missing => None,
            Fault::WrongDeadline => Some(DeadlineExpiry {
                deadline: deadline - Duration::from_secs(20),
                observed_at: Instant::now(),
                harness_wait: Duration::ZERO,
            }),
            Fault::FutureTimestamp => Some(DeadlineExpiry {
                deadline,
                observed_at: deadline + Duration::from_secs(60),
                harness_wait: Duration::ZERO,
            }),
            Fault::NonHang => {
                observed.outcome = Outcome::Response;
                Some(DeadlineExpiry {
                    deadline,
                    observed_at: Instant::now(),
                    harness_wait: Duration::ZERO,
                })
            }
        };
        observed
    }
}

impl Sut for Target {
    fn describe(&self) -> String {
        "synthetic per-plan receipt controls".to_owned()
    }
    fn prepare(&mut self, _: &str, _: Option<&Value>) -> Result<Captures, SutError> {
        Ok(Captures::new())
    }
    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        Ok(self.observation(plan))
    }
    fn exchange_concurrent(&mut self, plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        // This fake supplies records only; it makes no claim to dispatch real network requests.
        Ok(plans.iter().map(|plan| self.observation(plan)).collect())
    }
}

fn fixture(concurrent: bool, bad_index: usize) -> Case {
    let mut case = super::tests::corpus()
        .cases()
        .iter()
        .find(|case| case.id == "c-h2-0003")
        .expect("real scripted HTTP/2 case metadata")
        .clone();
    let mut source = "[case]\nschema_version = 4\ntimeout_ms = 10000\n".to_owned();
    if concurrent {
        source.push_str("[connection]\nconcurrent = true\n");
    }
    for index in 0..if concurrent { 2 } else { 1 } {
        if concurrent {
            source.push_str("[[exchanges]]\n[exchanges.request]\n");
        } else {
            source.push_str("[request]\n");
        }
        source.push_str("method = 'GET'\ntarget = '/'\nhttp_version = 'h2'\nh2_frames = [{ type = 'settings' }]\n");
        source.push_str(if concurrent { "[exchanges.expect]\n" } else { "[expect]\n" });
        source.push_str(if index == bad_index {
            "kind = 'hang'\n"
        } else {
            "kind = 'response'\n"
        });
    }
    case.document = Some(crate::toml::parse(&source).expect("receipt fixture TOML"));
    case
}

fn denial(concurrent: bool, bad_index: usize, fault: Fault) {
    let mut target = Target {
        fault,
        bad_index,
        seen: Vec::new(),
    };
    let outcome = run_case(
        &fixture(concurrent, bad_index),
        &mut target,
        &RunOptions::default(),
        &NoGoldens,
        &mut Vec::new(),
    );
    assert_eq!(target.seen, if concurrent { vec![0, 1] } else { vec![0] });
    assert!(
        outcome
            .failures()
            .iter()
            .any(|failure| failure.rule == "runner/deadline-expiry"),
        "{fault:?}: {:?}",
        outcome.failures()
    );
    assert!(
        !outcome.failures().iter().any(|failure| failure.rule == "runner/timeout"),
        "this control must reject the receipt, not exceed the whole-case budget: {:?}",
        outcome.failures()
    );
    assert_eq!(outcome.verdict, Verdict::Failed);
}

#[test]
fn serial_scripted_hang_requires_a_receipt() {
    denial(false, 0, Fault::Missing);
}

#[test]
fn concurrent_scripted_hang_requires_a_receipt_for_each_position() {
    for index in [0, 1] {
        denial(true, index, Fault::Missing);
    }
}

#[test]
fn concurrent_wrong_deadline_is_denied_for_each_position() {
    for index in [0, 1] {
        denial(true, index, Fault::WrongDeadline);
    }
}

#[test]
fn concurrent_future_timestamp_is_denied_for_each_position() {
    for index in [0, 1] {
        denial(true, index, Fault::FutureTimestamp);
    }
}

#[test]
fn concurrent_non_hang_receipt_is_denied_for_each_position() {
    for index in [0, 1] {
        denial(true, index, Fault::NonHang);
    }
}

#[test]
fn valid_receipt_does_not_replace_independent_expectations() {
    let deadline = Instant::now();
    let returned_at = deadline + Duration::from_millis(1);
    let receipt = DeadlineExpiry {
        deadline,
        observed_at: deadline,
        harness_wait: Duration::ZERO,
    };
    let mut observed = Observation::response(200, Vec::new(), b"x".to_vec());
    observed.outcome = Outcome::Hang;
    observed.deadline_expiry = Some(receipt.clone());
    assert!(valid_expiry(&receipt, Some(deadline), &observed, returned_at));
    let matching = crate::toml::parse("kind = 'hang'\nstatus = 200").expect("matching expectation");
    assert!(
        expect::judge(&matching, &observed, "/expect", &NoGoldens)
            .diagnostics
            .is_empty()
    );
    for mismatching in ["kind = 'response'", "kind = 'hang'\nstatus = 201"] {
        let expectation = crate::toml::parse(mismatching).expect("mismatching expectation");
        assert!(
            expect::judge(&expectation, &observed, "/expect", &NoGoldens)
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Deny)
        );
    }
}
