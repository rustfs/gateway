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

#[cfg(feature = "production-transports")]
mod measured_h2_deadlines {
    use super::super::*;
    use crate::conn::Conn;
    use crate::observation::{Observation, Outcome};
    use crate::production::ProductionDriver;
    use std::time::Duration;

    struct NoGoldens;

    impl GoldenSource for NoGoldens {
        fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
            Err(format!("no golden declared: {relative}"))
        }
    }

    fn case(number: u8, replacement: Option<(&str, &str)>) -> Case {
        let id = format!("c-h2-{number:04}");
        let mut case = super::super::tests::corpus()
            .cases()
            .iter()
            .find(|case| case.id == id)
            .expect("the named real transport case exists")
            .clone();
        if let Some((old, new)) = replacement {
            let source = std::fs::read_to_string(&case.path).expect("case source");
            assert_eq!(source.matches(old).count(), 1, "one exact fixture replacement");
            case.document = Some(crate::toml::parse(&source.replacen(old, new, 1)).expect("modified case"));
        }
        case
    }

    fn drive(case: &Case, sut: &mut dyn Sut) -> CaseOutcome {
        run_case(case, sut, &RunOptions::default(), &NoGoldens, &mut Vec::new())
    }

    fn production(case: &Case) -> CaseOutcome {
        let root = Corpus::discover_root().expect("the real corpus is available");
        drive(case, &mut Conn::production(root, ProductionDriver::Hyper))
    }

    struct ObservedClock {
        inner: Conn,
        deadline: Option<std::time::Instant>,
        expiry: Option<crate::observation::DeadlineExpiry>,
    }

    impl Sut for ObservedClock {
        fn describe(&self) -> String {
            self.inner.describe()
        }
        fn prepare(&mut self, id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
            self.inner.prepare(id, setup)
        }
        fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
            self.deadline = plan.deadline;
            let observed = self.inner.exchange(plan)?;
            self.expiry = observed.deadline_expiry.clone();
            Ok(observed)
        }
        fn finish(&mut self, id: &str) -> Result<(), SutError> {
            self.inner.finish(id)
        }
    }

    // Positive: a real peer stops after one DATA byte because the client gave no more credit.
    #[test]
    fn a_measured_h2_stall_can_satisfy_the_authored_hang_expectation() {
        let root = Corpus::discover_root().expect("the real corpus is available");
        let mut target = ObservedClock {
            inner: Conn::production(root, ProductionDriver::Hyper),
            deadline: None,
            expiry: None,
        };
        let outcome = drive(&case(3, None), &mut target);
        assert_eq!(outcome.verdict, Verdict::Passed, "{:?}", outcome.failures());
        let receipt = target.expiry.expect("the real executor measured its expiry boundary");
        assert_eq!(Some(receipt.deadline), target.deadline.map(|end| end + receipt.harness_wait));
        assert!(receipt.observed_at >= receipt.deadline);
        assert!(receipt.observed_at <= std::time::Instant::now());
    }

    // Negative: accepting a measured timeout must not make every outcome count as a hang.
    #[test]
    fn a_complete_h2_response_does_not_satisfy_a_hang_expectation() {
        let outcome = production(&case(1, Some(("kind = \"response\"", "kind = \"hang\""))));
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert!(
            outcome.failures().iter().any(|failure| failure.rule == "expect/kind"),
            "{:?}",
            outcome.failures()
        );
    }

    // Negative: a stalled response cannot be reported as a completed response.
    #[test]
    fn a_measured_h2_stall_does_not_satisfy_a_response_expectation() {
        let outcome = production(&case(3, Some(("kind = \"hang\"", "kind = \"response\""))));
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert!(
            outcome.failures().iter().any(|failure| failure.rule == "expect/kind"),
            "{:?}",
            outcome.failures()
        );
    }

    struct LateHang(crate::observation::Outcome);

    impl Sut for LateHang {
        fn describe(&self) -> String {
            "a late synthetic outcome without a measured deadline".to_owned()
        }

        fn prepare(&mut self, _: &str, _: Option<&Value>) -> Result<Captures, SutError> {
            Ok(Captures::new())
        }

        fn exchange(&mut self, _: &ExchangePlan<'_>) -> Result<Observation, SutError> {
            std::thread::sleep(Duration::from_millis(50));
            let mut observed = Observation::response(501, Vec::new(), b"<".to_vec());
            observed.outcome = self.0;
            Ok(observed)
        }
    }

    // Negative: skipping the whole-case timeout check merely because kind=hang is unsound.
    #[test]
    fn an_unbounded_hang_report_still_fails_the_whole_case_budget() {
        let case = case(3, Some(("timeout_ms = 300", "timeout_ms = 5")));
        let outcome = drive(&case, &mut LateHang(Outcome::Hang));
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert!(
            outcome.failures().iter().any(|failure| failure.rule == "runner/timeout"),
            "{:?}",
            outcome.failures()
        );
    }
    #[test]
    fn a_late_normal_response_still_fails_the_whole_case_budget() {
        let case = case(3, Some(("timeout_ms = 300", "timeout_ms = 5")));
        let outcome = drive(&case, &mut LateHang(Outcome::Response));
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert!(outcome.failures().iter().any(|failure| failure.rule == "runner/timeout"));
    }
    // These synthetic observations isolate admission of Hang; real wire/head/body/credit
    // controls above and in the corpus remain unchanged.
    struct EarlyOutcome(Outcome);

    impl Sut for EarlyOutcome {
        fn describe(&self) -> String {
            "an early outcome without an expiry receipt".to_owned()
        }
        fn prepare(&mut self, _: &str, _: Option<&Value>) -> Result<Captures, SutError> {
            Ok(Captures::new())
        }
        fn exchange(&mut self, _: &ExchangePlan<'_>) -> Result<Observation, SutError> {
            let mut observed = Observation::response(204, Vec::new(), Vec::new());
            observed.outcome = self.0;
            Ok(observed)
        }
    }

    fn receipt_case(version: u8, timeout: Option<i64>, scripted: bool, kind: &str) -> Case {
        let mut fixture = case(3, None);
        let budget = timeout.map_or_else(String::new, |value| format!("timeout_ms = {value}"));
        let frames = if scripted {
            "http_version = 'h2'\nh2_frames = [{ type = 'settings', payload_hex = '000400000001' }]"
        } else {
            "http_version = 'http/1.1'"
        };
        fixture.document = Some(crate::toml::parse(&format!(
            "[case]\nschema_version = {version}\n{budget}\n[request]\nmethod = 'GET'\ntarget = '/'\n{frames}\n[expect]\nkind = '{kind}'"
        )).expect("receipt admission fixture"));
        fixture
    }

    #[test]
    fn v4_scripted_h2_hang_rejects_an_early_outcome_without_a_receipt() {
        let outcome = drive(&receipt_case(4, Some(10_000), true, "hang"), &mut EarlyOutcome(Outcome::Hang));
        assert_eq!(outcome.verdict, Verdict::Failed, "an early fabricated Hang must not pass");
        assert!(
            outcome.failures().iter().any(|failure| {
                failure.rule == "runner/deadline-expiry"
                    && failure.message.contains("requires a measured deadline-expiry receipt")
            }),
            "{:?}",
            outcome.failures()
        );
    }

    #[test]
    fn v4_scripted_h2_hang_requires_an_explicit_positive_budget() {
        for timeout in [None, Some(0), Some(-1)] {
            let outcome = drive(&receipt_case(4, timeout, true, "hang"), &mut EarlyOutcome(Outcome::Hang));
            assert_eq!(outcome.verdict, Verdict::Failed, "invalid budget {timeout:?}");
            assert!(
                outcome.failures().iter().any(|failure| {
                    failure.rule == "runner/deadline-expiry"
                        && failure.message.contains("requires an explicit positive case.timeout_ms")
                }),
                "budget {timeout:?}: {:?}",
                outcome.failures()
            );
        }
    }

    #[test]
    fn legacy_foreign_defect_hang_does_not_require_a_new_receipt() {
        for version in 1..=3 {
            for scripted in [false, true] {
                let outcome = drive(&receipt_case(version, Some(10_000), scripted, "hang"), &mut EarlyOutcome(Outcome::Hang));
                assert_eq!(
                    outcome.verdict,
                    Verdict::Passed,
                    "version {version}, scripted={scripted}: {:?}",
                    outcome.failures()
                );
            }
        }
    }

    #[test]
    fn v4_scripted_h2_delayed_complete_response_needs_no_expiry_receipt() {
        let outcome = production(&case(2, None));
        assert_eq!(outcome.verdict, Verdict::Passed, "{:?}", outcome.failures());
    }

    struct RecordedClock {
        expire: bool,
        deadlines: Vec<std::time::Instant>,
        remaining: Vec<i64>,
    }

    impl Sut for RecordedClock {
        fn describe(&self) -> String {
            "recorded monotonic case clock".to_owned()
        }
        fn prepare(&mut self, _: &str, _: Option<&Value>) -> Result<Captures, SutError> {
            Ok(Captures::new())
        }
        fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
            let deadline = plan.deadline.expect("runner supplies the case deadline");
            self.deadlines.push(deadline);
            self.remaining.push(plan.timeout_ms.expect("remaining budget"));
            let mut observed = Observation::response(204, Vec::new(), Vec::new());
            if self.expire {
                std::thread::sleep(deadline.saturating_duration_since(std::time::Instant::now()));
                observed.outcome = Outcome::Hang;
                observed.deadline_expiry = Some(crate::observation::DeadlineExpiry {
                    deadline,
                    observed_at: std::time::Instant::now(),
                    harness_wait: Duration::ZERO,
                });
            } else {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(observed)
        }
    }

    fn two_exchanges(first_kind: &str, timeout_ms: u32) -> Case {
        let mut case = case(3, None);
        case.document = Some(
            crate::toml::parse(&format!(
                r#"
[case]
timeout_ms = {timeout_ms}
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/"
[exchanges.expect]
kind = "{first_kind}"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/"
[exchanges.expect]
kind = "response"
"#
            ))
            .expect("two clock-control exchanges"),
        );
        case
    }

    #[test]
    fn later_exchanges_cannot_receive_a_fresh_whole_case_budget() {
        let mut target = RecordedClock {
            expire: false,
            deadlines: Vec::new(),
            remaining: Vec::new(),
        };
        let outcome = drive(&two_exchanges("response", 1000), &mut target);
        assert_eq!(outcome.verdict, Verdict::Passed, "{:?}", outcome.failures());
        assert_eq!(target.deadlines.len(), 2);
        assert_eq!(target.deadlines[0], target.deadlines[1]);
        assert!(target.remaining[1] <= target.remaining[0] - 10, "{:?}", target.remaining);
    }

    #[test]
    fn an_expired_case_cannot_execute_a_later_request() {
        let mut target = RecordedClock {
            expire: true,
            deadlines: Vec::new(),
            remaining: Vec::new(),
        };
        let outcome = drive(&two_exchanges("hang", 40), &mut target);
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert_eq!(target.deadlines.len(), 1, "no request after the observed expiry");
        assert!(outcome.failures().iter().any(|failure| failure.rule == "runner/timeout"));
    }
    #[test]
    fn a_late_response_cannot_start_another_request_after_the_case_deadline() {
        let mut target = RecordedClock {
            expire: false,
            deadlines: Vec::new(),
            remaining: Vec::new(),
        };
        let outcome = drive(&two_exchanges("response", 5), &mut target);
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert_eq!(target.deadlines.len(), 1, "a late normal response also exhausts the case clock");
        assert!(outcome.failures().iter().any(|failure| failure.rule == "runner/timeout"));
    }
}

// Positive plus independent negative controls for the monotonic receipt boundary. These use fixed
// relative instants, so scheduler timing cannot turn a forged receipt into an accepted one.
#[test]
fn deadline_expiry_requires_the_exact_clock_outcome_and_measured_wait() {
    use crate::observation::{DeadlineExpiry, Observation, Outcome};
    use std::time::{Duration, Instant};

    let deadline = Instant::now();
    let wait = Duration::from_millis(7);
    let returned = deadline + Duration::from_millis(10);
    let receipt = DeadlineExpiry {
        deadline: deadline + wait,
        observed_at: deadline + Duration::from_millis(8),
        harness_wait: wait,
    };
    let mut observed = Observation::response(200, Vec::new(), Vec::new());
    observed.outcome = Outcome::Hang;
    observed.harness_wait_ms = 7;
    assert!(super::valid_expiry(&receipt, Some(deadline), &observed, returned));
    assert!(!super::valid_expiry(&receipt, None, &observed, returned));
    assert!(!super::valid_expiry(&receipt, Some(deadline + wait), &observed, returned));
    let mut forged = receipt.clone();
    forged.observed_at = deadline;
    assert!(!super::valid_expiry(&forged, Some(deadline), &observed, returned));
    forged.observed_at = returned + wait;
    assert!(!super::valid_expiry(&forged, Some(deadline), &observed, returned));
    observed.harness_wait_ms = 0;
    assert!(!super::valid_expiry(&receipt, Some(deadline), &observed, returned));
    observed.harness_wait_ms = 7;
    observed.outcome = Outcome::Response;
    assert!(!super::valid_expiry(&receipt, Some(deadline), &observed, returned));
    assert_eq!(receipt.deadline(), deadline + wait);
    assert_eq!(receipt.observed_at(), deadline + Duration::from_millis(8));
}

// rustfs/gateway#928: the case clock starts when the first request is dispatched, so the harness's
// own preparation — however long a loaded host makes it — cannot expire the case before the target
// is asked anything.
mod first_dispatch {
    use super::super::*;
    use crate::observation::Observation;
    use std::time::{Duration, Instant};

    struct Recorded {
        dispatched: Vec<Instant>,
    }

    impl Sut for Recorded {
        fn describe(&self) -> String {
            "records each dispatch".to_owned()
        }
        fn prepare(&mut self, _: &str, _: Option<&Value>) -> Result<Captures, SutError> {
            Ok(Captures::new())
        }
        fn exchange(&mut self, _: &ExchangePlan<'_>) -> Result<Observation, SutError> {
            self.dispatched.push(Instant::now());
            std::thread::sleep(Duration::from_millis(20));
            Ok(Observation::response(204, Vec::new(), Vec::new()))
        }
    }

    struct NoGoldens;
    impl GoldenSource for NoGoldens {
        fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
            Err(format!("no golden declared: {relative}"))
        }
    }

    /// A request large enough that interpolating it — harness work before dispatch — takes longer
    /// than the whole 1 ms case budget on any host.
    fn case_with_slow_preparation() -> Case {
        let mut case = super::super::tests::corpus().cases()[0].clone();
        let target = format!("/{}", "a".repeat(4 << 20));
        case.document = Some(
            crate::toml::parse(&format!(
                "[case]\ntimeout_ms = 1\n[[exchanges]]\n[exchanges.request]\nmethod = \"GET\"\ntarget = \"{target}\"\n\
                 [exchanges.expect]\nkind = \"response\"\n[[exchanges]]\n[exchanges.request]\nmethod = \"GET\"\n\
                 target = \"/\"\n[exchanges.expect]\nkind = \"response\"\n"
            ))
            .expect("the fixture parses"),
        );
        case
    }

    /// Negative and positive — preparation is not the target's time: the first request is always
    /// dispatched, and the target's own 20 ms against a 1 ms budget still fails the case and stops
    /// the second request.
    #[test]
    fn slow_preparation_cannot_expire_the_case_before_the_first_dispatch() {
        let mut target = Recorded { dispatched: Vec::new() };
        let outcome = run_case(
            &case_with_slow_preparation(),
            &mut target,
            &RunOptions::default(),
            &NoGoldens,
            &mut Vec::new(),
        );
        assert_eq!(target.dispatched.len(), 1, "the first request is dispatched, the second is not");
        assert_eq!(outcome.verdict, Verdict::Failed);
        assert!(outcome.failures().iter().any(|failure| failure.rule == "runner/timeout"));
    }
}
