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

//! Runner fixture-lifecycle regression tests.
//!
//! Responsible for: proving every path after successful preparation invokes cleanup and reports a
//! cleanup failure under its own rule. NOT responsible for: external endpoint fixture I/O or
//! judging protocol assertions. Upstream: `super::run_case`; downstream: no production code.

#![allow(clippy::expect_used)]

use super::*;
use crate::expect::GoldenSource;
use crate::interpolate::Captures;
use crate::observation::Observation;

struct NoGoldens;

impl GoldenSource for NoGoldens {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        Err(format!("this test declares no golden `{relative}`"))
    }
}

fn synthetic(id: &str, source: &str) -> Case {
    Case {
        id: id.to_owned(),
        domain: "synthetic".to_owned(),
        path: std::path::PathBuf::from(format!("cases/synthetic/{id}.toml")),
        relative: format!("cases/synthetic/{id}.toml"),
        document: Some(crate::toml::parse(source).expect("the test case is valid TOML")),
        diagnostics: Vec::new(),
    }
}

fn drive(case: &Case, sut: &mut dyn Sut) -> CaseOutcome {
    let mut notes = Vec::new();
    run_case(case, sut, &RunOptions::default(), &NoGoldens, &mut notes)
}

#[derive(Default)]
struct LifecycleSut {
    events: Vec<&'static str>,
    fail_exchange: bool,
    fail_concurrent: bool,
    fail_cleanup: bool,
}

impl Sut for LifecycleSut {
    fn describe(&self) -> String {
        "runner lifecycle test target".to_owned()
    }

    fn prepare(&mut self, _case_id: &str, _setup: Option<&Value>) -> Result<Captures, SutError> {
        self.events.push("prepare");
        Ok(Captures::new())
    }

    fn exchange(&mut self, _plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        self.events.push("exchange");
        if self.fail_exchange {
            return Err(SutError::Environment("authored exchange failed".to_owned()));
        }
        Ok(Observation::response(204, Vec::new(), Vec::new()))
    }

    fn exchange_concurrent(&mut self, _plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        self.events.push("concurrent");
        if self.fail_concurrent {
            return Err(SutError::Environment("concurrent dispatch failed".to_owned()));
        }
        Ok(vec![
            Observation::response(200, Vec::new(), Vec::new()),
            Observation::response(200, Vec::new(), Vec::new()),
        ])
    }

    fn finish(&mut self, _case_id: &str) -> Result<(), SutError> {
        self.events.push("finish");
        if self.fail_cleanup {
            return Err(SutError::Environment("fixture cleanup failed".to_owned()));
        }
        Ok(())
    }
}

const ONE_SUCCESSFUL_EXCHANGE: &str = r#"
[[exchanges]]
[exchanges.request]
method = "GET"
target = "/bucket"
[exchanges.expect]
kind = "response"
status = 204
"#;

const TWO_CONCURRENT_EXCHANGES: &str = r#"
[connection]
concurrent = true

[[exchanges]]
[exchanges.request]
method = "GET"
target = "/bucket/one"
[exchanges.expect]
kind = "response"
status = 200

[[exchanges]]
[exchanges.request]
method = "GET"
target = "/bucket/two"
[exchanges.expect]
kind = "response"
status = 200
"#;

/// Negative — an exchange environment error happens after fixture ownership was established, so
/// it cannot bypass cleanup merely because no observation exists to judge.
#[test]
fn an_exchange_error_after_prepare_still_finishes_the_case() {
    let case = synthetic("s-lifecycle-0001", ONE_SUCCESSFUL_EXCHANGE);
    let mut sut = LifecycleSut {
        fail_exchange: true,
        ..LifecycleSut::default()
    };
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Skipped);
    assert_eq!(sut.events, vec!["prepare", "exchange", "finish"]);
}

/// Negative — interpolation occurs after prepare and before the exchange seam. A missing capture
/// must therefore release fixtures even though the target never receives request bytes.
#[test]
fn an_interpolation_error_after_prepare_still_finishes_the_case() {
    let case = synthetic("s-lifecycle-0002", &ONE_SUCCESSFUL_EXCHANGE.replace("/bucket", "/${capture.missing}"));
    let mut sut = LifecycleSut::default();
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    assert_eq!(sut.events, vec!["prepare", "finish"]);
}

/// Negative — a concurrent target failure is another post-prepare early return and owns exactly
/// the same cleanup obligation as a serial exchange failure.
#[test]
fn a_concurrent_error_after_prepare_still_finishes_the_case() {
    let case = synthetic("s-lifecycle-0003", TWO_CONCURRENT_EXCHANGES);
    let mut sut = LifecycleSut {
        fail_concurrent: true,
        ..LifecycleSut::default()
    };
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Skipped);
    assert_eq!(sut.events, vec!["prepare", "concurrent", "finish"]);
}

/// Negative — cleanup affects the next case, so it is a named runner failure rather than a note
/// or an environment skip that can be hidden by a baseline.
#[test]
fn cleanup_failure_is_a_named_runner_failure() {
    let case = synthetic("s-lifecycle-0004", ONE_SUCCESSFUL_EXCHANGE);
    let mut sut = LifecycleSut {
        fail_cleanup: true,
        ..LifecycleSut::default()
    };
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    assert_eq!(sut.events, vec!["prepare", "exchange", "finish"]);
    let failure = outcome
        .failures()
        .into_iter()
        .find(|diagnostic| diagnostic.rule == "runner/cleanup")
        .expect("cleanup has its own runner rule");
    assert!(failure.message.contains("fixture cleanup failed"), "{failure}");
}

/// Negative — cleanup remains a first-class failure when the exchange itself returned no
/// observation; it must not disappear behind the environment skip produced for that exchange.
#[test]
fn cleanup_failure_after_an_exchange_error_is_still_named() {
    let case = synthetic("s-lifecycle-0005", ONE_SUCCESSFUL_EXCHANGE);
    let mut sut = LifecycleSut {
        fail_exchange: true,
        fail_cleanup: true,
        ..LifecycleSut::default()
    };
    let outcome = drive(&case, &mut sut);
    assert_eq!(outcome.verdict, Verdict::Failed);
    assert_eq!(sut.events, vec!["prepare", "exchange", "finish"]);
    assert!(
        outcome
            .failures()
            .iter()
            .any(|diagnostic| diagnostic.rule == "runner/cleanup")
    );
}
