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

//! Responsible for: exit-code acceptance after complete selected transport comparison.
//! NOT responsible for: deriving case capabilities or parsing report observations.
//! Upstream: the parity CLI; downstream: child failure provenance controls.

use super::*;
use crate::parity::{CaseResult, Difference, SelectedComparison};

fn h2_only() -> SelectedComparison {
    SelectedComparison {
        case_count: 1,
        identical_count: 0,
        common_failures: Vec::new(),
        differences: Vec::new(),
        capability_differences: vec![Difference {
            id: "c-h2-0001".to_owned(),
            hyper: Some(CaseResult {
                verdict: "passed".to_owned(), phase: "execute".to_owned(),
                skip_reason: None, failures: Vec::new(),
            }),
            conn: Some(CaseResult {
                verdict: "skipped".to_owned(), phase: "execute".to_owned(),
                skip_reason: Some("environment: the production self-held driver speaks HTTP/1.1 only; authored HTTP/2 frames run on the production Hyper driver".to_owned()),
                failures: Vec::new(),
            }),
        }],
    }
}

#[test]
fn complete_h2_only_comparison_permits_the_conn_all_unsupported_exit() {
    assert!(validate_child_exit(Some(3), Transport::Conn, &h2_only()).is_ok());
}

#[test]
fn ordinary_measured_success_and_regression_exits_remain_accepted() {
    for transport in [Transport::Hyper, Transport::Conn] {
        for code in [0, 1] {
            assert!(validate_child_exit(Some(code), transport, &h2_only()).is_ok());
        }
    }
}

#[test]
fn hyper_environment_failure_and_other_failure_codes_are_not_capability_evidence() {
    assert!(validate_child_exit(Some(3), Transport::Hyper, &h2_only()).is_err());
    for status in [None, Some(2), Some(4), Some(124), Some(137)] {
        for transport in [Transport::Hyper, Transport::Conn] {
            assert!(validate_child_exit(status, transport, &h2_only()).is_err());
        }
    }
}

#[test]
fn mixed_or_empty_selection_does_not_explain_an_all_unsupported_exit() {
    let mut mixed = h2_only();
    mixed.case_count = 2;
    mixed.identical_count = 1;
    assert!(validate_child_exit(Some(3), Transport::Conn, &mixed).is_err());
    let empty = SelectedComparison {
        case_count: 0,
        identical_count: 0,
        common_failures: Vec::new(),
        differences: Vec::new(),
        capability_differences: Vec::new(),
    };
    assert!(validate_child_exit(Some(3), Transport::Conn, &empty).is_err());
}

#[test]
fn incomplete_or_failed_comparison_cannot_authorize_exit_three() {
    let mut missing = h2_only();
    missing.case_count = 2;
    assert!(validate_child_exit(Some(3), Transport::Conn, &missing).is_err());
    let mut failed = h2_only();
    failed.common_failures.push(Difference {
        id: "c-object-0001".to_owned(),
        hyper: None,
        conn: None,
    });
    assert!(validate_child_exit(Some(3), Transport::Conn, &failed).is_err());
    let mut differing = h2_only();
    differing.differences.push(Difference {
        id: "unexpected".to_owned(),
        hyper: None,
        conn: None,
    });
    assert!(validate_child_exit(Some(3), Transport::Conn, &differing).is_err());
}

#[test]
fn identical_count_alone_disqualifies_an_all_unsupported_exit() {
    let mut comparison = h2_only();
    // Keep the complete capability count and every other predicate unchanged to isolate this guard.
    comparison.identical_count = 1;
    assert!(validate_child_exit(Some(3), Transport::Conn, &comparison).is_err());
}
