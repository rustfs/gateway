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

//! Exact ordered matching of measured HTTP/2 control frames; initially RST_STREAM only.
//! Responsible for: rejecting missing observations, wrong reset facts, and accidental prefix matches.
//! The list covers supported control types only; it never claims to capture all received frames.
//! NOT responsible for: obtaining bytes from a socket or interpreting application event streams.
//! Upstream: `super::judge`; downstream: conformance expectation regression tests.

use super::*;
use crate::observation::{ObservedH2ControlFrame, Outcome};

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, _relative: &str) -> Result<Vec<u8>, String> {
        Err("no golden in this test".to_owned())
    }
}

fn facts(resets: Option<Vec<ObservedH2ControlFrame>>) -> Observation {
    let mut observed = Observation::response(200, Vec::new(), Vec::new());
    observed.h2_control_frames = resets;
    observed
}

fn check(source: &str, observed: &Observation) -> Judgement {
    let expect = crate::toml::parse(source).expect("valid expectation");
    judge(&expect, observed, "/expect", &NoGoldens)
}

const EXACT: &str = r#"kind = "response"
h2_control_frames = [{ type = "rst_stream", stream_id = 3, error_code = 7 }, { type = "rst_stream", stream_id = 1, error_code = 8 }]
"#;

fn resets() -> Vec<ObservedH2ControlFrame> {
    vec![
        ObservedH2ControlFrame::ResetStream {
            stream_id: 3,
            error_code: 7,
        },
        ObservedH2ControlFrame::ResetStream {
            stream_id: 1,
            error_code: 8,
        },
    ]
}

#[test]
fn exact_reset_facts_match_without_reusing_s3_error_or_event_fields() {
    assert!(check(EXACT, &facts(Some(resets()))).is_clean());
}

#[test]
fn absent_reset_observation_fails_even_an_expected_empty_list() {
    for source in [EXACT, "kind = \"response\"\nh2_control_frames = []\n"] {
        let judged = check(source, &facts(None));
        assert!(!judged.is_clean(), "unmeasured cannot mean no reset");
        assert!(judged.diagnostics.iter().any(|item| item.rule == "expect/h2_control_frames"));
    }
}

#[test]
fn measured_no_reset_matches_only_an_empty_expectation() {
    assert!(check("kind = \"response\"\nh2_control_frames = []\n", &facts(Some(Vec::new()))).is_clean());
    assert!(!check(EXACT, &facts(Some(Vec::new()))).is_clean());
    assert!(!check("kind = \"response\"\nh2_control_frames = []\n", &facts(Some(resets()))).is_clean());
}

#[test]
fn a_different_stream_id_fails_even_when_the_error_codes_match() {
    let mut observed = resets();
    observed[0] = ObservedH2ControlFrame::ResetStream {
        stream_id: 5,
        error_code: 7,
    };
    assert!(!check(EXACT, &facts(Some(observed))).is_clean());
}

#[test]
fn a_different_error_code_fails_even_when_the_stream_ids_match() {
    let mut observed = resets();
    observed[0] = ObservedH2ControlFrame::ResetStream {
        stream_id: 3,
        error_code: 8,
    };
    assert!(!check(EXACT, &facts(Some(observed))).is_clean());
}

#[test]
fn reset_order_is_not_treated_as_a_set() {
    let mut observed = resets();
    observed.reverse();
    assert!(!check(EXACT, &facts(Some(observed))).is_clean());
}

#[test]
fn missing_and_extra_resets_cannot_match_a_prefix() {
    let mut missing = resets();
    missing.pop();
    let mut extra = resets();
    extra.push(ObservedH2ControlFrame::ResetStream {
        stream_id: 5,
        error_code: 2,
    });
    for observed in [missing, extra] {
        assert!(!check(EXACT, &facts(Some(observed))).is_clean());
    }
}

#[test]
fn numeric_unknown_codes_match_without_collapsing_to_a_known_name() {
    let source = "kind = \"response\"\nh2_control_frames = [{ type = \"rst_stream\", stream_id = 1, error_code = 4294967295 }]\n";
    let observed = vec![ObservedH2ControlFrame::ResetStream {
        stream_id: 1,
        error_code: u32::MAX,
    }];
    assert!(check(source, &facts(Some(observed))).is_clean());
}

#[test]
fn a_tcp_connection_reset_cannot_satisfy_a_pre_header_stream_reset_kind() {
    let mut observed = facts(Some(Vec::new()));
    observed.outcome = Outcome::ConnectionReset;
    observed.status = None;
    let judged = check(
        "kind = \"stream_reset\"\nh2_control_frames = [{ type = \"rst_stream\", stream_id = 1, error_code = 8 }]\n",
        &observed,
    );
    assert!(judged.diagnostics.iter().any(|item| item.rule == "expect/kind"));
    assert!(judged.diagnostics.iter().any(|item| item.rule == "expect/h2_control_frames"));
}

#[test]
fn a_missing_expectation_does_not_require_reset_capability() {
    assert!(check("kind = \"response\"\n", &facts(None)).is_clean());
}

#[test]
fn an_unsupported_control_type_cannot_match_only_by_stream_and_error_code() {
    let expected = EXACT.replace("rst_stream", "unknown_control");
    assert!(!check(&expected, &facts(Some(resets()))).is_clean());
}

#[test]
fn wrong_typed_forbidden_fields_cannot_match_reset_facts() {
    let observed = facts(Some(resets()));
    for field in ["last_stream_id", "increment"] {
        for value in ["'invalid'", "true", "[]", "{}", "1.5"] {
            let expected = EXACT.replacen("stream_id = 3,", &format!("stream_id = 3, {field} = {value},"), 1);
            let judged = check(&expected, &observed);
            assert!(
                judged.diagnostics.iter().any(|item| item.rule == "expect/h2_control_frames"),
                "forbidden field {field} = {value} must fail even without schema validation"
            );
        }
    }
}
