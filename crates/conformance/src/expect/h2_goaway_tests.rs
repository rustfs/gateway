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

//! Responsible for: exact GOAWAY expectations and independent socket receive-state assertions.
//! NOT responsible for: producing frames or inferring connection reusability.
//! Upstream: observation facts; downstream: the expectation matcher.

use super::*;
use crate::observation::{ObservedH2ControlFrame, SocketReadState};

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, _: &str) -> Result<Vec<u8>, String> {
        Err("no golden".to_owned())
    }
}
fn facts() -> Observation {
    let mut seen = Observation::response(200, Vec::new(), Vec::new());
    seen.h2_control_frames = Some(vec![ObservedH2ControlFrame::GoAway {
        last_stream_id: 3,
        error_code: 8,
    }]);
    seen.socket_read_after = Some(SocketReadState::NoTerminationObserved);
    seen
}
fn clean(expected: &str, seen: &Observation) -> bool {
    judge(&crate::toml::parse(expected).expect("valid fixture"), seen, "/expect", &NoGoldens).is_clean()
}
const EXACT: &str = "h2_control_frames = [{ type = 'goaway', last_stream_id = 3, error_code = 8 }]";
#[test]
fn exact_goaway_facts_match() {
    assert!(clean(EXACT, &facts()));
}
#[test]
fn a_wrong_last_stream_id_fails() {
    assert!(!clean(&EXACT.replace("= 3", "= 1"), &facts()));
}
#[test]
fn a_wrong_goaway_error_code_fails() {
    assert!(!clean(&EXACT.replace("= 8", "= 0"), &facts()));
}
#[test]
fn an_extra_goaway_is_not_ignored() {
    let mut seen = facts();
    seen.h2_control_frames
        .as_mut()
        .expect("fixture list")
        .push(ObservedH2ControlFrame::GoAway {
            last_stream_id: 1,
            error_code: 0,
        });
    assert!(!clean(EXACT, &seen));
}
#[test]
fn missing_goaway_evidence_cannot_match() {
    for frames in [None, Some(Vec::new())] {
        let mut seen = facts();
        seen.h2_control_frames = frames;
        assert!(!clean(EXACT, &seen));
    }
}
#[test]
fn raw_receive_states_are_exact_and_unmeasured_never_matches() {
    let states = [
        SocketReadState::NoTerminationObserved,
        SocketReadState::Eof,
        SocketReadState::Reset,
    ];
    let labels = ["no_termination_observed", "eof", "reset"];
    for (index, state) in states.into_iter().enumerate() {
        for (expected_index, label) in labels.into_iter().enumerate() {
            let mut seen = facts();
            seen.socket_read_after = Some(state);
            assert_eq!(clean(&format!("socket_read_after = '{label}'"), &seen), index == expected_index);
            seen.socket_read_after = None;
            assert!(!clean(&format!("socket_read_after = '{label}'"), &seen));
        }
    }
}

const CODES: &str = "h2_control_frames = [{ type = 'goaway', last_stream_id = 3, error_code_any_of = [1, 2, 3] }]";

fn with_code(code: u32) -> Observation {
    let mut seen = facts();
    seen.h2_control_frames = Some(vec![ObservedH2ControlFrame::GoAway {
        last_stream_id: 3,
        error_code: code,
    }]);
    seen
}

#[test]
fn each_explicitly_allowed_goaway_code_matches() {
    for code in [1, 2, 3] {
        assert!(clean(CODES, &with_code(code)), "{code}");
    }
}

#[test]
fn unrelated_and_no_error_codes_do_not_match_the_alternatives() {
    for code in [0, 4, 8, u32::MAX] {
        assert!(!clean(CODES, &with_code(code)), "{code}");
    }
}

#[test]
fn a_numeric_code_remains_exact_even_when_generic_codes_are_permitted_elsewhere() {
    let exact = EXACT.replace("error_code = 8", "error_code = 3");
    assert!(clean(&exact, &with_code(3)));
    for code in [0, 1, 2, 8] {
        assert!(!clean(&exact, &with_code(code)), "{code}");
    }
}

#[test]
fn alternative_code_matching_preserves_frame_identity_scope_count_and_order() {
    assert!(!clean(&CODES.replace("last_stream_id = 3", "last_stream_id = 0"), &with_code(1)));
    let mut seen = with_code(1);
    seen.h2_control_frames = Some(vec![ObservedH2ControlFrame::ResetStream {
        stream_id: 3,
        error_code: 1,
    }]);
    assert!(!clean(CODES, &seen));
    seen.h2_control_frames = None;
    assert!(!clean(CODES, &seen));
    seen.h2_control_frames = Some(Vec::new());
    assert!(!clean(CODES, &seen));
    seen = with_code(1);
    seen.h2_control_frames
        .as_mut()
        .expect("fixture frames")
        .push(ObservedH2ControlFrame::GoAway {
            last_stream_id: 3,
            error_code: 2,
        });
    assert!(!clean(CODES, &seen));
    let ordered = "h2_control_frames = [{ type = 'goaway', last_stream_id = 3, error_code_any_of = [1, 2, 3] }, { type = 'goaway', last_stream_id = 1, error_code = 0 }]";
    seen.h2_control_frames = Some(vec![
        ObservedH2ControlFrame::GoAway {
            last_stream_id: 1,
            error_code: 0,
        },
        ObservedH2ControlFrame::GoAway {
            last_stream_id: 3,
            error_code: 1,
        },
    ]);
    assert!(!clean(ordered, &seen));
}

#[test]
fn invalid_alternatives_are_refused_even_without_schema_validation() {
    for value in [
        "[]",
        "[1, 1]",
        "1",
        "'1'",
        "['1']",
        "[true]",
        "[-1]",
        "[4294967296]",
        "[1, 2.5]",
    ] {
        assert!(!clean(&CODES.replace("[1, 2, 3]", value), &with_code(1)), "{value}");
    }
    for exact in ["1", "'invalid'"] {
        let expected = CODES.replace("last_stream_id = 3,", &format!("last_stream_id = 3, error_code = {exact},"));
        assert!(!clean(&expected, &with_code(1)));
    }
}

#[test]
fn an_alternative_code_does_not_satisfy_an_unobserved_eof() {
    let expected = format!("{CODES}\nsocket_read_after = 'eof'");
    let mut seen = with_code(1);
    assert!(!clean(&expected, &seen));
    seen.socket_read_after = Some(SocketReadState::Eof);
    assert!(clean(&expected, &seen));
}

#[test]
fn other_received_kinds_cannot_bypass_schema_with_alternative_codes() {
    let mut seen = with_code(1);
    seen.h2_control_frames = Some(vec![ObservedH2ControlFrame::ResetStream {
        stream_id: 3,
        error_code: 1,
    }]);
    assert!(!clean(
        "h2_control_frames = [{ type = 'rst_stream', stream_id = 3, error_code = 1, error_code_any_of = [1, 2, 3] }]",
        &seen
    ));
    seen.h2_control_frames = Some(vec![ObservedH2ControlFrame::WindowUpdate {
        stream_id: 0,
        increment: 1,
    }]);
    assert!(!clean(
        "h2_control_frames = [{ type = 'window_update', stream_id = 0, increment = 1, error_code_any_of = [1, 2, 3] }]",
        &seen
    ));
}

#[test]
fn wrong_typed_forbidden_fields_cannot_match_goaway_facts() {
    for field in ["stream_id", "increment"] {
        for value in ["'invalid'", "true", "[]", "{}", "1.5"] {
            let expected = EXACT.replace("last_stream_id = 3,", &format!("last_stream_id = 3, {field} = {value},"));
            assert!(
                !clean(&expected, &facts()),
                "forbidden field {field} = {value} must fail even without schema validation"
            );
            let judged = judge(&crate::toml::parse(&expected).expect("valid fixture"), &facts(), "/expect", &NoGoldens);
            assert!(
                judged.diagnostics.iter().any(|item| item.rule == "expect/h2_control_frames"),
                "forbidden field {field} = {value} must produce the control-frame diagnostic"
            );
        }
    }
}

#[test]
fn wrong_typed_forbidden_fields_cannot_match_goaway_alternative_facts() {
    for field in ["stream_id", "increment"] {
        for value in ["'invalid'", "true", "[]", "{}", "1.5"] {
            let expected = CODES.replace("last_stream_id = 3,", &format!("last_stream_id = 3, {field} = {value},"));
            let judged = judge(
                &crate::toml::parse(&expected).expect("valid fixture"),
                &with_code(1),
                "/expect",
                &NoGoldens,
            );
            assert!(
                judged.diagnostics.iter().any(|item| item.rule == "expect/h2_control_frames"),
                "forbidden field {field} = {value} must fail with alternative error codes"
            );
        }
    }
}
