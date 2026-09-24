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

//! Responsible for: exact received WINDOW_UPDATE expectations, including connection scope.
//! NOT responsible for: sending frames or inventing credit from application intent.
//! Upstream: typed wire observations; downstream: expectation regression tests.

use super::*;
use crate::observation::ObservedH2ControlFrame;
struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, _: &str) -> Result<Vec<u8>, String> {
        Err("no golden".to_owned())
    }
}
fn facts() -> Observation {
    let mut seen = Observation::response(200, Vec::new(), Vec::new());
    seen.h2_control_frames = Some(vec![
        ObservedH2ControlFrame::WindowUpdate {
            stream_id: 0,
            increment: 7,
        },
        ObservedH2ControlFrame::ResetStream {
            stream_id: 3,
            error_code: 8,
        },
        ObservedH2ControlFrame::WindowUpdate {
            stream_id: 1,
            increment: 11,
        },
    ]);
    seen
}
const EXACT: &str = "h2_control_frames = [{ type='window_update', stream_id=0, increment=7 }, { type='rst_stream',stream_id=3,error_code=8 }, { type='window_update',stream_id=1,increment=11 }]";
fn clean(expected: &str, seen: &Observation) -> bool {
    judge(&crate::toml::parse(expected).expect("fixture"), seen, "/expect", &NoGoldens).is_clean()
}
#[test]
fn exact_window_scope_increment_and_mixed_order_match() {
    assert!(clean(EXACT, &facts()));
}
#[test]
fn a_wrong_window_scope_fails() {
    assert!(!clean(&EXACT.replace("stream_id=0", "stream_id=1"), &facts()));
}
#[test]
fn a_wrong_window_increment_fails() {
    assert!(!clean(&EXACT.replace("increment=7", "increment=8"), &facts()));
}
#[test]
fn reordered_window_controls_cannot_match_as_a_set() {
    let mut seen = facts();
    seen.h2_control_frames.as_mut().expect("fixture").reverse();
    assert!(!clean(EXACT, &seen));
}
#[test]
fn missing_or_extra_window_controls_are_not_ignored() {
    for count in [0, 2, 4] {
        let mut seen = facts();
        let frames = seen.h2_control_frames.as_mut().expect("fixture");
        frames.resize(
            count,
            ObservedH2ControlFrame::WindowUpdate {
                stream_id: 0,
                increment: 1,
            },
        );
        assert!(!clean(EXACT, &seen));
    }
    let mut seen = facts();
    seen.h2_control_frames = None;
    assert!(!clean(EXACT, &seen));
}

#[test]
fn wrong_typed_forbidden_fields_cannot_match_window_facts() {
    for field in ["last_stream_id", "error_code"] {
        for value in ["'invalid'", "true", "[]", "{}", "1.5"] {
            let expected = EXACT.replacen("increment=7", &format!("increment=7, {field}={value}"), 1);
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
