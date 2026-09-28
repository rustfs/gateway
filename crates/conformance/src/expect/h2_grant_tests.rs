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
//! Responsible for: matching connection-level WINDOW_UPDATE grants by presence and value, apart
//! from the ordered list of the other control frames a case asserts.
//! NOT responsible for: stream-level credit, which stays in the ordered list.
//! Upstream: typed wire observations; downstream: expectation regression tests.
//! Evidence: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2.1 — HTTP/2 does not specify
//! when a receiver sends WINDOW_UPDATE or what value it grants, so where a connection-level grant
//! falls among other frames, and whether an unasserted one is sent at all, is not a protocol fact.

use super::*;
use crate::observation::ObservedH2ControlFrame;

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, _: &str) -> Result<Vec<u8>, String> {
        Err("no golden".to_owned())
    }
}

const GRANT: ObservedH2ControlFrame = ObservedH2ControlFrame::WindowUpdate {
    stream_id: 0,
    increment: 7,
};
const GOAWAY: ObservedH2ControlFrame = ObservedH2ControlFrame::GoAway {
    last_stream_id: 0,
    error_code: 1,
};
const RESET: ObservedH2ControlFrame = ObservedH2ControlFrame::ResetStream {
    stream_id: 1,
    error_code: 8,
};

fn seen(frames: Vec<ObservedH2ControlFrame>) -> Observation {
    let mut seen = Observation::response(200, Vec::new(), Vec::new());
    seen.h2_control_frames = Some(frames);
    seen
}

fn clean(expected: &str, frames: Vec<ObservedH2ControlFrame>) -> bool {
    judge(&crate::toml::parse(expected).expect("fixture"), &seen(frames), "/expect", &NoGoldens).is_clean()
}

const GRANT_THEN_GOAWAY: &str =
    "h2_control_frames = [{ type='window_update', stream_id=0, increment=7 }, { type='goaway', last_stream_id=0, error_code=1 }]";
const GOAWAY_ONLY: &str = "h2_control_frames = [{ type='goaway', last_stream_id=0, error_code=1 }]";

#[test]
fn an_asserted_grant_matches_wherever_it_arrived() {
    assert!(clean(GRANT_THEN_GOAWAY, vec![GRANT, GOAWAY]));
    assert!(clean(GRANT_THEN_GOAWAY, vec![GOAWAY, GRANT]));
}

#[test]
fn an_unasserted_connection_grant_is_not_a_mismatch() {
    assert!(clean(GOAWAY_ONLY, vec![GRANT, GOAWAY]));
    assert!(clean(GOAWAY_ONLY, vec![GOAWAY, GRANT]));
    assert!(clean("h2_control_frames = []", vec![GRANT]));
}

#[test]
fn an_asserted_grant_that_never_arrived_fails() {
    assert!(!clean(GRANT_THEN_GOAWAY, vec![GOAWAY]));
    assert!(!clean(
        GRANT_THEN_GOAWAY,
        vec![
            GOAWAY,
            ObservedH2ControlFrame::WindowUpdate {
                stream_id: 0,
                increment: 8
            }
        ]
    ));
}

#[test]
fn each_asserted_grant_needs_its_own_received_grant() {
    let twice = "h2_control_frames = [{ type='window_update', stream_id=0, increment=7 }, { type='window_update', stream_id=0, increment=7 }]";
    assert!(!clean(twice, vec![GRANT]));
    assert!(clean(twice, vec![GRANT, GRANT]));
}

#[test]
fn stream_level_grants_stay_in_the_ordered_list() {
    let stream_grant = ObservedH2ControlFrame::WindowUpdate {
        stream_id: 1,
        increment: 5,
    };
    assert!(!clean(GOAWAY_ONLY, vec![stream_grant.clone(), GOAWAY]));
    let ordered = "h2_control_frames = [{ type='window_update', stream_id=1, increment=5 }, { type='goaway', last_stream_id=0, error_code=1 }]";
    assert!(clean(ordered, vec![stream_grant.clone(), GOAWAY]));
    assert!(!clean(ordered, vec![GOAWAY, stream_grant]));
}

#[test]
fn the_other_controls_stay_exact_and_ordered() {
    let both = "h2_control_frames = [{ type='rst_stream', stream_id=1, error_code=8 }, { type='goaway', last_stream_id=0, error_code=1 }]";
    assert!(clean(both, vec![GRANT, RESET, GOAWAY]));
    assert!(!clean(both, vec![GOAWAY, RESET]));
    assert!(!clean(both, vec![RESET]));
    assert!(!clean(both, vec![RESET, GOAWAY, GOAWAY]));
    assert!(!clean("h2_control_frames = []", vec![RESET]));
}

#[test]
fn an_unmeasured_list_still_fails() {
    let mut unmeasured = seen(Vec::new());
    unmeasured.h2_control_frames = None;
    let judged = judge(&crate::toml::parse(GOAWAY_ONLY).expect("fixture"), &unmeasured, "/expect", &NoGoldens);
    assert!(!judged.is_clean());
}
