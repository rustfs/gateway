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
//! Responsible for: exact PING-acknowledgement expectations and the `client_reset` outcome.
//! NOT responsible for: producing frames or deciding when a client reset was processed.
//! Upstream: observation facts; downstream: the expectation matcher.

use super::*;
use crate::observation::{ObservedH2ControlFrame, Outcome};

struct NoGoldens;
impl GoldenSource for NoGoldens {
    fn read_golden(&self, _: &str) -> Result<Vec<u8>, String> {
        Err("no golden".to_owned())
    }
}

fn facts(outcome: Outcome) -> Observation {
    let mut seen = Observation::response(200, Vec::new(), Vec::new());
    seen.outcome = outcome;
    seen.h2_control_frames = Some(vec![ObservedH2ControlFrame::PingAck {
        opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
    }]);
    seen
}

fn clean(expected: &str, seen: &Observation) -> bool {
    judge(&crate::toml::parse(expected).expect("valid fixture"), seen, "/expect", &NoGoldens).is_clean()
}

const ACK: &str = "h2_control_frames = [{ type = 'ping', payload_hex = '0102030405060708' }]";

#[test]
fn an_exact_acknowledgement_and_client_reset_match() {
    assert!(clean(&format!("kind = 'client_reset'\n{ACK}"), &facts(Outcome::ClientReset)));
    assert!(clean(ACK, &facts(Outcome::Response)));
}

#[test]
fn different_opaque_octets_fail() {
    assert!(!clean(&ACK.replace("08'", "09'"), &facts(Outcome::Response)));
    assert!(!clean(&ACK.replace("08'", "0809'"), &facts(Outcome::Response)));
}

#[test]
fn client_reset_is_not_confused_with_other_endings() {
    for other in [Outcome::Response, Outcome::Hang, Outcome::StreamReset] {
        assert!(!clean(&format!("kind = 'client_reset'\n{ACK}"), &facts(other)), "{other:?}");
    }
    assert!(!clean(&format!("kind = 'response'\n{ACK}"), &facts(Outcome::ClientReset)));
}

#[test]
fn an_acknowledgement_is_not_another_control_frame() {
    for expected in [
        "h2_control_frames = [{ type = 'goaway', last_stream_id = 0, error_code = 0 }]",
        "h2_control_frames = [{ type = 'ping', payload_hex = '0102030405060708', stream_id = 0 }]",
        "h2_control_frames = [{ type = 'goaway', last_stream_id = 0, error_code = 0, payload_hex = '0102030405060708' }]",
        "h2_control_frames = []",
    ] {
        assert!(!clean(expected, &facts(Outcome::Response)), "{expected}");
    }
}
