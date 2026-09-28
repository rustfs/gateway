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
//! Responsible for: the version-5 boundary of authored PING frames, received PING
//! acknowledgements, and the `client_reset` outcome.
//! NOT responsible for: observing sockets or deciding when a reset was processed.
//! Upstream: the case schema; downstream: schema acceptance and rejection controls.

use super::Schema;

fn valid(version: i64, frames: &str, expectation: &str, multiple: bool) -> bool {
    let prefix = if multiple { "exchanges." } else { "" };
    let exchange = if multiple { "[[exchanges]]\n" } else { "" };
    let source = format!(
        r#"
[case]
id = "c-test-0001"
schema_version = {version}
title = "PING acknowledgements"
rationale = "A PING acknowledgement is the only wire fact that orders a peer's processing of earlier frames."
polarity = "positive"
quirks = []
evidence = [{{ url = "https://www.rfc-editor.org/rfc/rfc9113.html#section-6.7", summary = "A PING without ACK is answered with an ACK echoing its eight octets." }}]
{exchange}[{prefix}request]
method = "GET"
target = "/"
http_version = "h2"
{frames}
[{prefix}expect]
{expectation}
"#
    );
    Schema::compile(include_str!("../../../../conformance/case.schema.json"))
        .expect("schema compiles")
        .validate(&crate::toml::parse(&source).expect("fixture TOML parses"))
        .is_empty()
}

const PING_FRAME: &str = "h2_frames = [{ type = 'headers', stream_id = 1 }, { type = 'ping', payload_hex = '0102030405060708' }]";
const HEADERS_ONLY: &str = "h2_frames = [{ type = 'headers', stream_id = 1 }]";
const RESPONSE: &str = "kind = 'response'\nstatus = 200";
const ACK: &str = "h2_control_frames = [{ type = 'ping', payload_hex = '0102030405060708' }]";

#[test]
fn version_five_accepts_ping_frames_acknowledgements_and_client_reset() {
    for multiple in [false, true] {
        assert!(valid(5, PING_FRAME, &format!("{RESPONSE}\n{ACK}"), multiple));
        assert!(valid(5, PING_FRAME, &format!("kind = 'client_reset'\n{ACK}"), multiple));
        assert!(valid(5, PING_FRAME, &format!("kind = 'client_reset'\nstatus = 200\n{ACK}"), multiple));
    }
}

#[test]
fn earlier_versions_cannot_author_a_ping_frame() {
    for version in 1..=4 {
        for multiple in [false, true] {
            assert!(!valid(version, PING_FRAME, RESPONSE, multiple), "version {version}");
        }
    }
}

#[test]
fn earlier_versions_cannot_expect_an_acknowledgement_or_a_client_reset() {
    for multiple in [false, true] {
        assert!(!valid(4, HEADERS_ONLY, &format!("{RESPONSE}\n{ACK}"), multiple));
        assert!(!valid(4, HEADERS_ONLY, &format!("kind = 'client_reset'\n{ACK}"), multiple));
    }
    // Versions 1-3 already refuse every control-frame expectation and both HTTP/2 outcomes.
    for version in 1..=3 {
        assert!(!valid(version, HEADERS_ONLY, "kind = 'client_reset'", false));
    }
}

#[test]
fn a_client_reset_needs_an_acknowledgement_in_its_control_frames() {
    for expectation in [
        "kind = 'client_reset'",
        "kind = 'client_reset'\nh2_control_frames = []",
        "kind = 'client_reset'\nh2_control_frames = [{ type = 'goaway', last_stream_id = 0, error_code = 0 }]",
        "kind = 'client_reset'\nstream_termination = 'reset'\nbody_bytes_before_error = 0\nh2_control_frames = [{ type = 'ping', payload_hex = '0102030405060708' }]",
    ] {
        assert!(!valid(5, PING_FRAME, expectation, false), "{expectation}");
    }
}

#[test]
fn an_acknowledgement_is_exactly_eight_octets_and_nothing_else() {
    for frame in [
        "{ type = 'ping' }",
        "{ type = 'ping', payload_hex = '01020304050607' }",
        "{ type = 'ping', payload_hex = '010203040506070809' }",
        "{ type = 'ping', payload_hex = '01020304050607zz' }",
        "{ type = 'ping', payload_hex = '0102030405060708', stream_id = 0 }",
        "{ type = 'ping', payload_hex = '0102030405060708', error_code = 0 }",
        "{ type = 'rst_stream', stream_id = 1, error_code = 8, payload_hex = '0102030405060708' }",
        "{ type = 'goaway', last_stream_id = 0, error_code = 0, payload_hex = '0102030405060708' }",
        "{ type = 'window_update', stream_id = 0, increment = 1, payload_hex = '0102030405060708' }",
    ] {
        assert!(
            !valid(5, PING_FRAME, &format!("{RESPONSE}\nh2_control_frames = [{frame}]"), false),
            "{frame}"
        );
    }
}
