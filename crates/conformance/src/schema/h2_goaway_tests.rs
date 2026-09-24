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

//! Responsible for: versioned GOAWAY and socket receive-state expectation boundaries.
//! NOT responsible for: observing sockets or granting a reusable-connection guarantee.
//! Upstream: the case schema; downstream: schema acceptance and rejection controls.

use super::Schema;
fn valid(version: i64, expectation: &str, multiple: bool) -> bool {
    valid_kind(version, expectation, multiple, "kind = \"response\"\nstatus = 200")
}

fn valid_kind(version: i64, expectation: &str, multiple: bool, kind: &str) -> bool {
    let prefix = if multiple { "exchanges." } else { "" };
    let exchange = if multiple { "[[exchanges]]\n" } else { "" };
    let source = format!(
        r#"
[case]
id = "c-test-0001"
schema_version = {version}
title = "GOAWAY and receive termination"
rationale = "A connection shutdown announcement does not establish that the peer stopped sending."
polarity = "negative"
quirks = []
evidence = [{{ url = "https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8", summary = "Existing streams may complete after a shutdown announcement." }}]
{exchange}[{prefix}request]
method = "GET"
target = "/"
[{prefix}expect]
{kind}
{expectation}
"#
    );
    Schema::compile(include_str!("../../../../conformance/case.schema.json"))
        .expect("schema compiles")
        .validate(&crate::toml::parse(&source).expect("fixture TOML parses"))
        .is_empty()
}
const GOAWAY: &str = "h2_control_frames = [{ type = 'goaway', last_stream_id = 0, error_code = 4294967295 }]";
#[test]
fn version_four_accepts_goaway_and_receive_state_in_both_forms() {
    for multiple in [false, true] {
        assert!(valid(4, &format!("{GOAWAY}\nsocket_read_after = 'no_termination_observed'"), multiple));
    }
}
#[test]
fn legacy_versions_cannot_add_socket_receive_assertions() {
    for version in 1..=3 {
        for multiple in [false, true] {
            assert!(!valid(version, "socket_read_after = 'eof'", multiple));
        }
    }
}
#[test]
fn legacy_versions_cannot_add_goaway_assertions() {
    for version in 1..=3 {
        for multiple in [false, true] {
            assert!(!valid(version, GOAWAY, multiple));
        }
    }
}
#[test]
fn receive_state_rejects_reusability_words_and_non_strings() {
    for value in ["'open'", "'closed'", "'half_closed'", "'unknown'", "true", "0"] {
        assert!(!valid(4, &format!("socket_read_after = {value}"), false));
    }
}
#[test]
fn all_three_measured_receive_states_are_accepted() {
    for value in ["no_termination_observed", "eof", "reset"] {
        assert!(valid(4, &format!("socket_read_after = '{value}'"), false));
    }
}
#[test]
fn goaway_requires_its_own_bounded_fields_and_rejects_reset_fields() {
    for frame in [
        "{ type = 'goaway', error_code = 0 }",
        "{ type = 'goaway', last_stream_id = 0 }",
        "{ type = 'goaway', last_stream_id = -1, error_code = 0 }",
        "{ type = 'goaway', last_stream_id = 2147483648, error_code = 0 }",
        "{ type = 'goaway', last_stream_id = 0, error_code = -1 }",
        "{ type = 'goaway', last_stream_id = 0, error_code = 4294967296 }",
        "{ type = 'goaway', last_stream_id = 0, error_code = 0, stream_id = 1 }",
        "{ type = 'rst_stream', stream_id = 1, error_code = 0, last_stream_id = 0 }",
    ] {
        assert!(!valid(4, &format!("h2_control_frames = [{frame}]"), false), "{frame}");
    }
}
#[test]
fn extending_the_union_keeps_reset_stream_identifiers_required() {
    assert!(!valid(4, "h2_control_frames = [{ type = 'rst_stream', error_code = 0 }]", false));
}

#[test]
fn a_goaway_only_list_cannot_substantiate_stream_reset() {
    for multiple in [false, true] {
        assert!(!valid_kind(4, GOAWAY, multiple, "kind = 'stream_reset'"));
        let mixed = "h2_control_frames = [{ type = 'goaway', last_stream_id = 1, error_code = 0 }, { type = 'rst_stream', stream_id = 1, error_code = 8 }]";
        assert!(valid_kind(4, mixed, multiple, "kind = 'stream_reset'"));
    }
}

const GOAWAY_CODES: &str = "h2_control_frames = [{ type = 'goaway', last_stream_id = 0, error_code_any_of = [1, 2, 3] }]";

#[test]
fn version_four_accepts_explicit_goaway_code_alternatives_in_both_forms() {
    for multiple in [false, true] {
        assert!(valid(4, GOAWAY_CODES, multiple));
    }
}

#[test]
fn legacy_versions_cannot_add_goaway_code_alternatives() {
    for version in 1..=3 {
        for multiple in [false, true] {
            assert!(!valid(version, GOAWAY_CODES, multiple));
        }
    }
}

#[test]
fn goaway_code_alternatives_require_a_nonempty_unique_u32_array() {
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
        let expected = GOAWAY_CODES.replace("[1, 2, 3]", value);
        assert!(!valid(4, &expected, false), "{value}");
    }
}

#[test]
fn a_goaway_cannot_declare_both_exact_and_alternative_error_codes() {
    for exact in ["3", "'invalid'"] {
        let expected = GOAWAY_CODES.replace("last_stream_id = 0,", &format!("last_stream_id = 0, error_code = {exact},"));
        assert!(!valid(4, &expected, false));
    }
}

#[test]
fn code_alternatives_do_not_apply_to_other_received_frame_kinds() {
    for frame in [
        "{ type = 'rst_stream', stream_id = 1, error_code_any_of = [1, 2, 3] }",
        "{ type = 'rst_stream', stream_id = 1, error_code = 3, error_code_any_of = [1, 2, 3] }",
        "{ type = 'window_update', stream_id = 0, increment = 1, error_code_any_of = [1, 2, 3] }",
    ] {
        assert!(!valid(4, &format!("h2_control_frames = [{frame}]"), false));
    }
}

#[test]
fn authored_error_codes_cannot_use_received_goaway_alternatives() {
    let authored =
        "[[request.h2_frames]]\ntype = 'goaway'\nstream_id = 0\nerror_code = 'PROTOCOL_ERROR'\nerror_code_any_of = [1, 2, 3]";
    assert!(valid(4, &authored.replace("\nerror_code_any_of = [1, 2, 3]", ""), false));
    assert!(!valid(4, authored, false));
}
