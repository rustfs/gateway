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

//! Schema boundaries for ordered HTTP/2 control-frame expectations; initially RST_STREAM only.
//! Responsible for: keeping new reset observations in version 4 while retaining older case meanings.
//! The list covers supported control types only; it never claims to capture all received frames.
//! NOT responsible for: implementing resets or treating a schema-valid case as an executed case.
//! Upstream: the frozen case schema; downstream: conformance schema validation tests.

use super::Schema;
use crate::toml;

fn document(version: i64, expectation: &str, multiple: bool) -> String {
    let prefix = if multiple { "exchanges." } else { "" };
    let exchange = if multiple { "[[exchanges]]\n" } else { "" };
    format!(
        r#"
[case]
id = "c-test-0001"
schema_version = {version}
title = "Received HTTP/2 reset facts"
rationale = "The reset frame and its numeric fields are observations distinct from connection termination."
polarity = "negative"
quirks = []
evidence = [{{ url = "https://www.rfc-editor.org/rfc/rfc9113.html#section-6.4", summary = "A reset terminates its identified stream and carries a numeric reason." }}]
{exchange}[{prefix}request]
method = "GET"
target = "/"
http_version = "h2"
[{prefix}expect]
{expectation}
"#
    )
}

fn violations(version: i64, expectation: &str, multiple: bool) -> Vec<super::Violation> {
    let schema = Schema::compile(include_str!("../../../../conformance/case.schema.json")).expect("repository schema compiles");
    schema.validate(&toml::parse(&document(version, expectation, multiple)).expect("valid test TOML"))
}

const RESET: &str = r#"kind = "stream_reset"
h2_control_frames = [{ type = "rst_stream", stream_id = 1, error_code = 8 }]
"#;

#[test]
fn version_four_accepts_reset_facts_in_single_and_multi_exchange_forms() {
    assert_eq!(super::SCHEMA_VERSION, 4);
    assert_eq!(super::MIN_SCHEMA_VERSION, 1);
    for multiple in [false, true] {
        let found = violations(4, RESET, multiple);
        assert!(found.is_empty(), "{found:?}");
    }
}

#[test]
fn earlier_versions_cannot_acquire_reset_observation_expectations() {
    for version in 1..=3 {
        for multiple in [false, true] {
            let found = violations(version, "kind = \"response\"\nstatus = 200\nh2_control_frames = []\n", multiple);
            assert!(found.iter().any(|item| item.pointer.ends_with("h2_control_frames")), "{found:?}");
        }
    }
}

#[test]
fn earlier_versions_cannot_claim_the_new_pre_header_reset_outcome() {
    for version in 1..=3 {
        for multiple in [false, true] {
            let found = violations(version, RESET, multiple);
            assert!(found.iter().any(|item| item.pointer.ends_with("kind")), "{found:?}");
        }
    }
}

#[test]
fn legacy_response_expectations_remain_valid_in_all_supported_versions() {
    for version in 1..=4 {
        for multiple in [false, true] {
            let found = violations(version, "kind = \"response\"\nstatus = 200\n", multiple);
            assert!(found.is_empty(), "version {version}: {found:?}");
        }
    }
}

#[test]
fn no_reset_is_explicitly_measurable_without_requiring_a_nonempty_list() {
    let found = violations(4, "kind = \"response\"\nstatus = 200\nh2_control_frames = []\n", false);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_stream_reset_outcome_requires_a_reset_fact_and_forbids_a_response_head() {
    for expected in [
        "kind = \"stream_reset\"\n",
        "kind = \"stream_reset\"\nh2_control_frames = []\n",
        "kind = \"stream_reset\"\nstatus = 200\nh2_control_frames = [{ type = \"rst_stream\", stream_id = 1, error_code = 8 }]\n",
    ] {
        assert!(!violations(4, expected, false).is_empty(), "{expected}");
    }
}

#[test]
fn reset_fact_fields_are_required_bounded_and_not_extensible_by_accident() {
    for fact in [
        "{ type = \"rst_stream\", stream_id = 1 }",
        "{ type = \"rst_stream\", error_code = 8 }",
        "{ stream_id = 1, error_code = 8 }",
        "{ type = \"unknown_control\", stream_id = 1, error_code = 8 }",
        "{ type = \"rst_stream\", stream_id = 0, error_code = 8 }",
        "{ type = \"rst_stream\", stream_id = -1, error_code = 8 }",
        "{ type = \"rst_stream\", stream_id = 2147483648, error_code = 8 }",
        "{ type = \"rst_stream\", stream_id = 1, error_code = -1 }",
        "{ type = \"rst_stream\", stream_id = 1, error_code = 4294967296 }",
        "{ type = \"rst_stream\", stream_id = 1, error_code = \"CANCEL\" }",
        "{ type = \"rst_stream\", stream_id = 1, error_code = 8, status = 200 }",
    ] {
        let expected = format!("kind = \"response\"\nstatus = 200\nh2_control_frames = [{fact}]\n");
        assert!(!violations(4, &expected, false).is_empty(), "{fact}");
    }
}

#[test]
fn a_numeric_unknown_error_code_is_a_wire_fact_not_a_schema_error() {
    let expected = "kind = \"stream_reset\"\nh2_control_frames = [{ type = \"rst_stream\", stream_id = 2147483647, error_code = 4294967295 }]\n";
    let found = violations(4, expected, false);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_post_header_reset_still_requires_the_received_body_byte_count() {
    let missing = "kind = \"stream_error\"\nstream_termination = \"reset\"\nstatus = 200\nh2_control_frames = [{ type = \"rst_stream\", stream_id = 1, error_code = 8 }]\n";
    let found = violations(4, missing, false);
    assert!(found.iter().any(|item| item.message.contains("body_bytes_before_error")), "{found:?}");
    let found = violations(4, &(missing.to_owned() + "body_bytes_before_error = 2\n"), false);
    assert!(found.is_empty(), "{found:?}");
}
