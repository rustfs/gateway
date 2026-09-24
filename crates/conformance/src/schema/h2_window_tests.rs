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

//! Responsible for: versioned WINDOW_UPDATE fields and bounded scripted flow-control expectations.
//! NOT responsible for: observing credit, permitting invalid peer frames, or sender policy.
//! Upstream: the frozen case schema; downstream: schema regression controls.

use super::Schema;
fn valid(version: i64, expectation: &str, kind: &str) -> bool {
    let source = format!(
        r#"
[case]
id="c-test-0001"
schema_version={version}
title="Measured WINDOW_UPDATE"
rationale="Connection and stream credit are separate numerical facts from received frames."
polarity="negative"
quirks=[]
evidence=[{{url="https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9",summary="Window updates name an increment and a connection or stream scope."}}]
[request]
method="GET"
target="/"
[expect]
{kind}
h2_control_frames=[{expectation}]
"#
    );
    Schema::compile(include_str!("../../../../conformance/case.schema.json"))
        .expect("schema")
        .validate(&crate::toml::parse(&source).expect("fixture"))
        .is_empty()
}
const WINDOW: &str = "{type='window_update',stream_id=0,increment=2147483647}";
#[test]
fn version_four_accepts_connection_and_stream_window_facts() {
    assert!(valid(4, WINDOW, "kind='response'\nstatus=200"));
    assert!(valid(
        4,
        &WINDOW.replace("stream_id=0", "stream_id=2147483647"),
        "kind='response'\nstatus=200"
    ));
}
#[test]
fn older_versions_cannot_assert_window_observations() {
    for version in 1..=3 {
        assert!(!valid(version, WINDOW, "kind='response'\nstatus=200"));
    }
}
#[test]
fn window_facts_require_positive_bounded_increments_and_valid_scope() {
    for fact in [
        "{type='window_update',stream_id=0}",
        "{type='window_update',increment=1}",
        "{type='window_update',stream_id=-1,increment=1}",
        "{type='window_update',stream_id=2147483648,increment=1}",
        "{type='window_update',stream_id=0,increment=0}",
        "{type='window_update',stream_id=0,increment=-1}",
        "{type='window_update',stream_id=0,increment=2147483648}",
        "{type='window_update',stream_id=0,increment='1'}",
    ] {
        assert!(!valid(4, fact, "kind='response'\nstatus=200"), "{fact}");
    }
}
#[test]
fn control_specific_fields_cannot_leak_between_variants() {
    for fact in [
        "{type='window_update',stream_id=1,increment=1,error_code=0}",
        "{type='window_update',stream_id=1,increment=1,last_stream_id=1}",
        "{type='rst_stream',stream_id=1,error_code=0,increment=1}",
        "{type='goaway',last_stream_id=1,error_code=0,increment=1}",
        "{type='rst_stream',stream_id=0,error_code=0}",
    ] {
        assert!(!valid(4, fact, "kind='response'\nstatus=200"), "{fact}");
    }
}
#[test]
fn window_updates_alone_cannot_substantiate_stream_reset() {
    assert!(!valid(4, WINDOW, "kind='stream_reset'"));
}

fn bounded_hang_valid(version: u8, budget: Option<&str>, multiple: bool, scripted: bool, kind: &str) -> bool {
    let budget = budget.map_or_else(String::new, |value| format!("timeout_ms = {value}"));
    let prefix = if multiple { "exchanges." } else { "" };
    let exchange = if multiple { "[[exchanges]]" } else { "" };
    let frames = if scripted { "h2_frames = [{ type = 'settings' }]" } else { "" };
    let source = format!(
        r#"
[case]
id = "c-test-0001"
schema_version = {version}
title = "Bounded flow-control incompletion"
rationale = "A client withholding flow-control credit observes incompletion only through an explicit deadline."
polarity = "negative"
quirks = []
evidence = [{{ url = "https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9", summary = "A sender requires sufficient flow-control credit before sending DATA." }}]
{budget}
{exchange}
[{prefix}request]
method = "GET"
target = "/"
http_version = "h2"
{frames}
[{prefix}expect]
kind = "{kind}"
status = 200
"#
    );
    Schema::compile(include_str!("../../../../conformance/case.schema.json"))
        .expect("schema compiles")
        .validate(&crate::toml::parse(&source).expect("bounded expectation fixture"))
        .is_empty()
}

#[test]
fn scripted_h2_hang_requires_a_positive_explicit_budget_in_both_forms() {
    for multiple in [false, true] {
        for budget in [
            None,
            Some("0"),
            Some("-1"),
            Some("'1'"),
            Some("true"),
            Some("false"),
            Some("1.5"),
            Some("[]"),
            Some("{}"),
        ] {
            assert!(
                !bounded_hang_valid(4, budget, multiple, true, "hang"),
                "budget {budget:?}, exchanges={multiple}"
            );
        }
    }
}

#[test]
fn scripted_h2_hang_accepts_positive_whole_case_budgets() {
    for multiple in [false, true] {
        assert!(bounded_hang_valid(4, Some("1"), multiple, true, "hang"));
    }
}

#[test]
fn explicit_budget_requirement_does_not_change_legacy_or_complete_expectations() {
    for multiple in [false, true] {
        for version in 1..=3 {
            assert!(bounded_hang_valid(version, None, multiple, true, "hang"));
        }
        assert!(bounded_hang_valid(4, None, multiple, false, "hang"));
        assert!(bounded_hang_valid(4, None, multiple, true, "response"));
    }
}
