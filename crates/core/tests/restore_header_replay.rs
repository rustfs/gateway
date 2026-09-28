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

//! Stable replay for the Restore status-header fuzz property.
//! Responsible for: fixed positive/negative seeds and generated calendar boundaries.
//! NOT responsible for: wire I/O.
//! Upstream: committed fuzz seeds. Downstream: the production restore parser and formatter.

#[path = "../../../fuzz/support/restore_header.rs"]
mod property;

fn replay(name: &str) -> bool {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds/restore_header")
        .join(name);
    property::check(&std::fs::read(path).expect("required restore fuzz seed")).is_some()
}

#[test]
fn canonical_headers_are_accepted() {
    for name in ["ongoing", "restored", "false-without-expiry", "leap-day", "sunday"] {
        assert!(replay(name), "{name}");
    }
}

#[test]
fn invalid_calendar_is_refused() {
    for name in [
        "nonleap-day",
        "century-nonleap",
        "day-zero",
        "april-31",
        "hour-24",
        "minute-60",
        "second-60",
        "five-digit-year",
        "lowercase-weekday",
    ] {
        assert!(!replay(name), "{name}");
    }
}

#[test]
fn contradictory_state_is_refused() {
    assert!(!replay("ongoing-with-expiry"));
}
#[test]
fn trailing_pairs_are_refused() {
    assert!(!replay("trailing-pair"));
}
#[test]
fn broken_quotes_are_refused() {
    assert!(!replay("unquoted"));
    assert!(!replay("missing-open-quote"));
}
#[test]
fn unknown_boolean_is_refused() {
    assert!(!replay("unknown-boolean"));
}
#[test]
fn wrong_separator_is_refused() {
    assert!(!replay("missing-space"));
}
#[test]
fn invalid_encoding_is_not_repaired() {
    assert!(!replay("not-utf8"));
}

#[test]
fn generated_headers_and_single_byte_damage_are_checked() {
    let weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    for year in [0, 1900, 2000, 2024, 2100, 9999] {
        for day in 1..=28 {
            let weekday = weekdays[day as usize % weekdays.len()];
            let text = format!("ongoing-request=\"false\", expiry-date=\"{weekday}, {day:02} Feb {year:04} 12:34:56 GMT\"");
            assert!(property::check(text.as_bytes()).is_some());
            for at in 0..text.len() {
                let mut damaged = text.as_bytes().to_vec();
                damaged[at] = 0;
                assert!(property::check(&damaged).is_none(), "NUL at {at}");
            }
        }
    }
}
