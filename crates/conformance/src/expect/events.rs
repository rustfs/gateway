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

//! Event-stream count and payload expectations.
//!
//! Responsible for: matching independently decoded event frames by type and applying the ordinary
//! byte-exact body vocabulary to one expected payload. NOT responsible for: decoding frames or
//! judging the settled response body. Upstream: the observation and parent expectation engine.
//! Downstream: select/restore conformance cases.

use crate::diagnostic::Diagnostic;
use crate::observation::Observation;
use crate::value::Value;

use super::{GoldenSource, check_body_expectation};

pub(super) fn check_events(
    expect: &Value,
    observed: &Observation,
    pointer: &str,
    goldens: &dyn GoldenSource,
    out: &mut Vec<Diagnostic>,
) {
    let Some(Value::Array(events)) = expect.read("expect.events") else { return };
    for (index, spec) in events.iter().enumerate() {
        let at = format!("{pointer}/events/{index}");
        let Some(event_type) = spec.read("expect.events[].type").and_then(Value::as_str) else { continue };
        let count = observed.events.iter().filter(|event| event.event_type == event_type).count() as i64;
        let minimum = spec
            .read("expect.events[].min_count")
            .and_then(Value::as_integer)
            .unwrap_or(1);
        let maximum = spec.read("expect.events[].max_count").and_then(Value::as_integer);
        if count < minimum {
            out.push(Diagnostic::deny(
                "expect/events.min_count",
                &at,
                format!("expected at least {minimum} `{event_type}` frames, observed {count}"),
            ));
        }
        if maximum.is_some_and(|limit| count > limit) {
            out.push(Diagnostic::deny(
                "expect/events.max_count",
                &at,
                format!("expected at most {} `{event_type}` frames, observed {count}", maximum.unwrap_or_default()),
            ));
        }
        if let Some(payload) = spec.read("expect.events[].payload") {
            let matching: Vec<_> = observed
                .events
                .iter()
                .filter(|event| event.event_type == event_type)
                .collect();
            if matching.len() != 1 {
                out.push(Diagnostic::deny(
                    "expect/events.payload",
                    &format!("{at}/payload"),
                    format!(
                        "an event payload expectation requires exactly one `{event_type}` frame, observed {}",
                        matching.len()
                    ),
                ));
            } else if let Some(event) = matching.first() {
                check_body_expectation(payload, &event.payload, &format!("{at}/payload"), goldens, out);
            }
        }
    }
}
