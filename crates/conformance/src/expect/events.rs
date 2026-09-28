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
//! Responsible for: selecting independently decoded messages by type and message kind, asserting
//! their declared headers on every selected frame, and applying the ordinary byte-exact body
//! vocabulary to one expected payload. A spec selects `event` messages by `:event-type` unless its
//! `headers` explicitly name `message-type = "error"`, in which case it selects request-level
//! error frames by `:error-code`: an error whose code spells `End` never satisfies an `End`
//! expectation by accident. Header names are written without the leading colon every S3 Select
//! header carries, because the frozen case schema's header-name pattern is an HTTP token and
//! cannot spell one; `error-code` is compared against the frame's `:error-code`. NOT responsible for: decoding frames or judging the settled response
//! body. Upstream: the observation and parent expectation engine.
//! Downstream: select/restore conformance cases.

use crate::diagnostic::Diagnostic;
use crate::observation::Observation;
use crate::value::Value;

use super::{GoldenSource, check_body_expectation, expected_values};

/// The message kind a spec selects: `event` unless its headers explicitly ask for another one.
fn wanted_kind(headers: Option<&Value>) -> &str {
    match headers {
        Some(Value::Table(headers)) => headers
            .iter()
            .find(|(name, _)| name == "message-type")
            .and_then(|(_, value)| value.as_str())
            .unwrap_or("event"),
        _ => "event",
    }
}

fn header<'a>(event: &'a crate::observation::ObservedEvent, name: &str) -> Option<&'a str> {
    event
        .headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Every declared header, on every selected frame. Names are byte-exact after the leading colon is
/// restored: event-stream header names are not HTTP field names and carry no case folding.
fn check_event_headers(headers: &Value, selected: &[&crate::observation::ObservedEvent], at: &str, out: &mut Vec<Diagnostic>) {
    let Value::Table(headers) = headers else { return };
    for (frame, event) in selected.iter().enumerate() {
        for (name, wanted) in headers {
            let observed = header(event, &format!(":{name}"));
            for expected in expected_values(wanted) {
                let hit = if expected == "*" {
                    observed.is_some()
                } else {
                    observed == Some(expected)
                };
                if !hit {
                    out.push(Diagnostic::deny(
                        "expect/events.headers",
                        &format!("{at}/headers/{name}"),
                        format!(
                            "selected frame #{frame}: expected `:{name}: {expected}`, observed {}",
                            observed.map_or_else(|| "no such header".to_owned(), |value| format!("`{value}`"))
                        ),
                    ));
                }
            }
        }
    }
}

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
        let headers = spec.read("expect.events[].headers");
        let kind = wanted_kind(headers);
        let selected: Vec<_> = observed
            .events
            .iter()
            .filter(|event| event.event_type == event_type && header(event, ":message-type") == Some(kind))
            .collect();
        let count = selected.len() as i64;
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
        if let Some(headers) = headers {
            check_event_headers(headers, &selected, &at, out);
        }
        if let Some(payload) = spec.read("expect.events[].payload") {
            let matching = &selected;
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
