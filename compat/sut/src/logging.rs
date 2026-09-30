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

//! The launcher's log: every `tracing` event at `info` or above, as one line on stderr.
//!
//! Responsible for: [`install`], so the gateway's start-up report (`SECURITY_POSTURE` and the lines
//! beside it) and its dangerous-assembly warnings reach the log a suite run keeps, as they did when
//! the gateway printed them itself (rustfs/gateway#1162).
//! NOT responsible for: which events exist or what they carry (`rustfs-gateway`,
//! `docs/observability.md`), or spans, which nothing here reads.
//! Upstream: the gateway's events. Downstream: the launcher's stderr.
//!
//! A subscriber of its own rather than a formatting crate: it is a few dozen lines, it prints exactly
//! the fields an event carries, and the launcher gains no dependency the gateway does not have.

use std::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// Hands `LEVEL target: message field=value …` for every event at `info` or above to its sink.
struct EventLines<W>(W);

/// The message, then every other field as `name=value`, in the order the event declares them.
#[derive(Default)]
struct Line {
    message: String,
    fields: String,
}

impl Visit for Line {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

impl<W: Fn(String) + Send + Sync + 'static> Subscriber for EventLines<W> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::INFO
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::INFO)
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut line = Line::default();
        event.record(&mut line);
        let metadata = event.metadata();
        (self.0)(format!("{} {}: {}{}", metadata.level(), metadata.target(), line.message, line.fields));
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Installs the launcher's log as the process-wide subscriber. A second call, or one after another
/// subscriber was installed, changes nothing.
pub(crate) fn install() {
    let _ = tracing::subscriber::set_global_default(EventLines(|line: String| eprintln!("{line}")));
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn lines_of(emit: impl FnOnce()) -> Vec<String> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let subscriber = EventLines(move |line: String| sink.lock().expect("not poisoned").push(line));
        tracing::subscriber::with_default(subscriber, emit);
        seen.lock().expect("not poisoned").clone()
    }

    /// Positive — an event is one line: level, target, message, then every field in order.
    #[test]
    fn an_event_is_one_line_with_its_fields() {
        let lines = lines_of(|| {
            tracing::info!(
                target: "rustfs_gateway",
                event = "gateway_naming_posture",
                component = "gateway",
                "NAMING_POSTURE slash_policy=aws-preserve"
            );
        });
        assert_eq!(
            lines,
            ["INFO rustfs_gateway: NAMING_POSTURE slash_policy=aws-preserve event=gateway_naming_posture component=gateway"]
        );
    }

    /// Negative — nothing below `info` is printed.
    #[test]
    fn a_debug_event_is_not_printed() {
        let lines = lines_of(|| {
            tracing::debug!(target: "rustfs_gateway", event = "quiet", "not for the launcher's log");
            tracing::trace!(target: "rustfs_gateway", "nor this");
        });
        assert!(lines.is_empty(), "{lines:?}");
    }
}
