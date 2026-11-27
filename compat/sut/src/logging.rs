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
//! the gateway printed them itself, and so do its authentication and authorization refusals
//! (`warn`), its contained panics (`error`) (rustfs/gateway#1162), unexpected `5xx` answers
//! observed through [`ServerErrorObserver`], and `rustfs-gateway-fs` internal storage-error sites
//! (rustfs/gateway#1083).
//! NOT responsible for: which gateway events exist or what they carry (`rustfs-gateway`,
//! `docs/observability.md`), spans, which nothing here reads, or Mint report aggregation
//! (`ci/mint/report.py`).
//! Upstream: the gateway's events, [`rustfs_gateway::Observer`], and `rustfs_gateway_fs`.
//! Downstream: the launcher's stderr.
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

/// Target for launcher-owned diagnostic events.
pub(crate) const TARGET: &str = "compat_sut";
/// Event name for unexpected `5xx` answers observed from the gateway.
pub(crate) const EVENT_SERVER_ERROR: &str = "compat_sut_server_error";
/// Event name for internal storage errors constructed in `rustfs-gateway-fs`.
pub(crate) const EVENT_FS_STORAGE_ERROR: &str = "compat_sut_fs_storage_error";

/// Closed-vocabulary HTTP method label: the nine standard methods, and `OTHER` for anything else
/// so caller-chosen methods never enter the launcher's log (matches `RequestEvent::method`).
fn method_label(method: &http::Method) -> &'static str {
    match *method {
        http::Method::GET => "GET",
        http::Method::HEAD => "HEAD",
        http::Method::POST => "POST",
        http::Method::PUT => "PUT",
        http::Method::DELETE => "DELETE",
        http::Method::OPTIONS => "OPTIONS",
        http::Method::PATCH => "PATCH",
        http::Method::CONNECT => "CONNECT",
        http::Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

/// Closed-vocabulary handler-deadline outcome label.
fn deadline_label(report: Option<rustfs_gateway::HandlerDeadlineReport>) -> &'static str {
    match report {
        None => "none",
        Some(rustfs_gateway::HandlerDeadlineReport::Acknowledged) => "acknowledged",
        Some(rustfs_gateway::HandlerDeadlineReport::Unacknowledged) => "unacknowledged",
    }
}

/// Records every unexpected `5xx` answer (`status >= 500`, excluding expected `501 NotImplemented`
/// capability refusals) as one closed-vocabulary `error` event carrying `method`, `operation`,
/// `status`, `code`, `deadline`, and the server-minted `request_id` — never an identity, header,
/// path, query, or body (rustfs/gateway#1083).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ServerErrorObserver;

fn emit_server_error(
    method: &http::Method,
    operation: Option<&str>,
    status: u16,
    error: Option<&rustfs_gateway::ErrorCode>,
    handler_deadline: Option<rustfs_gateway::HandlerDeadlineReport>,
    request_id: &rustfs_gateway::RequestId,
) {
    if status < 500 || status == 501 {
        return;
    }
    let method = method_label(method);
    let operation = operation.unwrap_or("unknown");
    let code = error.map_or("none", rustfs_gateway::ErrorCode::as_str);
    let deadline = deadline_label(handler_deadline);
    tracing::error!(
        target: TARGET,
        event = EVENT_SERVER_ERROR,
        method,
        operation,
        status,
        code,
        deadline,
        request_id = %request_id,
        "server returned 5xx"
    );
}

impl rustfs_gateway::Observer for ServerErrorObserver {
    fn on_response(&self, event: &rustfs_gateway::RequestEvent<'_>) {
        emit_server_error(
            event.method(),
            event.operation,
            event.status,
            event.error,
            event.handler_deadline,
            event.request_id,
        );
    }
}

/// Strips any host prefix from a compiler-recorded source path, keeping only a clean relative
/// `crates/fs/src/<path>.rs` path and folding any foreign or malformed path to `"unknown"`.
pub(crate) fn normalize_fs_location(file: &str) -> String {
    let normalized = file.replace('\\', "/");
    let marker = "crates/fs/src/";
    let Some(index) = normalized.rfind(marker) else {
        return "unknown".to_owned();
    };
    let relative = &normalized[index..];
    let suffix = &relative[marker.len()..];
    let Some(stem) = suffix.strip_suffix(".rs") else {
        return "unknown".to_owned();
    };
    if !stem.is_empty()
        && stem.len() <= 77
        && !stem.starts_with('/')
        && !stem.ends_with('/')
        && !stem.contains("//")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'/'))
    {
        relative.to_owned()
    } else {
        "unknown".to_owned()
    }
}

/// Records the host-free source site of an internal `rustfs-gateway-fs` storage error.
pub(crate) fn record_fs_storage_error(location: &'static core::panic::Location<'static>) {
    let file = normalize_fs_location(location.file());
    let line = location.line();
    tracing::error!(
        target: TARGET,
        event = EVENT_FS_STORAGE_ERROR,
        file = file.as_str(),
        line,
        "filesystem backend returned storage_error"
    );
}

/// Installs the launcher's log as the process-wide subscriber and wires the reference backend's
/// internal storage-error observer. A second call, or one after another subscriber was installed,
/// changes nothing.
pub(crate) fn install() {
    let _ = tracing::subscriber::set_global_default(EventLines(|line: String| eprintln!("{line}")));
    let _ = rustfs_gateway_fs::set_storage_error_observer(record_fs_storage_error);
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

    /// Negative — non-5xx responses and expected `501 NotImplemented` capability refusals emit no
    /// server-error diagnostic line.
    #[test]
    fn n_server_error_observer_ignores_non_5xx_and_not_implemented() {
        use rustfs_gateway::{ErrorCode, RequestId};

        let request_id = RequestId::from_bits(0x1234);
        let lines = lines_of(|| {
            for (status, error) in [
                (200, None),
                (400, Some(&ErrorCode::INVALID_ARGUMENT)),
                (403, Some(&ErrorCode::ACCESS_DENIED)),
                (404, Some(&ErrorCode::NO_SUCH_KEY)),
                (501, Some(&ErrorCode::NOT_IMPLEMENTED)),
            ] {
                emit_server_error(&http::Method::PUT, Some("PutObject"), status, error, None, &request_id);
            }
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    /// Negative — custom/unknown HTTP methods are folded to `OTHER`, and no identity or raw wire
    /// field is ever emitted on the 5xx diagnostic line.
    #[test]
    fn n_server_error_observer_folds_unknown_methods_and_omits_identity() {
        use rustfs_gateway::{ErrorCode, RequestId};

        let request_id = RequestId::from_bits(0xCAFE);
        let custom = http::Method::from_bytes(b"PROPFIND").expect("custom method");
        let lines = lines_of(|| {
            emit_server_error(&custom, None, 500, Some(&ErrorCode::INTERNAL_ERROR), None, &request_id);
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with(
                "ERROR compat_sut: server returned 5xx event=compat_sut_server_error method=OTHER operation=unknown status=500 code=InternalError deadline=none request_id="
            ),
            "{}",
            lines[0]
        );
        assert!(!lines[0].contains("PROPFIND"), "{}", lines[0]);
    }

    /// Negative — `normalize_fs_location` strips host path prefixes and rejects paths outside
    /// `crates/fs/src/`, traversal segments, or non-`.rs` paths.
    #[test]
    fn n_normalize_fs_location_strips_host_prefix_and_rejects_foreign_paths() {
        assert_eq!(
            normalize_fs_location("/Users/alice/gateway/crates/fs/src/put_object.rs"),
            "crates/fs/src/put_object.rs"
        );
        assert_eq!(
            normalize_fs_location(r"C:\work\gateway\crates\fs\src\versioning\publish.rs"),
            "crates/fs/src/versioning/publish.rs"
        );
        for foreign in [
            "/etc/passwd",
            "crates/gateway/src/service.rs",
            "crates/fs/src/../secret.rs",
            "crates/fs/src//lib.rs",
            "crates/fs/src/lib.txt",
            "crates/fs/src/.rs",
            "crates/fs/src/BadCase.rs",
        ] {
            assert_eq!(normalize_fs_location(foreign), "unknown", "{foreign}");
        }
    }

    /// Positive — `ServerErrorObserver` emits closed-vocabulary fields for 500 and deadline reports.
    #[test]
    fn a_server_error_observer_logs_500_with_deadline_state() {
        use rustfs_gateway::{ErrorCode, HandlerDeadlineReport, RequestId};

        let request_id = RequestId::from_bits(0xBEEF);
        let lines = lines_of(|| {
            emit_server_error(
                &http::Method::PUT,
                Some("PutObject"),
                500,
                Some(&ErrorCode::INTERNAL_ERROR),
                Some(HandlerDeadlineReport::Unacknowledged),
                &request_id,
            );
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with(
                "ERROR compat_sut: server returned 5xx event=compat_sut_server_error method=PUT operation=PutObject status=500 code=InternalError deadline=unacknowledged request_id="
            ),
            "{}",
            lines[0]
        );
    }

    /// Positive — `record_fs_storage_error` writes one structured `error` line with the relative
    /// source location.
    #[test]
    fn a_record_fs_storage_error_writes_structured_error_line() {
        let lines = lines_of(|| {
            record_fs_storage_error(core::panic::Location::caller());
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with(
                "ERROR compat_sut: filesystem backend returned storage_error event=compat_sut_fs_storage_error file=unknown line="
            ),
            "{}",
            lines[0]
        );
    }
}
