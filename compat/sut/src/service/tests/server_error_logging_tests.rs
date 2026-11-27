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

//! End-to-end verification that `super::build_service` records unexpected `5xx` answers through
//! `crate::logging::ServerErrorObserver` without leaking credentials or logging `4xx`/`501`
//! answers (rustfs/gateway#1083).
//!
//! Responsible for: proving the served assembly actually attaches the 5xx observer rather than
//! leaving `NoObserver` in place, and proving healthy, `404`, and `501` responses produce no
//! `compat_sut_server_error` line while a real backend `500 InternalError` produces one.
//! NOT responsible for: `EventLines` formatting details (`crate::logging`), or report aggregation
//! (`ci/mint/report.py`).
//! Upstream: `super::build_service` and `crate::logging`. Downstream: nothing.

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};

use super::*;

struct Capture(Arc<Mutex<Vec<String>>>);

#[derive(Default)]
struct RecordedLine {
    message: String,
    fields: String,
}

impl Visit for RecordedLine {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            use std::fmt::Write as _;
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write as _;
            let _ = write!(self.message, "{value:?}");
        } else {
            use std::fmt::Write as _;
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::ERROR
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = RecordedLine::default();
        event.record(&mut line);
        let metadata = event.metadata();
        self.0.lock().expect("not poisoned").push(format!(
            "{} {}: {}{}",
            metadata.level(),
            metadata.target(),
            line.message,
            line.fields
        ));
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

fn capture_lines<F, Fut>(future: F) -> impl std::future::Future<Output = Vec<String>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let seen = Arc::new(Mutex::new(Vec::new()));
    let subscriber = Capture(Arc::clone(&seen));
    let dispatch = tracing::Dispatch::new(subscriber);
    async move {
        let guard = tracing::dispatcher::set_default(&dispatch);
        future().await;
        drop(guard);
        seen.lock().expect("not poisoned").clone()
    }
}

/// Negative — healthy `200`, `404 NoSuchBucket`, and `501 NotImplemented` answers through the
/// served assembly never emit a `compat_sut_server_error` line.
#[tokio::test(flavor = "current_thread")]
async fn n_healthy_4xx_and_501_answers_emit_no_server_error_event() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));

    let lines = capture_lines(|| async {
        assert_eq!(
            exchange(&service, as_main(http::Method::PUT, "/healthy", Bytes::new()))
                .await
                .status(),
            200
        );
        assert_eq!(
            exchange(&service, as_main(http::Method::GET, "/missing-bucket?list-type=2", Bytes::new()))
                .await
                .status(),
            404
        );
        assert_eq!(
            exchange(&service, as_main(http::Method::GET, "/healthy?notification", Bytes::new()))
                .await
                .status(),
            501
        );
    })
    .await;

    let server_errors: Vec<&String> = lines.iter().filter(|line| line.contains("compat_sut_server_error")).collect();
    assert!(server_errors.is_empty(), "{server_errors:?}");
}

/// Positive — a real `500 InternalError` from the backend through `build_service` emits one
/// closed-vocabulary `compat_sut_server_error` line carrying the minted request id and zero secrets.
#[tokio::test(flavor = "current_thread")]
async fn a_backend_500_through_build_service_is_observed_without_secrets() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/broken", Bytes::new()))
            .await
            .status(),
        200
    );

    // Corrupting the bucket's persisted versioning status file lets authorization pass and
    // forces `FsBackend::PutObject` to fail with `storage_error()` (`500 InternalError`).
    let bucket_dir = std::fs::read_dir(&root.0)
        .expect("read data root")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("b-"))
        })
        .expect("bucket directory");
    std::fs::write(bucket_dir.join("versioning-status"), b"corrupt-versioning-status").expect("write corrupt versioning status");

    let mut response_request_id = String::new();
    let lines = capture_lines(|| async {
        let response = exchange(&service, as_main(http::Method::PUT, "/broken/secret-key", Bytes::from_static(b"data"))).await;
        assert_eq!(response.status(), 500, "{}", body_of(&response));
        response_request_id = response.header("x-amz-request-id").expect("request id header").to_owned();
    })
    .await;

    let server_errors: Vec<&String> = lines.iter().filter(|line| line.contains("compat_sut_server_error")).collect();
    assert_eq!(server_errors.len(), 1, "{lines:?}");
    let expected = format!(
        "ERROR compat_sut: server returned 5xx event=compat_sut_server_error method=PUT operation=PutObject status=500 code=InternalError deadline=none request_id={response_request_id}"
    );
    assert_eq!(server_errors[0], &expected);
    assert!(!server_errors[0].contains(MAIN_KEY));
    assert!(!server_errors[0].contains(MAIN_SECRET));
    assert!(!server_errors[0].contains("secret-key"));
}
