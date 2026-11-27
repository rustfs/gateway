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

//! Pure unit tests for `storage_error_with` caller-location tracking without touching the
//! process-wide `OnceLock` shared by other `--lib` unit tests (rustfs/gateway#1083).
//!
//! Responsible for: proving `storage_error_with(None)` yields the standard `InternalError`,
//! proving the wire-facing error message never leaks source paths or line numbers, and proving
//! `#[track_caller]` forwards the exact caller file and line to an observer.
//! NOT responsible for: testing the process-wide `set_storage_error_observer` registration
//! (which runs inside an isolated child process in `tests/crud/storage_error_observer.rs`).
//! Upstream: `crate::storage_error_with`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use super::*;

static PURE_LOCATIONS: Mutex<Vec<(&'static str, u32)>> = Mutex::new(Vec::new());

fn record_pure(location: &'static core::panic::Location<'static>) {
    PURE_LOCATIONS
        .lock()
        .expect("not poisoned")
        .push((location.file(), location.line()));
}

/// Negative — without an observer, `storage_error_with` still produces `InternalError`.
#[test]
fn n_storage_error_with_none_returns_internal_error() {
    let error = storage_error_with(None);
    assert_eq!(*error.code(), ErrorCode::INTERNAL_ERROR);
    assert_eq!(
        error.message(),
        "the filesystem reference backend could not complete the storage operation"
    );
}

/// Negative — the wire-facing message never leaks source file paths or line numbers even when
/// an observer is installed.
#[test]
fn n_storage_error_wire_message_hides_source_location() {
    fn noop(_location: &'static core::panic::Location<'static>) {}
    let error = storage_error_with(Some(noop));
    assert!(!error.message().contains("storage_error_tests.rs"), "{}", error.message());
    assert!(!error.message().contains("crates/fs"), "{}", error.message());
}

/// Positive — `storage_error_with` forwards the caller's exact file and line via `#[track_caller]`.
#[test]
fn a_storage_error_with_reports_its_call_site() {
    PURE_LOCATIONS.lock().expect("not poisoned").clear();
    let expected_line = line!() + 1;
    let _ = storage_error_with(Some(record_pure));
    let seen = PURE_LOCATIONS.lock().expect("not poisoned").clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].0.ends_with("crates/fs/src/storage_error_tests.rs"), "{seen:?}");
    assert_eq!(seen[0].1, expected_line, "{seen:?}");
}
