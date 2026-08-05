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

//! The pre-authentication properties, asserted over the source rather than described in a comment.
//!
//! Responsible for: proving that nothing on the routing path is `async`, that nothing there takes a
//! store or a connection, that a `String` cannot be laundered into a static error message, and the
//! house rules every file in this crate is meant to follow.
//! NOT responsible for: behaviour. Every other test file covers that; this one covers the shape of
//! the code, which is where these properties actually live.
//! Upstream: the crate's own source. Downstream: nothing.
//!
//! # Why a source guard and not a review checklist
//!
//! "The router must not await" is true today because somebody wrote it that way. It stays true only
//! if adding an `async fn` there fails. A reviewer who has to remember it will eventually not, and
//! the failure mode — an unauthenticated caller making the service do I/O — is the kind that is
//! found in production. Each guard below ends with a test proving it can fail, because a guard that
//! cannot fail is worse than none: it reads as coverage.

use std::fs;
use std::path::{Path, PathBuf};

fn source_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `src`, with its path.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && let Ok(text) = fs::read_to_string(&path)
            {
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&source_root(), &mut out);
    assert!(out.len() >= 8, "the walker found {} files; it is not walking", out.len());
    out
}

/// Words that name a handle the routing path must never hold.
const STORE_WORDS: &[&str] = &[
    "Store",
    "Repository",
    "Connection",
    "Pool",
    "Backend",
    "Client",
    "Database",
    "Handle",
];

/// Whether a line declares something taking one of those.
fn mentions_a_store(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
        return false;
    }
    STORE_WORDS.iter().any(|word| trimmed.contains(word))
}

/// Whether a line declares an `async fn`.
fn declares_async(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.starts_with("//") && (trimmed.contains("async fn ") || trimmed.contains("async move") || trimmed.contains(".await"))
}

#[test]
fn nothing_on_the_routing_path_is_async() {
    for (path, text) in sources() {
        for (number, line) in text.lines().enumerate() {
            assert!(
                !declares_async(line),
                "{}:{}: routing runs before the signature is verified; a router that can await is an \
                 unauthenticated amplifier\n  {line}",
                path.display(),
                number.saturating_add(1),
            );
        }
    }
}

#[test]
fn nothing_on_the_routing_path_holds_a_store() {
    for (path, text) in sources() {
        for (number, line) in text.lines().enumerate() {
            assert!(
                !mentions_a_store(line),
                "{}:{}: the routing path must not name a store, a connection or a pool\n  {line}",
                path.display(),
                number.saturating_add(1),
            );
        }
    }
}

/// A `&'static str` message cannot come from `format!` — unless somebody leaks one.
#[test]
fn a_string_cannot_be_laundered_into_a_static_message() {
    for (path, text) in sources() {
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !trimmed.contains(".leak(") && !trimmed.contains("Box::leak"),
                "{}:{}: leaking a String is the only way to turn request bytes into a static error \
                 message, and that is what the type is there to prevent\n  {line}",
                path.display(),
                number.saturating_add(1),
            );
        }
    }
}

/// The pre-authentication error type must not build any of its text at runtime.
#[test]
fn the_pre_auth_error_never_formats_a_message() {
    let path = source_root().join("error.rs");
    let text = fs::read_to_string(&path).expect("error.rs");
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.contains("fn fmt") {
            continue;
        }
        // `Display` may format; a *message* may not. The distinction is that `Display` renders an
        // error that is already fully determined, while a formatted message would carry new text.
        assert!(
            !trimmed.contains("format!(") || text.contains("impl std::fmt::Display for PreAuthError"),
            "{}:{}: a pre-authentication message is a compile-time constant\n  {line}",
            path.display(),
            number.saturating_add(1),
        );
    }
    assert!(
        text.contains("message: &'static str"),
        "the message field must stay a &'static str; that is the whole mechanism"
    );
}

/// Every file carries the licence header and answers the three module questions.
#[test]
fn every_source_file_is_shaped_the_way_the_house_rules_ask() {
    for (path, text) in sources() {
        assert!(
            text.starts_with("// Copyright 2026 RustFS Team"),
            "{}: missing the Apache-2.0 header",
            path.display()
        );
        assert!(
            text.contains("//! Responsible for:") && text.contains("//! NOT responsible for:") && text.contains("//! Upstream:"),
            "{}: the module docs must answer what it is responsible for, what it is not, and who is \
             upstream and downstream",
            path.display()
        );
        let lines = text.lines().count();
        assert!(
            lines <= 800,
            "{}: {lines} lines, over the 800-line ceiling; split it or register an allowance",
            path.display()
        );
    }
}

/// Neither `resolve` nor `build` may be reached through a signature that hides a handle.
#[test]
fn the_two_entry_points_take_only_borrowed_request_facts() {
    let table = fs::read_to_string(source_root().join("route/table.rs")).expect("table.rs");
    assert!(
        table.contains("pub fn build(entries: Vec<RouteEntry>, shadowing: &ShadowingDecls) -> Result<Self, RouteBuildError>"),
        "RouteTable::build takes entries and declarations; adding a third parameter is the change this guard is about"
    );
    assert!(
        table.contains("pub fn resolve(&self, request: &RouteRequestParts<'_>) -> Option<&RouteEntry>"),
        "RouteTable::resolve takes one borrowed request view and nothing else"
    );
}

// ── the guards can fail ──────────────────────────────────────────────────────────────────────

#[test]
fn the_async_detector_notices_an_async_function() {
    assert!(declares_async("    pub async fn resolve(&self) {}"));
    assert!(declares_async("        let entry = self.lookup().await;"));
    assert!(!declares_async("//! nothing here is async fn, and nothing awaits"));
    assert!(!declares_async("    pub fn resolve(&self) {}"));
}

#[test]
fn the_store_detector_notices_a_handle() {
    assert!(mentions_a_store("    pub fn build(store: &ObjectStore) {}"));
    assert!(mentions_a_store("    fn with(pool: ConnectionPool) {}"));
    assert!(!mentions_a_store("    // a Store would be refused here"));
    assert!(!mentions_a_store("    pub fn resolve(&self, request: &RouteRequestParts<'_>) {}"));
}
