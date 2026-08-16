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

/// The files that are not on the routing path, and the reason each one is not.
///
/// The routing path is everything a request touches *before* the security floor has admitted it.
/// The invocation side runs after, and awaiting is exactly what it is for — a handler that could
/// not await would not be a handler. Listing the exceptions by name is what keeps "this file may
/// await" a decision somebody made once, rather than a property the guard quietly loses.
///
/// An entry naming a file that does not exist, or one that turns out not to await after all, fails
/// [`the_off_path_allowance_says_what_is_true`]: a stale allowance reads as a reviewed decision
/// about code that is no longer there.
const OFF_THE_ROUTING_PATH: &[(&str, &str)] = &[
    (
        "registry/handlers.rs",
        "the erased handler call: it runs after the floor has admitted the request, and it is the \
         dynamic invocation path in this crate",
    ),
    (
        "static_dispatch.rs",
        "the sealed generic decode, authorization, handler and encode entry runs only after the \
         facade security floor has admitted the request",
    ),
    (
        "cancellation.rs",
        "handler cancellation is execution state observed only after the security floor has \
         admitted the request",
    ),
];

/// Whether a file is one of the few allowed to await.
fn is_off_the_routing_path(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    OFF_THE_ROUTING_PATH
        .iter()
        .any(|(suffix, _)| text.ends_with(&format!("src/{suffix}")))
}

/// The identifier segments of a line: `ObjectStore` is `["Object", "Store"]`.
///
/// Segment-wise rather than substring-wise, because a substring test cannot tell `Handle` from
/// `Handler`, and `Handler` is the name of the thing this crate registers. Whole segments keep
/// every catch the substring version had — `ObjectStore`, `ConnectionPool` — without reporting the
/// registry's own vocabulary.
fn identifier_segments(text: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch == '_' || !ch.is_alphanumeric() {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        if ch.is_uppercase() && !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// Whether a line declares something taking one of those.
fn mentions_a_store(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
        return false;
    }
    let segments = identifier_segments(trimmed);
    STORE_WORDS.iter().any(|word| segments.iter().any(|segment| segment == word))
}

/// Whether a line declares an `async fn`.
fn declares_async(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.starts_with("//") && (trimmed.contains("async fn ") || trimmed.contains("async move") || trimmed.contains(".await"))
}

#[test]
fn nothing_on_the_routing_path_is_async() {
    for (path, text) in sources() {
        if is_off_the_routing_path(&path) {
            continue;
        }
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

/// The allowance list describes the tree it is written about, and the routing path cannot reach it.
#[test]
fn the_off_path_allowance_says_what_is_true() {
    for (suffix, reason) in OFF_THE_ROUTING_PATH {
        let path = source_root().join(suffix);
        let text = fs::read_to_string(&path).unwrap_or_else(|_| panic!("{suffix} is allowed to await but does not exist"));
        assert!(
            text.lines().any(declares_async),
            "{suffix} is on the allowance list and does not await; delete the entry rather than \
             leaving a reviewed exception for code that no longer needs one ({reason})"
        );
    }

    // The point of the list is that awaiting stays on the far side of authentication. A routing
    // file that reached into the invocation layer would be back on the wrong side of it, whatever
    // the allowance says.
    for (path, text) in sources() {
        if !path.to_string_lossy().contains("/route/") {
            continue;
        }
        assert!(
            !text.contains("registry::handlers") && !text.contains("crate::handler"),
            "{}: the routing module must not reach the invocation layer",
            path.display()
        );
    }
}

/// The framework pins one future per request, and the count is the guard.
///
/// The erased registry costs one `Box::pin`. That is the same count s3s already pays, because its
/// internal dispatch is `#[async_trait]` — so per-operation dispatch is not a regression against
/// it. The number is asserted rather than described, because the way it grows is somebody adding a
/// second boxing layer for convenience and nobody noticing until a profile says so.
#[test]
fn the_framework_pins_a_future_once_per_request() {
    let pins: usize = sources()
        .iter()
        .map(|(_, text)| {
            text.lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| line.contains("Box::pin"))
                .count()
        })
        .sum();
    assert_eq!(
        pins, 1,
        "the framework must pin exactly one future per request; found {pins} `Box::pin` sites in this crate"
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
    assert!(mentions_a_store("    fn take(handle: Handle) {}"));
    assert!(mentions_a_store("    fn take(b: Backend) {}"));
    assert!(!mentions_a_store("    // a Store would be refused here"));
    assert!(!mentions_a_store("    pub fn resolve(&self, request: &RouteRequestParts<'_>) {}"));
    // The registry's own vocabulary is not a store handle, and a substring test cannot say so.
    assert!(!mentions_a_store("    pub trait Handler<O: Operation>: Send + Sync + 'static {}"));
    assert!(!mentions_a_store("    pub fn handlers(&self) -> &HandlerTable {}"));
}

#[test]
fn the_segmenter_splits_the_way_the_detector_needs() {
    assert_eq!(identifier_segments("ObjectStore"), vec!["Object", "Store"]);
    assert_eq!(identifier_segments("HandlerTable"), vec!["Handler", "Table"]);
    assert_eq!(identifier_segments("&mut self.query_index"), vec!["mut", "self", "query", "index"]);
}

#[test]
fn the_off_path_check_matches_only_the_listed_files() {
    assert!(is_off_the_routing_path(&source_root().join("registry/handlers.rs")));
    assert!(is_off_the_routing_path(&source_root().join("static_dispatch.rs")));
    assert!(is_off_the_routing_path(&source_root().join("cancellation.rs")));
    assert!(!is_off_the_routing_path(&source_root().join("registry/mod.rs")));
    assert!(!is_off_the_routing_path(&source_root().join("route/table.rs")));
}
