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

//! Source-level guards for the properties no type signature can state on its own.
//!
//! Responsible for: proving that the raw request never leaves this crate, that no lossy UTF-8
//! conversion exists on any path, that the crate-level lint denials are still in place, and that
//! every file carries its licence header, its module docs and stays inside the size limit.
//! NOT responsible for: behaviour — the other three suites cover that.
//! Upstream: the crate's own sources. Downstream: nothing.
//!
//! Each guard is paired with a proof that it can fail. A guard that has never been shown to fire
//! is indistinguishable from a guard that cannot.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under `src/`.
fn sources() -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let entries = fs::read_dir(&root).expect("the crate has a src directory");
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path).expect("readable source file");
            files.push((path, text));
        }
    }
    assert!(files.len() >= 9, "expected the whole module set, found {}", files.len());
    files
}

/// Whether `haystack` names `needle` as a whole type, rather than as part of a longer name.
///
/// Without the boundary check, `WireRequest<C>` would count as `Request<` and the guard would
/// flag the one method that is allowed to return a wire request.
fn names_type(haystack: &str, needle: &str) -> bool {
    let mut offset = 0usize;
    while let Some(found) = haystack.get(offset..).and_then(|rest| rest.find(needle)) {
        let at = offset.saturating_add(found);
        let preceded_by_name = haystack
            .get(..at)
            .and_then(|before| before.chars().next_back())
            .is_some_and(|character| character.is_alphanumeric() || character == '_');
        let end = at.saturating_add(needle.len());
        let followed_by_name = haystack
            .get(end..)
            .and_then(|after| after.chars().next())
            .is_some_and(|character| character.is_alphanumeric() || character == '_');
        if !preceded_by_name && !followed_by_name {
            return true;
        }
        offset = end;
    }
    false
}

/// Whether a line declares a function whose *return* type mentions a forbidden type.
fn leaks_raw_request(line: &str) -> bool {
    const FORBIDDEN: &[&str] = &["HeaderMap", "Uri", "Request<", "Parts"];
    let trimmed = line.trim_start();
    if !trimmed.starts_with("pub fn") && !trimmed.starts_with("pub const fn") {
        return false;
    }
    let Some(arrow) = trimmed.find("->") else { return false };
    let returns = trimmed.get(arrow..).unwrap_or("");
    FORBIDDEN.iter().any(|forbidden| names_type(returns, forbidden))
}

#[test]
fn no_public_accessor_hands_back_the_raw_request() {
    for (path, text) in sources() {
        for (number, line) in text.lines().enumerate() {
            assert!(
                !leaks_raw_request(line),
                "{}:{} returns a raw request type: {line}",
                path.display(),
                number.saturating_add(1)
            );
        }
    }
}

#[test]
fn the_raw_request_guard_can_fail() {
    assert!(leaks_raw_request("    pub fn headers(&self) -> &HeaderMap {"));
    assert!(leaks_raw_request("pub fn into_parts(self) -> (http::request::Parts, B) {"));
    assert!(leaks_raw_request("    pub fn uri(&self) -> &Uri {"));
    // A parameter of that type is fine — that is how the request gets consumed in the first place.
    assert!(!leaks_raw_request(
        "    pub fn accept(request: Request<B>, limits: &Limits) -> Result<Self, WireReject> {"
    ));
    assert!(!leaks_raw_request("    pub fn headers(&self) -> HeaderView<'_> {"));
    // And a longer name that merely contains a forbidden one is not a leak.
    assert!(!leaks_raw_request("    pub fn map_body<C, F>(self, transform: F) -> WireRequest<C> {"));
    assert!(!leaks_raw_request("    pub fn kind(&self) -> LimitKind::UriBytes {"));
}

#[test]
fn no_lossy_utf8_conversion_exists_anywhere_in_the_crate() {
    // A lossy conversion produces a value containing U+FFFD that differs from the bytes that
    // arrived, so authorisation and storage would be looking at two different strings. Every path
    // here either validates the bytes or hands them on untouched.
    for (path, text) in sources() {
        assert!(!text.contains("from_utf8_lossy"), "{} uses a lossy conversion", path.display());
        assert!(!text.contains("to_string_lossy"), "{} uses a lossy conversion", path.display());
    }
}

#[test]
fn the_crate_level_lint_denials_are_still_in_place() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).expect("readable lib.rs");
    for lint in [
        "forbid(unsafe_code)",
        "clippy::unwrap_used",
        "clippy::expect_used",
        "clippy::indexing_slicing",
        "clippy::arithmetic_side_effects",
        "clippy::cast_possible_truncation",
        "clippy::cast_sign_loss",
        "clippy::panic",
    ] {
        assert!(lib.contains(lint), "lib.rs no longer denies {lint}");
    }
}

#[test]
fn no_unchecked_arithmetic_or_indexing_slipped_in() {
    // The lint denials above are enforced by the compiler; this checks the two escape hatches a
    // denial cannot see, namely a local `allow` re-opening one of them.
    for (path, text) in sources() {
        assert!(
            !text.contains("allow(clippy::indexing_slicing"),
            "{} re-opens indexing_slicing",
            path.display()
        );
        assert!(
            !text.contains("allow(clippy::arithmetic_side_effects"),
            "{} re-opens arithmetic_side_effects",
            path.display()
        );
        assert!(!text.contains("allow(clippy::unwrap_used"), "{} re-opens unwrap_used", path.display());
    }
}

#[test]
fn every_source_file_carries_its_licence_header_and_module_docs() {
    for (path, text) in sources() {
        assert!(
            text.starts_with("// Copyright 2026 RustFS Team"),
            "{} does not open with the licence header",
            path.display()
        );
        assert!(
            text.contains("Licensed under the Apache License, Version 2.0"),
            "{} is missing the licence grant",
            path.display()
        );
        // AGENTS.md: a module doc that answers only "what is this" is incomplete.
        assert!(text.contains("//! Responsible for:"), "{} lacks a responsibility line", path.display());
        assert!(
            text.contains("//! NOT responsible for:"),
            "{} lacks a non-responsibility line",
            path.display()
        );
        assert!(text.contains("//! Upstream:"), "{} lacks an upstream/downstream line", path.display());
    }
}

#[test]
fn no_source_file_exceeds_the_size_limit() {
    for (path, text) in sources() {
        let lines = text.lines().count();
        assert!(lines <= 800, "{} is {lines} lines, over the 800-line limit", path.display());
    }
}

#[test]
fn the_negative_cases_outnumber_the_positive_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut positive = 0usize;
    let mut negative = 0usize;
    let entries = fs::read_dir(&root).expect("the crate has a tests directory");
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable test file");
        let mut in_negative_section = false;
        for line in text.lines() {
            if line.contains("── positive ") {
                in_negative_section = false;
            }
            if line.contains("── negative ") {
                in_negative_section = true;
            }
            if line.trim_start().starts_with("fn ") && line.contains("()") {
                continue;
            }
            if line.trim() == "#[test]" {
                if in_negative_section {
                    negative = negative.saturating_add(1);
                } else {
                    positive = positive.saturating_add(1);
                }
            }
        }
    }
    assert!(
        negative >= positive,
        "AGENTS.md requires negative cases to outnumber positive ones; found {negative} negative and {positive} positive"
    );
}
