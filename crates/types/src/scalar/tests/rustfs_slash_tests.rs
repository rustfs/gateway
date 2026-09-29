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

//! The legacy RustFS slash rule (rustfs/gateway#1101), held to the keys legacy RustFS stores.
//!
//! Responsible for: [`SlashPolicy::RustfsLegacy`] — a key that starts with `/` has every run of
//! slashes folded, its leading slashes dropped and one trailing slash kept, a key of slashes only
//! becomes `/`, and every other key is left exactly as sent — and the floor still running after
//! it. Each positive example is a request measured on legacy RustFS (`PUT /b//x` stored `x`); the
//! label is what follows `/bucket/` in that path.
//! NOT responsible for: the other two policies (`naming_tests.rs`), or where a path is split into
//! a bucket and a key (`rustfs_gateway_core::codec::view`).
//! Upstream: [`crate::scalar::naming`]. Downstream: nothing.

use crate::scalar::{NamePolicy, NameRejection, ObjectKey, SlashPolicy};

fn legacy() -> NamePolicy {
    NamePolicy::default().with_slash_policy(SlashPolicy::RustfsLegacy)
}

/// The key a path label becomes under the legacy rule, or the rule that refused it.
fn key(label: &str) -> Result<String, NameRejection> {
    ObjectKey::materialize(label, &legacy()).map(|key| key.as_str().to_owned())
}

// ---------------------------------------------------------------------------
// Positive: a key that starts with a slash is folded as legacy RustFS folds it.
// ---------------------------------------------------------------------------

#[test]
fn a_key_that_starts_with_a_slash_is_folded() {
    for (label, stored) in [
        ("/x", "x"),
        ("//x", "x"),
        ("/x/", "x/"),
        ("//x//", "x/"),
        ("//dir////x", "dir/x"),
        ("/dir///sub//file", "dir/sub/file"),
        ("///dir1////dir2/x////////", "dir1/dir2/x/"),
        // An encoded leading slash is a slash once the label is decoded, and the rule reads the
        // decoded key, as legacy RustFS does after it decodes the whole path.
        ("%2Fx", "x"),
        ("%2F%2Fdir%2F%2Fx", "dir/x"),
    ] {
        assert_eq!(key(label), Ok(stored.to_owned()), "{label:?}");
    }
}

#[test]
fn a_key_of_slashes_only_becomes_one_slash() {
    // `PUT /b//` and `PUT /b///` reach RustFS as the key `/`, which RustFS then refuses itself.
    for label in ["/", "//", "/////"] {
        assert_eq!(key(label), Ok("/".to_owned()), "{label:?}");
    }
}

#[test]
fn the_signature_still_covers_the_spelling_that_arrived() {
    let folded = ObjectKey::materialize("//dir//x", &legacy()).expect("the legacy rule accepts it");
    assert_eq!(folded.as_str(), "dir/x", "storage and authorization see the folded key");
    assert_eq!(folded.as_encoded(), "//dir//x", "the signature covers what the client sent");
}

// ---------------------------------------------------------------------------
// Negative: what the legacy rule must not do.
// ---------------------------------------------------------------------------

#[test]
fn a_key_that_does_not_start_with_a_slash_is_left_as_sent() {
    // Legacy RustFS hands `a//b` to its storage unchanged (which then refuses the interior run);
    // folding it here would store `a/b`, an object legacy RustFS never wrote.
    for label in ["a//b", "dir///sub//file", "a/", "a///", "x", "a/b/"] {
        assert_eq!(key(label), Ok(label.to_owned()), "{label:?}");
    }
    let collapse = NamePolicy::default().with_slash_policy(SlashPolicy::Collapse);
    assert_eq!(
        ObjectKey::materialize("a//b", &collapse).map(|key| key.as_str().to_owned()),
        Ok("a/b".to_owned()),
        "Collapse folds the interior run, which is why it is not the RustFS rule"
    );
}

#[test]
fn the_fold_removes_separators_and_nothing_else() {
    assert_eq!(key("/a/./b"), Ok("a/./b".to_owned()), "a dot segment is data to the fold");
    assert_eq!(key("/a%20/b"), Ok("a /b".to_owned()));
    assert_eq!(key("/a\\\\b"), Ok("a\\\\b".to_owned()), "a backslash is not a slash");
}

#[test]
fn the_floor_still_runs_after_the_fold() {
    assert_eq!(key("/../x"), Err(NameRejection::TraversalSegment), "`../x` once folded");
    assert_eq!(key("//a/..//b"), Err(NameRejection::TraversalSegment));
    assert_eq!(key("/a%00b"), Err(NameRejection::Nul));
    assert_eq!(key("/a%01b"), Err(NameRejection::ControlCharacter));
    assert_eq!(key("/a%252Fb"), Err(NameRejection::EncodedSeparator));
    assert_eq!(key(""), Err(NameRejection::Empty));
}

#[test]
fn the_length_limit_reads_the_folded_key() {
    // Legacy RustFS checks the length of the folded key, so `/b//` followed by 1024 bytes is a
    // legal 1024-byte key and one byte more is too long.
    let at_limit = format!("/{}", "k".repeat(1024));
    assert_eq!(key(&at_limit).map(|stored| stored.len()), Ok(1024));
    assert_eq!(key(&format!("/{}", "k".repeat(1025))), Err(NameRejection::TooLong));
    assert_eq!(key(&"k".repeat(1025)), Err(NameRejection::TooLong));
}

#[test]
fn a_run_of_ten_thousand_slashes_folds_without_quadratic_work() {
    let rooted = format!("{}x{}", "/".repeat(10_000), "/".repeat(10_000));
    assert_eq!(key(&rooted), Ok("x/".to_owned()));
    // Not rooted: the run is kept, so the length limit refuses it.
    let interior = format!("x{}", "/".repeat(10_000));
    assert_eq!(key(&interior), Err(NameRejection::TooLong));
}

#[test]
fn the_policy_is_named_persistence_affecting_and_is_not_the_default() {
    assert!(SlashPolicy::RustfsLegacy.rewrites_keys());
    assert_eq!(SlashPolicy::RustfsLegacy.as_str(), "rustfs-legacy");
    assert_ne!(NamePolicy::default().slash_policy(), SlashPolicy::RustfsLegacy);
    assert_ne!(SlashPolicy::RustfsLegacy.as_str(), SlashPolicy::Collapse.as_str());
}
