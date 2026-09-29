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

//! The two slash rewrites a [`SlashPolicy`](super::naming::SlashPolicy) can select.
//!
//! Responsible for: folding the runs of slashes in an already-decoded key, MinIO's way (every run,
//! and the leading slash) and legacy RustFS's way (only in a key that starts with `/`).
//! NOT responsible for: choosing between them, decoding, or any floor rule: all three are
//! `super::naming`'s, which calls these from its one normalisation and nowhere else.
//! Upstream: `super::naming::normalize_key`. Downstream: nothing.

/// Folds runs of slashes and drops a leading one. Linear in the length of the input.
pub(super) fn collapse_slashes(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut previous_was_slash = false;
    for ch in value.chars() {
        if ch == '/' {
            if !previous_was_slash {
                out.push(ch);
            }
            previous_was_slash = true;
        } else {
            out.push(ch);
            previous_was_slash = false;
        }
    }
    match out.strip_prefix('/') {
        Some(rest) => rest.to_owned(),
        None => out,
    }
}

/// [`SlashPolicy::RustfsLegacy`](super::naming::SlashPolicy::RustfsLegacy): folds a key that starts with `/` and leaves every other key as
/// sent. Linear in the length of the input.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS folds the slashes of a key only when the
/// key starts with one, so `PUT /bucket//a//b` stores `a/b` while `PUT /bucket/a//b` hands `a//b`
/// to storage unchanged; whether a run of slashes is data depends on where in the key it sits,
/// and the spelling a client sent is not the object it names. Kept so every key a RustFS client
/// stored stays reachable under the spelling it used. The intended future behaviour is
/// [`SlashPolicy::AwsPreserve`](super::naming::SlashPolicy::AwsPreserve), which needs the objects stored under a folded spelling migrated
/// first.
pub(super) fn fold_rooted_slashes(value: String) -> String {
    if !value.starts_with('/') {
        return value;
    }
    let mut folded = String::with_capacity(value.len());
    // A separator is written only once the next segment starts, so leading slashes and runs
    // between segments each leave at most one behind.
    let mut separator_pending = false;
    for ch in value.chars() {
        if ch == '/' {
            separator_pending = !folded.is_empty();
        } else {
            if separator_pending {
                folded.push('/');
                separator_pending = false;
            }
            folded.push(ch);
        }
    }
    // A key of slashes only keeps one, and a key that ended in a run of slashes keeps one of them.
    if folded.is_empty() || separator_pending {
        folded.push('/');
    }
    folded
}
