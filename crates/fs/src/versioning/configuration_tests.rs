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

//! The excluded-key rule and the wildcard match behind it, against legacy RustFS's definitions.
//!
//! Responsible for: [`super::matches_simple`] agreeing with legacy RustFS's recursive definition on
//! every pattern and name of a small alphabet, [`super::Exclusions::excludes`], and the state a
//! write and a delete of an excluded key run under.
//! NOT responsible for: the configuration reaching storage and being applied through the wire
//! (`tests/crud/versioning.rs`).
//! Upstream: `super`. Downstream: nothing.

use super::super::VersioningState;
use super::{Exclusions, matches_simple};

/// Legacy RustFS's `match_simple`, as its source defines it: the reference the iterative match is
/// held to.
fn reference(pattern: &[u8], name: &[u8]) -> bool {
    fn deep(name: &[u8], pattern: &[u8]) -> bool {
        let (mut name, mut pattern) = (name, pattern);
        while let Some((&first, rest)) = pattern.split_first() {
            match first {
                b'*' => {
                    return rest.is_empty()
                        || deep(name, rest)
                        || name.split_first().is_some_and(|(_, tail)| deep(tail, pattern));
                }
                b'?' => match name.split_first() {
                    None => return true,
                    Some((_, tail)) => name = tail,
                },
                literal => match name.split_first() {
                    Some((&byte, tail)) if byte == literal => name = tail,
                    _ => return false,
                },
            }
            pattern = rest;
        }
        name.is_empty()
    }
    if pattern.is_empty() {
        return name.is_empty();
    }
    if pattern == b"*" {
        return true;
    }
    deep(name, pattern)
}

/// Every string of `alphabet` up to `length` bytes.
fn strings(alphabet: &[u8], length: usize) -> Vec<Vec<u8>> {
    let mut out = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..length {
        let mut next = Vec::new();
        for prefix in &frontier {
            for byte in alphabet {
                let mut grown = prefix.clone();
                grown.push(*byte);
                next.push(grown);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

/// Positive and negative — the iterative match answers exactly as the recursive definition on
/// every pattern of up to six bytes over `a`, `b`, `*`, `?` and every name of up to five bytes over
/// `a`, `b`, and both answers occur.
#[test]
fn the_match_agrees_with_legacy_rustfs_everywhere_on_a_small_alphabet() {
    let patterns = strings(b"ab*?", 6);
    let names = strings(b"ab", 5);
    let (mut matched, mut refused) = (0usize, 0usize);
    for pattern in &patterns {
        for name in &names {
            let expected = reference(pattern, name);
            assert_eq!(
                matches_simple(pattern, name),
                expected,
                "{:?} against {:?}",
                String::from_utf8_lossy(pattern),
                String::from_utf8_lossy(name)
            );
            if expected {
                matched += 1;
            } else {
                refused += 1;
            }
        }
    }
    assert!(matched > 10_000 && refused > 10_000, "{matched} matched, {refused} refused");
}

/// Negative — the edges legacy RustFS's definition has: an empty pattern matches only the empty
/// name, a lone star everything, a `?` reached after the name's last byte matches, and a literal
/// byte only itself.
#[test]
fn n_the_match_keeps_legacy_rustfss_edges() {
    assert!(matches_simple(b"", b""));
    assert!(!matches_simple(b"", b"a"));
    assert!(matches_simple(b"*", b"anything/at/all"));
    assert!(matches_simple(b"a?c/*", b"a"));
    assert!(!matches_simple(b"a?c/*", b"ab"));
    assert!(matches_simple(b"a?c/*", b"abc/"));
    assert!(matches_simple(b"logs/*", b"logs/2026/x"));
    assert!(!matches_simple(b"logs/*", b"log"));
    assert!(!matches_simple(b"logs/*", b"LOGS/x"));
    assert!(matches_simple("caf\u{e9}/*".as_bytes(), "caf\u{e9}/menu".as_bytes()));
}

fn exclusions(folders: bool, prefixes: &[&str]) -> Exclusions {
    Exclusions {
        folders,
        prefixes: prefixes.iter().map(|prefix| (*prefix).to_owned()).collect(),
    }
}

/// Negative — a key is excluded by a matching prefix or, under `ExcludeFolders`, by ending in `/`;
/// nothing is excluded by default, and an empty prefix excludes every key.
#[test]
fn n_a_key_is_excluded_only_by_a_matching_prefix_or_as_a_folder() {
    let none = Exclusions::default();
    assert!(!none.excludes("logs/a") && !none.excludes("dir/"));

    let logs = exclusions(false, &["logs/", "tmp*"]);
    assert!(logs.excludes("logs/a") && logs.excludes("logs/") && logs.excludes("tmpfile") && logs.excludes("tmp/x"));
    assert!(!logs.excludes("log") && !logs.excludes("data/logs/a") && !logs.excludes("dir/"));

    let folders = exclusions(true, &[]);
    assert!(folders.excludes("dir/") && folders.excludes("a/b/"));
    assert!(!folders.excludes("dir/file") && !folders.excludes("dir"));

    let everything = exclusions(false, &[""]);
    assert!(everything.excludes("any") && everything.excludes("dir/"));
}

/// Negative — an excluded key of an enabled bucket is written as the null version and deleted
/// without a marker; every other state, and every key that is not excluded, keeps its state.
#[test]
fn n_an_excluded_key_is_written_as_suspended_and_deleted_as_unversioned() {
    assert_eq!(VersioningState::Enabled.for_write(true), VersioningState::Suspended);
    assert_eq!(VersioningState::Enabled.for_delete(true), VersioningState::Never);
    for state in [VersioningState::Never, VersioningState::Enabled, VersioningState::Suspended] {
        assert_eq!(state.for_write(false), state);
        assert_eq!(state.for_delete(false), state);
    }
    for state in [VersioningState::Never, VersioningState::Suspended] {
        assert_eq!(state.for_write(true), state);
        assert_eq!(state.for_delete(true), state);
    }
}
