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

//! Judges the RustFS-profile request matrix: the gateway's RustFS profile against the legacy stack
//! as RustFS main configures it, with no difference either stack's handler could see beyond the
//! registered ones — and the controls that prove a row would notice one.
//!
//! Responsible for: holding every RustFS-profile row to its exact set of known-diff ids, both
//! directions, and showing with a mismatched pair of profiles that the key rows fail when either
//! side lacks the rule the row pins.
//! NOT responsible for: the rows (`samples/rustfs.rs`) or the generic matrix (`matrix.rs`).
//! Upstream: `samples/rustfs.rs`, the checked-in register. Downstream: none.

use std::collections::BTreeSet;

use crate::decode::Differ;
use crate::samples::rustfs_requests as rows;
use crate::samples::{KEY_SHAPES, key_operations};
use crate::{DIFFED_OPERATIONS, Item, KnownDiffs, Profile, RawRequest, rustfs_decode_diff};

/// Positive — every RustFS-profile row produces exactly its registered differences: a new one
/// fails as unregistered, one that went away fails as an expectation no longer met.
#[test]
fn every_rustfs_row_produces_exactly_its_registered_differences() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let mut problems = Vec::new();
    let mut names = BTreeSet::new();
    for row in rows() {
        assert!(names.insert(row.name), "row {} is listed twice", row.name);
        let diff = rustfs_decode_diff(&row.request).unwrap_or_else(|error| panic!("{}: {error}", row.name));
        let verdict = register.verdict_for(&row.request, diff.findings());
        for failure in &verdict.failures {
            problems.push(format!("{}: unregistered {failure}", row.name));
        }
        let matched: BTreeSet<&str> = verdict.known.iter().map(|(_, id)| id.as_str()).collect();
        let expected: BTreeSet<&str> = row.expect.iter().copied().collect();
        if matched != expected {
            problems.push(format!("{}: matched {matched:?}, expected {expected:?}", row.name));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Positive — a row with no expected difference really compared a key: both handlers were reached
/// for the same operation and handed the same key, so the agreement is not two refusals agreeing.
#[test]
fn a_slash_row_compares_the_key_each_handler_was_handed() {
    for (target, key) in [
        ("/bkt//key", "key"),
        ("/bkt///dir//key", "dir/key"),
        ("/bkt/dir//key", "dir//key"),
        ("/bkt//", "/"),
    ] {
        let diff = rustfs_decode_diff(&RawRequest::get(target)).expect("both stacks answer");
        assert_eq!(diff.operation.gateway.as_deref(), Some("GetObject"), "{target}");
        assert!(diff.error.same() && diff.error.gateway.is_none(), "{target}: {:?}", diff.error);
        let handed = diff
            .members
            .iter()
            .find(|member| member.path == "GetObjectInput.key")
            .unwrap_or_else(|| panic!("{target}: the key was not compared"));
        assert_eq!(handed.gateway.to_string(), format!("{key:?}"), "{target}");
        assert!(
            !diff.input.iter().any(|member| member.path == handed.path),
            "{target}: the two keys differ: {:?}",
            diff.input
        );
    }
}

fn key_findings(differ: &Differ, target: &str) -> Vec<String> {
    let diff = differ.diff(&RawRequest::get(target)).expect("both stacks answer");
    diff.findings()
        .into_iter()
        .filter(|finding| finding.item == Item::Member("GetObjectInput.key".to_owned()))
        .map(|finding| finding.to_string())
        .collect()
}

/// Negative — a gateway without the legacy slash rule is caught: against the legacy stack as
/// RustFS configures it, `/bkt//key` hands the handler `/key` where legacy RustFS hands `key`.
#[test]
fn n_a_gateway_without_the_slash_rule_is_caught() {
    let differ = Differ::with_profiles(Profile::Generic, Profile::Rustfs).expect("both stacks build");
    assert_eq!(key_findings(&differ, "/bkt//key").len(), 1, "the leading slash must be a key difference");
    assert!(key_findings(&differ, "/bkt/dir/key").is_empty(), "a plain key is no difference");
}

/// Negative — the other direction: the rule the gateway applies must be the one the legacy stack
/// applies, so the same gateway against a legacy stack that does not fold is caught as well.
#[test]
fn n_a_legacy_stack_without_the_fold_is_caught_too() {
    let differ = Differ::with_profiles(Profile::Rustfs, Profile::Generic).expect("both stacks build");
    assert_eq!(key_findings(&differ, "/bkt//key").len(), 1, "the folded key must be a key difference");
    assert!(key_findings(&differ, "/bkt/dir//key").is_empty(), "an interior run is kept by both");
}

/// Positive — every key shape crossed with every operation that names its key in the path: the
/// gateway's RustFS profile and legacy RustFS route to the same operation and produce no difference
/// beyond the operation's own registered ones, and wherever the operation's members are compared
/// the key each handler was handed is the key legacy RustFS hands its storage.
#[test]
fn every_key_shape_reaches_every_operation_as_legacy_rustfs_hands_it() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let mut problems = Vec::new();
    for (label, stored) in KEY_SHAPES {
        for (operation, build, expected) in key_operations() {
            let request = build(&format!("/bkt/{label}"));
            let diff = rustfs_decode_diff(&request).unwrap_or_else(|error| panic!("{operation} {label}: {error}"));
            let verdict = register.verdict_for(&request, diff.findings());
            let matched: BTreeSet<&str> = verdict.known.iter().map(|(_, id)| id.as_str()).collect();
            if !verdict.failures.is_empty() || matched != expected.iter().copied().collect() {
                problems.push(format!("{operation} {label}: unregistered {:?}, matched {matched:?}", verdict.failures));
            }
            // An operation the harness registers no handler for is answered before a handler on
            // both stacks and names no operation on the gateway side; its route is compared by the
            // register's refusal rule instead.
            if DIFFED_OPERATIONS.contains(&operation) && diff.operation.gateway.as_deref() != Some(operation) {
                problems.push(format!("{operation} {label}: routed to {:?}", diff.operation));
            }
            let key_path = format!("{operation}Input.key");
            if let Some(handed) = diff.members.iter().find(|member| member.path == key_path)
                && handed.gateway.to_string() != format!("{stored:?}")
            {
                problems.push(format!("{operation} {label}: handed {}", handed.gateway));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Negative — the cross product is not vacuous: a gateway with the RustFS slash rule but the default
/// key floor refuses keys legacy RustFS hands its storage, and every such refusal is a difference
/// where the RustFS rows expect none.
#[test]
fn n_a_gateway_with_the_default_key_floor_is_caught() {
    let differ = Differ::with_rustfs_slash_rule_only().expect("both stacks build");
    for label in ["a%01b", "a%252Fb", "%5Cx", "a/../b"] {
        let diff = differ
            .diff(&RawRequest::get(&format!("/bkt/{label}")))
            .expect("both stacks answer");
        let refused = diff.findings().iter().any(|finding| finding.item == Item::Outcome);
        assert!(refused, "{label}: the default floor went unnoticed: {:?}", diff.findings());
    }
}
