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

//! Judges the request matrix: exact registered differences per row, no stale register entry, and
//! every member of every diffed operation exercised.
//!
//! Responsible for: holding each row to its expected set of known-diff ids in both directions (a
//! new difference fails, a difference that went away fails), every decode register entry to at
//! least one row, and every member — shared, or carried by one model only, list elements by
//! shape — to a row that sets it (and, when shared, agrees on it).
//! NOT responsible for: the rows themselves (`rows.rs`).
//! Upstream: `rows.rs`, the checked-in register. Downstream: none.

use std::collections::{BTreeMap, BTreeSet};

use super::rows::rows;
use crate::known::Kind;
use crate::{DIFFED_OPERATIONS, FieldValue, KnownDiffs, decode_diff};

/// Positive — every row produces exactly its registered differences. A new difference fails as
/// unregistered; a difference that went away fails as an expectation no longer met.
#[test]
fn every_row_produces_exactly_its_registered_differences() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let mut problems = Vec::new();
    let mut names = BTreeSet::new();
    for row in rows() {
        assert!(names.insert(row.name), "row {} is listed twice", row.name);
        let diff = decode_diff(&row.request).unwrap_or_else(|error| panic!("{}: {error}", row.name));
        let verdict = register.verdict(diff.findings());
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

/// Negative — a register entry no row produces is stale and fails: the register may only hold a
/// difference the matrix still observes.
#[test]
fn every_decode_register_entry_is_produced_by_some_row() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let produced: BTreeSet<&str> = rows().iter().flat_map(|row| row.expect.iter().copied()).collect();
    let stale: Vec<&str> = register
        .entries()
        .iter()
        .filter(|entry| entry.kind == Kind::Decode && !produced.contains(entry.id.as_str()))
        .map(|entry| entry.id.as_str())
        .collect();
    assert!(stale.is_empty(), "register entries no row produces: {stale:?}");
}

/// The path of a member with list positions erased: `delete.objects[3].key` is `delete.objects[].key`.
fn shape_of(path: &str) -> String {
    let mut shape = String::with_capacity(path.len());
    let mut in_index = false;
    for character in path.chars() {
        match character {
            '[' => {
                in_index = true;
                shape.push('[');
            }
            ']' => {
                in_index = false;
                shape.push(']');
            }
            _ if in_index => {}
            other => shape.push(other),
        }
    }
    shape
}

/// Negative — a member no row sets is unexercised: both stacks could decode it wrongly the same
/// way, or not at all, and every row would still pass. For every diffed operation, every member
/// both models carry must be set to the same value on both stacks in some row, and every member
/// only one model carries must be set on that side in some row (which the matrix then holds to a
/// registered difference). List elements count by shape, so each element member is held too.
#[test]
fn every_member_of_every_diffed_operation_is_exercised_by_some_row() {
    #[derive(Default)]
    struct Seen {
        gateway_paths: BTreeSet<String>,
        s3s_paths: BTreeSet<String>,
        gateway_set: BTreeSet<String>,
        s3s_set: BTreeSet<String>,
        agreed: BTreeSet<String>,
        compared_gateway: BTreeSet<String>,
        compared_s3s: BTreeSet<String>,
    }
    let mut seen: BTreeMap<String, Seen> = BTreeMap::new();
    for row in rows() {
        let diff = decode_diff(&row.request).expect("the harness runs");
        for (side_operation, handed, is_gateway) in [
            (&diff.operation.gateway, &diff.handed.gateway, true),
            (&diff.operation.s3s, &diff.handed.s3s, false),
        ] {
            let Some(operation) = side_operation else {
                continue;
            };
            let entry = seen.entry(operation.clone()).or_default();
            for (path, value) in handed {
                let shape = shape_of(path);
                let present = matches!(value, FieldValue::Present(_));
                let (paths, set) = if is_gateway {
                    (&mut entry.gateway_paths, &mut entry.gateway_set)
                } else {
                    (&mut entry.s3s_paths, &mut entry.s3s_set)
                };
                paths.insert(shape.clone());
                if present {
                    set.insert(shape);
                }
            }
        }
        if let Some(operation) = &diff.operation.gateway {
            let entry = seen.entry(operation.clone()).or_default();
            for member in &diff.members {
                let shape = shape_of(&member.path);
                if member.gateway != FieldValue::NoMember {
                    entry.compared_gateway.insert(shape.clone());
                }
                if member.s3s != FieldValue::NoMember {
                    entry.compared_s3s.insert(shape.clone());
                }
                if matches!(member.gateway, FieldValue::Present(_)) && member.gateway == member.s3s {
                    entry.agreed.insert(shape);
                }
            }
        }
    }
    let mut problems = Vec::new();
    for operation in DIFFED_OPERATIONS {
        let Some(entry) = seen.get(*operation) else {
            problems.push(format!("{operation}: no row reached a handler"));
            continue;
        };
        // What each side was handed must account for every member the comparison saw on it, or
        // the classification below would be read from an empty list and demand nothing.
        let unreported: Vec<&String> = entry
            .compared_gateway
            .difference(&entry.gateway_paths)
            .chain(entry.compared_s3s.difference(&entry.s3s_paths))
            .collect();
        if !unreported.is_empty() {
            problems.push(format!(
                "{operation}: compared members missing from what the handlers were handed: {unreported:?}"
            ));
        }
        let shared: BTreeSet<&String> = entry.gateway_paths.intersection(&entry.s3s_paths).collect();
        let unagreed: Vec<&&String> = shared.iter().filter(|path| !entry.agreed.contains(**path)).collect();
        let gateway_unset: Vec<&String> = entry
            .gateway_paths
            .difference(&entry.s3s_paths)
            .filter(|path| !entry.gateway_set.contains(*path))
            .collect();
        let s3s_unset: Vec<&String> = entry
            .s3s_paths
            .difference(&entry.gateway_paths)
            .filter(|path| !entry.s3s_set.contains(*path))
            .collect();
        if !unagreed.is_empty() {
            problems.push(format!("{operation}: shared members never set and agreed: {unagreed:?}"));
        }
        if !gateway_unset.is_empty() {
            problems.push(format!("{operation}: gateway-only members never set: {gateway_unset:?}"));
        }
        if !s3s_unset.is_empty() {
            problems.push(format!("{operation}: s3s-only members never set: {s3s_unset:?}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Positive — list positions are erased and nothing else.
#[test]
fn a_member_shape_erases_list_positions_only() {
    assert_eq!(
        shape_of("DeleteObjectsInput.delete.objects[12].key"),
        "DeleteObjectsInput.delete.objects[].key"
    );
    assert_eq!(shape_of("GetObjectInput.range"), "GetObjectInput.range");
}
