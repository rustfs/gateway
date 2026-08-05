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

//! The macro's operation list is the route table's, or this test is red.
//!
//! Responsible for: proving that `src/op_names.rs` says exactly what
//! `rustfs_gateway_core::standard_operation_names()` says.
//! NOT responsible for: the mapping between a method name and an operation (`src/tests`).
//! Upstream: `rustfs-gateway-core`. Downstream: nothing.
//!
//! # Why a test rather than a generated file
//!
//! The names exist once, in the generated route table. A proc-macro crate cannot read that at
//! expansion time without depending on `rustfs-gateway-core`, which would drag the whole generated
//! dto tree into the build graph of every crate that writes `#[handlers]` — for a list of strings.
//!
//! The mirror plus this test gives the same guarantee: one source of truth, and drift is a red
//! test rather than a macro that silently accepts a name the router has never heard of. The file it
//! checks is parsed from source rather than imported, because a proc-macro crate exports its macros
//! and nothing else.

use std::fs;
use std::path::PathBuf;

/// The names as `src/op_names.rs` lists them.
fn mirrored_names() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join("op_names.rs");
    let source = fs::read_to_string(path).expect("src/op_names.rs exists");
    let (_, tail) = source
        .split_once("static OPERATION_NAMES: &[&str] = &[")
        .expect("the list is declared");
    let (list, _) = tail.split_once("];").expect("the list is terminated");
    list.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_matches('"').to_owned())
        .collect()
}

/// Positive — the mirror and the route table agree, name for name and in the same order.
#[test]
fn the_mirrored_operation_names_match_the_route_table() {
    let expected: Vec<String> = rustfs_gateway_core::standard_operation_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        mirrored_names(),
        expected,
        "crates/macros/src/op_names.rs has drifted from the generated route table; copy the list \
         across, and remember that a name the macro accepts and the router does not is a handler \
         nothing can reach"
    );
}

/// Negative — the mirror is sorted and has no duplicates, so a merge cannot hide an entry.
#[test]
fn the_mirror_is_sorted_and_unique() {
    let names = mirrored_names();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(names, sorted, "the list must stay sorted and free of duplicates");
    assert!(!names.is_empty(), "an empty list would make every method name an error");
}

/// Negative — nothing in the mirror is namespaced: third-party names are never in this table.
///
/// The macro maps a method name to an operation mechanically, and a namespaced name has a colon in
/// it, which no method name can produce. A namespaced entry here would be a name the macro could
/// never reach and a reader would assume it could.
#[test]
fn the_mirror_holds_no_third_party_names() {
    for name in mirrored_names() {
        assert!(
            !name.contains(':'),
            "{name} is a third-party name; those are registered by hand, not by the macro"
        );
    }
}
