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

//! The whole route table as text, so that a change to it appears in a diff.
//!
//! Responsible for: comparing the rendered generated table against the checked-in golden, and
//! proving the comparison can fail.
//! NOT responsible for: what the table *should* contain — that is codegen's, driven by the model
//! and the route overlay.
//! Upstream: `rustfs-gateway-core`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! A model upgrade changes the routing of operations nobody touched. A new query parameter turns a
//! selector that used to be unique into one that overlaps, or moves an operation between bands, and
//! nothing about the diff of the generated tree makes that visible — it is thousands of lines of
//! data. The golden is one line per operation in precedence order: a routing change is a routing
//! change in the diff, in the pull request that made it, where somebody can still ask why.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```bash
//! UPDATE_GOLDEN=1 cargo test -p rustfs-gateway-core --test golden
//! ```

use std::fs;
use std::path::PathBuf;

use rustfs_gateway_core::route::{PROVISIONAL_SHADOWING, RouteTable, generated_entries};

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/route-table.txt")
}

fn rendered() -> String {
    let entries = generated_entries().expect("the generated rows parse");
    let table = RouteTable::build(entries, &PROVISIONAL_SHADOWING).expect("the generated table builds");
    table.render()
}

#[test]
fn the_rendered_route_table_matches_the_golden() {
    let rendered = rendered();
    let path = golden_path();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("the golden directory");
        }
        fs::write(&path, &rendered).expect("write the golden");
        return;
    }
    let expected = fs::read_to_string(&path).expect("the golden exists; regenerate with UPDATE_GOLDEN=1");
    assert_eq!(
        rendered, expected,
        "the route table changed. If that was intended, regenerate the golden and say why in the pull request."
    );
}

/// A golden nobody can break is not a guard.
#[test]
fn the_comparison_notices_a_changed_selector() {
    let mut mutated = rendered();
    mutated = mutated.replace("QueryPresent(\"location\")", "QueryPresent(\"lifecycle\")");
    assert_ne!(
        mutated,
        rendered(),
        "the rendering must include the selector, or a changed predicate would not show up"
    );
}

/// The rendering has to carry the two things a reviewer reads: precedence order and the predicates.
#[test]
fn the_rendering_is_ordered_and_complete() {
    let rendered = rendered();
    let precedences: Vec<u16> = rendered
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|field| field.parse().ok())
        .collect();
    assert!(
        precedences.windows(2).all(|pair| pair.first() <= pair.last()),
        "the golden must be in precedence order, or a diff is noise"
    );

    let entries = generated_entries().expect("the generated rows parse");
    assert_eq!(rendered.lines().count(), entries.len(), "one line per operation");
    for entry in &entries {
        assert!(rendered.contains(entry.op_name), "{} is missing from the golden", entry.op_name);
    }
}
