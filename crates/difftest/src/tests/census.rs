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

//! Every diffed operation's gateway projection reads every member the generated DTO has.
//!
//! Responsible for: holding each gateway projection's declared member list to the generated
//! field count, and to itself (no member twice). The gateway DTO may not be destructured
//! exhaustively (ADR-0004 P3), so this count is what makes a new gateway member a failure here
//! rather than a member nobody compares; the s3s side is exhaustive by construction.
//! NOT responsible for: whether a member's value is compared correctly (`controls.rs`).
//! Upstream: `generated/dto/field_counts.txt`. Downstream: none.

use std::collections::BTreeSet;

use crate::DIFFED_OPERATIONS;
use crate::project::GATEWAY_MEMBER_CENSUS;

fn field_counts() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/dto/field_counts.txt");
    std::fs::read_to_string(path).expect("the generated field-count ratchet is readable")
}

fn generated_count(counts: &str, shape: &str) -> Option<usize> {
    counts.lines().find_map(|line| {
        let (name, count) = line.split_once(' ')?;
        (name == shape).then(|| count.trim().parse().ok()).flatten()
    })
}

/// Positive — every projection reads exactly as many members as its generated input has.
#[test]
fn every_gateway_projection_reads_every_generated_member() {
    let counts = field_counts();
    let mut problems = Vec::new();
    for (shape, members) in GATEWAY_MEMBER_CENSUS {
        let unique: BTreeSet<&str> = members.iter().copied().collect();
        if unique.len() != members.len() {
            problems.push(format!("{shape}: a member is listed twice"));
        }
        match generated_count(&counts, shape) {
            Some(count) if count == members.len() => {}
            Some(count) => problems.push(format!("{shape}: the DTO has {count} members, the projection reads {}", members.len())),
            None => problems.push(format!("{shape}: not in field_counts.txt")),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Negative — the census names exactly the diffed operations: an operation diffed without a
/// census row would escape the count above.
#[test]
fn the_census_names_exactly_the_diffed_operations() {
    let census: BTreeSet<String> = GATEWAY_MEMBER_CENSUS
        .iter()
        .map(|(shape, _)| shape.trim_end_matches("Input").to_owned())
        .collect();
    let diffed: BTreeSet<String> = DIFFED_OPERATIONS.iter().map(|operation| (*operation).to_owned()).collect();
    assert_eq!(census, diffed);
}

/// Negative — the count lookup refuses a shape the file does not name, and reads the number.
#[test]
fn the_count_lookup_reads_the_number_and_refuses_an_unknown_shape() {
    assert_eq!(generated_count("A 3\nAB 7\n", "AB"), Some(7));
    assert_eq!(generated_count("A 3\nAB 7\n", "ABC"), None);
    assert_eq!(generated_count("A 3\nAB x\n", "AB"), None);
}
